package hpke

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"sync"

	"github.com/cloudflare/circl/kem"
	circlkem "github.com/cloudflare/circl/kem/schemes"
)

const (
	KEMID_DHKEM_X25519           uint16 = 0x0020
	KEMID_Hybrid_X25519_MLKEM768 uint16 = 0xFF01

	KDFID_HKDF_SHA256 uint16 = 0x0001
	AEADID_AESGCM_256 uint16 = 0x0003

	Nh       = 32
	Nk       = 32
	Nn       = 12
	X25519PK = 32

	sharedSecretExportLabel = "nebula-hpke-shared"
)

type KEM interface {
	GenerateKeyPair() (pub, priv []byte, err error)
	Encap(pkR []byte) (sharedSecret, enc []byte, err error)
	Decap(enc, skR []byte) ([]byte, error)
	AuthEncap(pkR []byte, skS []byte) (sharedSecret, enc []byte, err error)
	AuthDecap(enc, skR, pkS []byte) ([]byte, error)
	PublicKeyLen() int
	PrivateKeyLen() int
	SharedSecretLen() int
	EncLen() int
	ID() uint16
}

type dhkemX25519 struct{}

var DHKEM_X25519 KEM = &dhkemX25519{}

var x25519Scheme = circlkem.ByName("HPKE_KEM_X25519_HKDF_SHA256")

func (*dhkemX25519) ID() uint16               { return KEMID_DHKEM_X25519 }
func (*dhkemX25519) PublicKeyLen() int          { return 32 }
func (*dhkemX25519) PrivateKeyLen() int         { return 32 }
func (*dhkemX25519) SharedSecretLen() int       { return 32 }
func (*dhkemX25519) EncLen() int                { return 32 }

func (*dhkemX25519) GenerateKeyPair() ([]byte, []byte, error) {
	pk, sk, err := x25519Scheme.GenerateKeyPair()
	if err != nil {
		return nil, nil, err
	}
	pkBytes, _ := pk.MarshalBinary()
	skBytes, _ := sk.MarshalBinary()
	return pkBytes, skBytes, nil
}

func (*dhkemX25519) Encap(pkR []byte) ([]byte, []byte, error) {
	pk, err := x25519Scheme.UnmarshalBinaryPublicKey(pkR)
	if err != nil {
		return nil, nil, err
	}
	ct, ss, err := x25519Scheme.Encapsulate(pk)
	if err != nil {
		return nil, nil, err
	}
	return ss, ct, nil
}

func (*dhkemX25519) Decap(enc, skR []byte) ([]byte, error) {
	sk, err := x25519Scheme.UnmarshalBinaryPrivateKey(skR)
	if err != nil {
		return nil, err
	}
	return x25519Scheme.Decapsulate(sk, enc)
}

func (*dhkemX25519) AuthEncap(pkR []byte, skS []byte) ([]byte, []byte, error) {
	auth, ok := x25519Scheme.(kem.AuthScheme)
	if !ok {
		return nil, nil, fmt.Errorf("hpke: X25519 does not support Auth mode")
	}
	pk, err := x25519Scheme.UnmarshalBinaryPublicKey(pkR)
	if err != nil {
		return nil, nil, err
	}
	sk, err := x25519Scheme.UnmarshalBinaryPrivateKey(skS)
	if err != nil {
		return nil, nil, err
	}
	ct, ss, err := auth.AuthEncapsulate(pk, sk)
	if err != nil {
		return nil, nil, err
	}
	return ss, ct, nil
}

func (*dhkemX25519) AuthDecap(enc, skR, pkS []byte) ([]byte, error) {
	auth, ok := x25519Scheme.(kem.AuthScheme)
	if !ok {
		return nil, fmt.Errorf("hpke: X25519 does not support Auth mode")
	}
	sk, err := x25519Scheme.UnmarshalBinaryPrivateKey(skR)
	if err != nil {
		return nil, err
	}
	pk, err := x25519Scheme.UnmarshalBinaryPublicKey(pkS)
	if err != nil {
		return nil, err
	}
	return auth.AuthDecapsulate(sk, enc, pk)
}

func RandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := io.ReadFull(rand.Reader, b)
	if err != nil {
		return nil, err
	}
	return b, nil
}

type HPKESuite struct {
	KEM    KEM
	KDFID  uint16
	AEADID uint16
}

var DefaultHPKE = &HPKESuite{
	KEM:    DHKEM_X25519,
	KDFID:  KDFID_HKDF_SHA256,
	AEADID: AEADID_AESGCM_256,
}

type Context struct {
	sealFn       func(aad, pt []byte) ([]byte, error)
	openFn       func(aad, ct []byte) ([]byte, error)
	sharedSecret []byte
	mu           sync.Mutex
}

func (c *Context) SharedSecret() []byte { return c.sharedSecret }

func (c *Context) Seal(aad, pt []byte) ([]byte, error) {
	return c.sealFn(aad, pt)
}

func (c *Context) Open(aad, ct []byte) ([]byte, error) {
	return c.openFn(aad, ct)
}

func labeledExtract(salt []byte, label string, ikm []byte, suiteID []byte) []byte {
	if salt == nil {
		salt = make([]byte, Nh)
	}
	mac := hmac.New(sha256.New, salt)
	mac.Write([]byte("HPKE-v1"))
	mac.Write(suiteID)
	mac.Write([]byte(label))
	mac.Write(ikm)
	return mac.Sum(nil)
}

func labeledExpand(prk []byte, label string, info []byte, length int, suiteID []byte) []byte {
	labeledInfo := make([]byte, 0, 2+len("HPKE-v1")+len(suiteID)+len(label)+len(info))
	labeledInfo = append(labeledInfo, byte(length>>8), byte(length&0xff))
	labeledInfo = append(labeledInfo, []byte("HPKE-v1")...)
	labeledInfo = append(labeledInfo, suiteID...)
	labeledInfo = append(labeledInfo, []byte(label)...)
	labeledInfo = append(labeledInfo, info...)
	out, err := hkdf.Expand(sha256.New, prk, string(labeledInfo), length)
	if err != nil {
		return make([]byte, length)
	}
	return out
}

func extractAndExpand(dh, kemCtx []byte, kemID uint16) []byte {
	suiteID := make([]byte, 5)
	suiteID[0] = 'K'; suiteID[1] = 'E'; suiteID[2] = 'M'
	binary.BigEndian.PutUint16(suiteID[3:5], kemID)
	prk := labeledExtract(nil, "shared_secret", dh, suiteID)
	return labeledExpand(prk, "shared_secret", kemCtx, Nh, suiteID)
}

func hkdfExtract(salt, ikm []byte) []byte {
	if salt == nil {
		salt = make([]byte, Nh)
	}
	mac := hmac.New(sha256.New, salt)
	mac.Write(ikm)
	return mac.Sum(nil)
}

func computeSuiteID(suite *HPKESuite) []byte {
	id := make([]byte, 10)
	id[0] = 'H'; id[1] = 'P'; id[2] = 'K'; id[3] = 'E'
	binary.BigEndian.PutUint16(id[4:6], suite.KEM.ID())
	binary.BigEndian.PutUint16(id[6:8], suite.KDFID)
	binary.BigEndian.PutUint16(id[8:10], suite.AEADID)
	return id
}

func keySchedule(mode byte, sharedSecret []byte, info []byte, suite *HPKESuite) *Context {
	suiteID := computeSuiteID(suite)
	psk := []byte{}
	pskID := []byte{}

	earlySecret := hkdfExtract(nil, psk)

	pskIDHash := labeledExtract(earlySecret, "psk_id_hash", pskID, suiteID)
	infoHash := labeledExtract(earlySecret, "info_hash", info, suiteID)

	keyScheduleCtx := make([]byte, 1+Nh+Nh)
	keyScheduleCtx[0] = mode
	copy(keyScheduleCtx[1:], pskIDHash)
	copy(keyScheduleCtx[1+Nh:], infoHash)

	secret := labeledExtract(earlySecret, "secret", sharedSecret, suiteID)

	key := labeledExpand(secret, "key", keyScheduleCtx, Nk, suiteID)
	nonceBytes := labeledExpand(secret, "base_nonce", keyScheduleCtx, Nn, suiteID)

	block, _ := aes.NewCipher(key)
	aead, _ := cipher.NewGCM(block)

	seq := uint64(0)
	var nonceBuf [Nn]byte
	copy(nonceBuf[:], nonceBytes)

	ctx := &Context{
		sharedSecret: sharedSecret,
	}
	ctx.sealFn = func(aad, pt []byte) ([]byte, error) {
		ctx.mu.Lock()
		defer ctx.mu.Unlock()
		if seq > (1<<64)-2 {
			return nil, fmt.Errorf("hpke: seq overflow")
		}
		var n [Nn]byte
		binary.BigEndian.PutUint64(n[Nn-8:], seq)
		for i := 0; i < Nn; i++ {
			n[i] ^= nonceBuf[i]
		}
		seq++
		return aead.Seal(nil, n[:], pt, aad), nil
	}
	ctx.openFn = func(aad, ct []byte) ([]byte, error) {
		ctx.mu.Lock()
		defer ctx.mu.Unlock()
		if seq > (1<<64)-2 {
			return nil, fmt.Errorf("hpke: seq overflow")
		}
		var n [Nn]byte
		binary.BigEndian.PutUint64(n[Nn-8:], seq)
		for i := 0; i < Nn; i++ {
			n[i] ^= nonceBuf[i]
		}
		seq++
		return aead.Open(nil, n[:], ct, aad)
	}

	return ctx
}

func SetupBaseS(pkR []byte, info []byte, suite *HPKESuite) (*Context, []byte, error) {
	ss, enc, err := suite.KEM.Encap(pkR)
	if err != nil {
		return nil, nil, err
	}
	ctx := keySchedule(0, ss, info, suite)
	return ctx, enc, nil
}

func SetupBaseR(enc, skR []byte, info []byte, suite *HPKESuite) (*Context, error) {
	ss, err := suite.KEM.Decap(enc, skR)
	if err != nil {
		return nil, err
	}
	ctx := keySchedule(0, ss, info, suite)
	return ctx, nil
}

func SetupAuthS(pkR []byte, skS []byte, info []byte, suite *HPKESuite) (*Context, []byte, error) {
	ss, enc, err := suite.KEM.AuthEncap(pkR, skS)
	if err != nil {
		return nil, nil, err
	}
	ctx := keySchedule(2, ss, info, suite)
	return ctx, enc, nil
}

func SetupAuthR(enc, skR, pkS []byte, info []byte, suite *HPKESuite) (*Context, error) {
	ss, err := suite.KEM.AuthDecap(enc, skR, pkS)
	if err != nil {
		return nil, err
	}
	ctx := keySchedule(2, ss, info, suite)
	return ctx, nil
}
