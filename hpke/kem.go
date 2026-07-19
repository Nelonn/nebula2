package hpke

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"io"
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

func (*dhkemX25519) ID() uint16 { return KEMID_DHKEM_X25519 }

func (*dhkemX25519) PublicKeyLen() int    { return 32 }
func (*dhkemX25519) PrivateKeyLen() int   { return 32 }
func (*dhkemX25519) SharedSecretLen() int { return 32 }
func (*dhkemX25519) EncLen() int          { return 32 }

func (*dhkemX25519) GenerateKeyPair() ([]byte, []byte, error) {
	sk, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return sk.PublicKey().Bytes(), sk.Bytes(), nil
}

func (*dhkemX25519) Encap(pkR []byte) ([]byte, []byte, error) {
	sk, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	pub := sk.PublicKey().Bytes()
	pkRKey, err := ecdh.X25519().NewPublicKey(pkR)
	if err != nil {
		return nil, nil, err
	}
	dh, err := sk.ECDH(pkRKey)
	if err != nil {
		return nil, nil, err
	}
	kemCtx := make([]byte, 0, 3*X25519PK)
	kemCtx = append(kemCtx, pub...)
	kemCtx = append(kemCtx, pkR...)
	ss := extractAndExpand(dh, kemCtx, KEMID_DHKEM_X25519)
	return ss, pub, nil
}

func (*dhkemX25519) Decap(enc, skR []byte) ([]byte, error) {
	sk, err := ecdh.X25519().NewPrivateKey(skR)
	if err != nil {
		return nil, err
	}
	pkEKey, err := ecdh.X25519().NewPublicKey(enc)
	if err != nil {
		return nil, err
	}
	dh, err := sk.ECDH(pkEKey)
	if err != nil {
		return nil, err
	}
	pkR := sk.PublicKey().Bytes()
	kemCtx := make([]byte, 0, 3*X25519PK)
	kemCtx = append(kemCtx, enc...)
	kemCtx = append(kemCtx, pkR...)
	return extractAndExpand(dh, kemCtx, KEMID_DHKEM_X25519), nil
}

func (*dhkemX25519) AuthEncap(pkR []byte, skS []byte) ([]byte, []byte, error) {
	sk, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	pub := sk.PublicKey().Bytes()
	pkRKey, err := ecdh.X25519().NewPublicKey(pkR)
	if err != nil {
		return nil, nil, err
	}
	skSKey, err := ecdh.X25519().NewPrivateKey(skS)
	if err != nil {
		return nil, nil, err
	}
	dh1, err := sk.ECDH(pkRKey)
	if err != nil {
		return nil, nil, err
	}
	dh2, err := skSKey.ECDH(pkRKey)
	if err != nil {
		return nil, nil, err
	}
	pkS := skSKey.PublicKey().Bytes()
	dh := append(dh1, dh2...)
	kemCtx := make([]byte, 0, 3*X25519PK)
	kemCtx = append(kemCtx, pub...)
	kemCtx = append(kemCtx, pkR...)
	kemCtx = append(kemCtx, pkS...)
	ss := extractAndExpand(dh, kemCtx, KEMID_DHKEM_X25519)
	return ss, pub, nil
}

func (*dhkemX25519) AuthDecap(enc, skR, pkS []byte) ([]byte, error) {
	sk, err := ecdh.X25519().NewPrivateKey(skR)
	if err != nil {
		return nil, err
	}
	pkEKey, err := ecdh.X25519().NewPublicKey(enc)
	if err != nil {
		return nil, err
	}
	pkSKey, err := ecdh.X25519().NewPublicKey(pkS)
	if err != nil {
		return nil, err
	}
	dh1, err := sk.ECDH(pkEKey)
	if err != nil {
		return nil, err
	}
	dh2, err := sk.ECDH(pkSKey)
	if err != nil {
		return nil, err
	}
	pkR := sk.PublicKey().Bytes()
	dh := append(dh1, dh2...)
	kemCtx := make([]byte, 0, 3*X25519PK)
	kemCtx = append(kemCtx, enc...)
	kemCtx = append(kemCtx, pkR...)
	kemCtx = append(kemCtx, pkS...)
	return extractAndExpand(dh, kemCtx, KEMID_DHKEM_X25519), nil
}

func labeledExtract(salt []byte, label string, ikm []byte, suiteID []byte) []byte {
	if salt == nil {
		salt = make([]byte, Nh)
	}
	labeledIKM := make([]byte, 0, len("HPKE-v1")+len(suiteID)+len(label)+len(ikm))
	labeledIKM = append(labeledIKM, []byte("HPKE-v1")...)
	labeledIKM = append(labeledIKM, suiteID...)
	labeledIKM = append(labeledIKM, []byte(label)...)
	labeledIKM = append(labeledIKM, ikm...)
	mac := hmac.New(sha256.New, salt)
	mac.Write(labeledIKM)
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
		panic(err)
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
	key           []byte
	nonce         [Nn]byte
	seq           uint64
	sharedSecret  []byte
}

func (c *Context) SharedSecret() []byte { return c.sharedSecret }

func hkdfExtract(salt, ikm []byte) []byte {
	if salt == nil {
		salt = make([]byte, Nh)
	}
	mac := hmac.New(sha256.New, salt)
	mac.Write(ikm)
	return mac.Sum(nil)
}

func keySchedule(mode byte, sharedSecret []byte, info []byte, suite *HPKESuite) *Context {
	suiteID := computeSuiteID(suite)
	psk := []byte{}
	pskID := []byte{}

	earlySecret := hkdfExtract(nil, psk)

	pskIDHash := labeledExpand(earlySecret, "psk_id_hash", pskID, Nh, suiteID)
	infoHash := labeledExpand(earlySecret, "info_hash", info, Nh, suiteID)

	keyScheduleCtx := make([]byte, 1+Nh+Nh)
	keyScheduleCtx[0] = mode
	copy(keyScheduleCtx[1:], pskIDHash)
	copy(keyScheduleCtx[1+Nh:], infoHash)

	secret := labeledExtract(pskIDHash, "secret", sharedSecret, suiteID)

	key := labeledExpand(secret, "key", keyScheduleCtx, Nk, suiteID)
	nonceBytes := labeledExpand(secret, "base_nonce", keyScheduleCtx, Nn, suiteID)

	ctx := &Context{key: key, sharedSecret: sharedSecret}
	copy(ctx.nonce[:], nonceBytes)
	return ctx
}

func computeSuiteID(suite *HPKESuite) []byte {
	id := make([]byte, 10)
	id[0] = 'H'; id[1] = 'P'; id[2] = 'K'; id[3] = 'E'
	binary.BigEndian.PutUint16(id[4:6], suite.KEM.ID())
	binary.BigEndian.PutUint16(id[6:8], suite.KDFID)
	binary.BigEndian.PutUint16(id[8:10], suite.AEADID)
	return id
}

func (c *Context) computeNonce() []byte {
	var nonce [Nn]byte
	binary.BigEndian.PutUint64(nonce[Nn-8:], c.seq)
	for i := 0; i < Nn; i++ {
		nonce[i] ^= c.nonce[i]
	}
	c.seq++
	return nonce[:]
}

func (c *Context) Seal(aad, pt []byte) ([]byte, error) {
	block, err := aes.NewCipher(c.key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := c.computeNonce()
	return gcm.Seal(nil, nonce, pt, aad), nil
}

func (c *Context) Open(aad, ct []byte) ([]byte, error) {
	block, err := aes.NewCipher(c.key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := c.computeNonce()
	pt, err := gcm.Open(nil, nonce, ct, aad)
	if err != nil {
		return nil, err
	}
	return pt, nil
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

func RandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := io.ReadFull(rand.Reader, b)
	if err != nil {
		return nil, err
	}
	return b, nil
}
