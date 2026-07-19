package nebula

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	"github.com/flynn/noise"
	"github.com/gaissmai/bart"
	"github.com/slackhq/nebula/cert"
	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/handshake"
	"github.com/slackhq/nebula/hpke"
	"github.com/slackhq/nebula/noiseutil"
	"github.com/slackhq/nebula/util"
)

type PKI struct {
	cs        atomic.Pointer[CertState]
	caPool    atomic.Pointer[cert.CAPool]
	l         *slog.Logger
	headerKey [16]byte
	headerBlock atomic.Pointer[headerBlockWrapper]
}

type headerBlockWrapper struct {
	block cipher.Block
}

func (p *PKI) HeaderBlock() cipher.Block {
	w := p.headerBlock.Load()
	if w == nil {
		return nil
	}
	return w.block
}

type CertState struct {
	v3Cert       cert.Certificate
	v3Credential *handshake.Credential

	initiatingVersion cert.Version
	privateKey        []byte
	pkcs11Backed      bool
	cipher            string

	hpkePrivateKey []byte
	hpkeHybrid     bool

	myVpnNetworks            []netip.Prefix
	myVpnNetworksTable       *bart.Lite
	myVpnAddrs               []netip.Addr
	myVpnAddrsTable          *bart.Lite
	myVpnBroadcastAddrsTable *bart.Lite
}

func NewPKIFromConfig(l *slog.Logger, c *config.C) (*PKI, error) {
	pki := &PKI{l: l}
	err := pki.reload(c, true)
	if err != nil {
		return nil, err
	}

	pki.computeHeaderKey()

	c.RegisterReloadCallback(func(c *config.C) {
		rErr := pki.reload(c, false)
		if rErr != nil {
			util.LogWithContextIfNeeded("Failed to reload PKI from config", rErr, l)
		}
	})

	return pki, nil
}

func (p *PKI) computeHeaderKey() {
	pool := p.caPool.Load()
	h := sha256.New()
	if pool != nil {
		// Hash all CA certificate fingerprints to derive the global header key.
		// All nodes with the same CA get the same key.
		fps := pool.GetFingerprints()
		slices.Sort(fps)
		for _, fp := range fps {
			h.Write([]byte(fp))
		}
	}
	copy(p.headerKey[:], h.Sum(nil)[:16])
	if block, err := aes.NewCipher(p.headerKey[:]); err == nil {
		p.headerBlock.Store(&headerBlockWrapper{block: block})
		p.l.Debug("Initialized packet header cipher")
	} else {
		p.l.Warn("failed to initialize header cipher", "error", err)
	}
}

func (p *PKI) GetCAPool() *cert.CAPool {
	return p.caPool.Load()
}

func (p *PKI) getCertState() *CertState {
	return p.cs.Load()
}

func (p *PKI) reload(c *config.C, initial bool) error {
	err := p.reloadCerts(c, initial)
	if err != nil {
		if initial {
			return err
		}
		err.Log(p.l)
	}

	err = p.reloadCAPool(c)
	if err != nil {
		if initial {
			return err
		}
		err.Log(p.l)
	}

	return nil
}

func (p *PKI) reloadCerts(c *config.C, initial bool) *util.ContextualError {
	var cipher string
	var currentState *CertState
	if initial {
		cipher = c.GetString("cipher", "aes")
		switch cipher {
		case "aes", "chachapoly":
			// Each post-handshake CipherState in noiseutil hardcodes its own
			// nonce endianness now, so there's nothing to set up here.
		default:
			return util.NewContextualError(
				"unknown cipher",
				m{"cipher": cipher},
				nil,
			)
		}
	} else {
		// Cipher cant be hot swapped so just leave it at what it was before
		currentState = p.cs.Load()
		cipher = currentState.cipher
	}

	newState, err := newCertStateFromConfig(c, cipher)
	if err != nil {
		return util.NewContextualError("Could not load client cert", nil, err)
	}

	if currentState != nil {
		if !slices.Equal(currentState.v3Cert.Networks(), newState.v3Cert.Networks()) {
			return util.NewContextualError(
				"Networks in new cert was different from old",
				m{"new_networks": newState.v3Cert.Networks(), "old_networks": currentState.v3Cert.Networks(), "cert_version": cert.Version3},
				nil,
			)
		}

		if currentState.v3Cert.Curve() != newState.v3Cert.Curve() {
			return util.NewContextualError(
				"Curve in new cert was different from old",
				m{"new_curve": newState.v3Cert.Curve(), "old_curve": currentState.v3Cert.Curve(), "cert_version": cert.Version3},
				nil,
			)
		}
	}

	p.cs.Store(newState)

	if initial {
		p.l.Debug("Client nebula certificate(s)", "cert", newState)
	} else {
		p.l.Info("Client certificate(s) refreshed from disk", "cert", newState)
	}
	return nil
}

func (p *PKI) reloadCAPool(c *config.C) *util.ContextualError {
	caPool, err := loadCAPoolFromConfig(p.l, c)
	if err != nil {
		return util.NewContextualError("Failed to load ca from config", nil, err)
	}

	p.caPool.Store(caPool)
	p.l.Debug("Trusted CA fingerprints", "fingerprints", caPool.GetFingerprints())
	return nil
}

func (cs *CertState) GetDefaultCertificate() cert.Certificate {
	c := cs.getCertificate(cs.initiatingVersion)
	if c == nil {
		panic("No default certificate found")
	}
	return c
}

// DefaultVersion returns the preferred cert version for initiating handshakes.
func (cs *CertState) DefaultVersion() cert.Version { return cs.initiatingVersion }

// GetCredential returns the pre-computed handshake credential for the given version, or nil.
func (cs *CertState) GetCredential(v cert.Version) *handshake.Credential {
	if v == cert.Version3 {
		return cs.v3Credential
	}
	return nil
}

func (cs *CertState) getCertificate(v cert.Version) cert.Certificate {
	if v == cert.Version3 {
		return cs.v3Cert
	}
	return nil
}

func newDataPlaneCipherSuite(cipher string) (noise.CipherSuite, error) {
	if cipher == "chachapoly" {
		return noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashSHA256), nil
	}
	return noise.NewCipherSuite(noise.DH25519, noiseutil.CipherAESGCM, noise.HashSHA256), nil
}

func newHPKESuite(hybrid bool) *hpke.HPKESuite {
	if hybrid {
		return &hpke.HPKESuite{
			KEM:    hpke.HybridKEM_X25519_MLKEM768,
			KDFID:  hpke.KDFID_HKDF_SHA256,
			AEADID: hpke.AEADID_AESGCM_256,
		}
	}
	return &hpke.HPKESuite{
		KEM:    hpke.DHKEM_X25519,
		KDFID:  hpke.KDFID_HKDF_SHA256,
		AEADID: hpke.AEADID_AESGCM_256,
	}
}

func (cs *CertState) GetHPKEHybrid() bool { return cs.hpkeHybrid }

func (cs *CertState) String() string {
	b, err := cs.MarshalJSON()
	if err != nil {
		return fmt.Sprintf("error marshaling certificate state: %v", err)
	}
	return string(b)
}

func (cs *CertState) MarshalJSON() ([]byte, error) {
	msg := []json.RawMessage{}
	if cs.v3Cert != nil {
		b, err := cs.v3Cert.MarshalJSON()
		if err != nil {
			return nil, err
		}
		msg = append(msg, b)
	}

	return json.Marshal(msg)
}

func newCertStateFromConfig(c *config.C, cipher string) (*CertState, error) {
	var err error

	privPathOrPEM := c.GetString("pki.key", "")
	if privPathOrPEM == "" {
		return nil, errors.New("no pki.key path or PEM data provided")
	}

	rawKey, curve, isPkcs11, err := loadPrivateKey(privPathOrPEM)
	if err != nil {
		return nil, err
	}

	hpkePriv, hpkeHybrid, err := loadHPKEPrivateKey(c)
	if err != nil {
		return nil, err
	}

	var rawCert []byte

	pubPathOrPEM := c.GetString("pki.cert", "")
	if pubPathOrPEM == "" {
		return nil, errors.New("no pki.cert path or PEM data provided")
	}

	if strings.Contains(pubPathOrPEM, "-----BEGIN") {
		rawCert = []byte(pubPathOrPEM)
		pubPathOrPEM = "<inline>"

	} else {
		rawCert, err = os.ReadFile(pubPathOrPEM)
		if err != nil {
			return nil, fmt.Errorf("unable to read pki.cert file %s: %s", pubPathOrPEM, err)
		}
	}

	var crt, v3 cert.Certificate
	for {
		crt, rawCert, err = loadCertificate(rawCert)
		if err != nil {
			return nil, err
		}

		switch crt.Version() {
		case cert.Version3:
			if v3 != nil {
				return nil, fmt.Errorf("v3 certificate already found in pki.cert")
			}
			v3 = crt
		default:
			return nil, fmt.Errorf("unsupported certificate version %v: only v3 certificates are supported", crt.Version())
		}

		if len(rawCert) == 0 || strings.TrimSpace(string(rawCert)) == "" {
			break
		}
	}

	if v3 == nil {
		return nil, errors.New("no v3 certificate found in pki.cert")
	}

	rawInitiatingVersion := c.GetUint32("pki.initiating_version", 3)
	if rawInitiatingVersion == 0 {
		rawInitiatingVersion = 3
	}
	switch rawInitiatingVersion {
	case 3:
	default:
		return nil, fmt.Errorf("unsupported pki.initiating_version %v: only version 3 is supported", rawInitiatingVersion)
	}

	return newCertState(isPkcs11, curve, rawKey, cipher, v3, hpkePriv, hpkeHybrid)
}

func loadHPKEPrivateKey(c *config.C) ([]byte, bool, error) {
	hpkePath := c.GetString("pki.hpke_key", "")
	if hpkePath == "" {
		hpkePath = c.GetString("pki.hpke-key", "")
	}
	if hpkePath == "" {
		return nil, false, nil
	}

	pemData, err := os.ReadFile(hpkePath)
	if err != nil {
		return nil, false, fmt.Errorf("unable to read pki.hpke_key file %s: %s", hpkePath, err)
	}

	return cert.UnmarshalHPKEPrivateKeyFromPEM(pemData)
}

func newCertState(pkcs11backed bool, privateKeyCurve cert.Curve, privateKey []byte, cipher string, v3 cert.Certificate, hpkePriv []byte, hpkeHybrid bool) (*CertState, error) {
	if v3 == nil {
		return nil, errors.New("v3 certificate is required")
	}

	cs := CertState{
		privateKey:               privateKey,
		pkcs11Backed:             pkcs11backed,
		cipher:                   cipher,
		hpkePrivateKey:           hpkePriv,
		hpkeHybrid:               hpkeHybrid,
		myVpnNetworksTable:       new(bart.Lite),
		myVpnAddrsTable:          new(bart.Lite),
		myVpnBroadcastAddrsTable: new(bart.Lite),
	}

	v3hs, err := v3.MarshalForHandshakes()
	if err != nil {
		return nil, fmt.Errorf("error marshalling v3 certificate for handshake: %w", err)
	}
	ncs, err := newDataPlaneCipherSuite(cipher)
	if err != nil {
		return nil, err
	}
	hSuite := newHPKESuite(hpkeHybrid)

	var hpkePub []byte
	if hk, ok := v3.(cert.HPKEPublicKeyer); ok {
		hpkePub = hk.HPKEPublicKey()
	}

	if len(hpkePub) == 0 {
		return nil, fmt.Errorf("v3 certificate does not contain an HPKE public key")
	}
	if len(hpkePriv) == 0 {
		return nil, fmt.Errorf("v3 certificate requires pki.hpke_key but no key was provided")
	}
	if err := cert.VerifyHPKEPrivateKey(hpkePub, hpkePriv); err != nil {
		return nil, fmt.Errorf("HPKE private key does not match HPKE public key in certificate: %w", err)
	}

	cs.v3Cert = v3
	cs.v3Credential = handshake.NewCredential(v3, v3hs, hpkePriv, hpkePub, ncs, hSuite)
	cs.initiatingVersion = cert.Version3

	for _, network := range v3.Networks() {
		cs.myVpnNetworks = append(cs.myVpnNetworks, network)
		cs.myVpnNetworksTable.Insert(network)

		cs.myVpnAddrs = append(cs.myVpnAddrs, network.Addr())
		cs.myVpnAddrsTable.Insert(netip.PrefixFrom(network.Addr(), network.Addr().BitLen()))

		if network.Addr().Is4() {
			addr := network.Masked().Addr().As4()
			mask := net.CIDRMask(network.Bits(), network.Addr().BitLen())
			binary.BigEndian.PutUint32(addr[:], binary.BigEndian.Uint32(addr[:])|^binary.BigEndian.Uint32(mask))
			cs.myVpnBroadcastAddrsTable.Insert(netip.PrefixFrom(netip.AddrFrom4(addr), network.Addr().BitLen()))
		}
	}

	return &cs, nil
}

func loadPrivateKey(privPathOrPEM string) (rawKey []byte, curve cert.Curve, isPkcs11 bool, err error) {
	var pemPrivateKey []byte
	if strings.Contains(privPathOrPEM, "-----BEGIN") {
		pemPrivateKey = []byte(privPathOrPEM)
		privPathOrPEM = "<inline>"
		rawKey, _, curve, err = cert.UnmarshalPrivateKeyFromPEM(pemPrivateKey)
		if err != nil {
			return nil, curve, false, fmt.Errorf("error while unmarshaling pki.key %s: %s", privPathOrPEM, err)
		}
	} else if strings.HasPrefix(privPathOrPEM, "pkcs11:") {
		rawKey = []byte(privPathOrPEM)
		return rawKey, cert.Curve_P256, true, nil
	} else {
		pemPrivateKey, err = os.ReadFile(privPathOrPEM)
		if err != nil {
			return nil, curve, false, fmt.Errorf("unable to read pki.key file %s: %s", privPathOrPEM, err)
		}
		rawKey, _, curve, err = cert.UnmarshalPrivateKeyFromPEM(pemPrivateKey)
		if err != nil {
			return nil, curve, false, fmt.Errorf("error while unmarshaling pki.key %s: %s", privPathOrPEM, err)
		}
	}

	return
}

func loadCertificate(b []byte) (cert.Certificate, []byte, error) {
	c, b, err := cert.UnmarshalCertificateFromPEM(b)
	if err != nil {
		return nil, b, fmt.Errorf("error while unmarshaling pki.cert: %w", err)
	}

	if c.Expired(time.Now()) {
		return nil, b, fmt.Errorf("nebula certificate for this host is expired")
	}

	if len(c.Networks()) == 0 {
		return nil, b, fmt.Errorf("no networks encoded in certificate")
	}

	if c.IsCA() {
		return nil, b, fmt.Errorf("host certificate is a CA certificate")
	}

	return c, b, nil
}

func loadCAPoolFromConfig(l *slog.Logger, c *config.C) (*cert.CAPool, error) {
	caPathOrPEM := c.GetString("pki.ca", "")
	if caPathOrPEM == "" {
		return nil, errors.New("no pki.ca path or PEM data provided")
	}

	var caReader io.ReadCloser
	var err error

	if strings.Contains(caPathOrPEM, "-----BEGIN") {
		caReader = io.NopCloser(strings.NewReader(caPathOrPEM))
	} else {
		caReader, err = os.Open(caPathOrPEM)
		if err != nil {
			return nil, fmt.Errorf("unable to read pki.ca file %s: %s", caPathOrPEM, err)
		}
	}
	defer caReader.Close()

	caPool, err := cert.NewCAPoolFromPEMReader(caReader)
	if errors.Is(err, cert.ErrExpired) {
		var expired int
		for _, crt := range caPool.CAs {
			if crt.Certificate.Expired(time.Now()) {
				expired++
				l.Warn("expired certificate present in CA pool", "cert", crt)
			}
		}

		if expired >= len(caPool.CAs) {
			return nil, errors.New("no valid CA certificates present")
		}

	} else if err != nil {
		return nil, fmt.Errorf("error while adding CA certificate to CA trust store: %s", err)
	}

	bl := c.GetStringSlice("pki.blocklist", []string{})
	if len(bl) > 0 {
		for _, fp := range bl {
			caPool.BlocklistFingerprint(fp)
		}

		l.Info("Blocklisted certificates", "fingerprintCount", len(bl))
	}

	return caPool, nil
}
