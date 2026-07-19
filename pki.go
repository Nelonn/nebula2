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
	v1Cert       cert.Certificate
	v1Credential *handshake.Credential

	v2Cert       cert.Certificate
	v2Credential *handshake.Credential

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
		pki.computeHeaderKey()
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
	block, _ := aes.NewCipher(p.headerKey[:])
	p.headerBlock.Store(&headerBlockWrapper{block: block})
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
		if newState.v1Cert != nil {
			if currentState.v1Cert == nil {
				//adding certs is fine, actually. Networks-in-common confirmed in newCertState().
			} else {
				// did IP in cert change? if so, don't set
				if !slices.Equal(currentState.v1Cert.Networks(), newState.v1Cert.Networks()) {
					return util.NewContextualError(
						"Networks in new cert was different from old",
						m{"new_networks": newState.v1Cert.Networks(), "old_networks": currentState.v1Cert.Networks(), "cert_version": cert.Version1},
						nil,
					)
				}

				if currentState.v1Cert.Curve() != newState.v1Cert.Curve() {
					return util.NewContextualError(
						"Curve in new v1 cert was different from old",
						m{"new_curve": newState.v1Cert.Curve(), "old_curve": currentState.v1Cert.Curve(), "cert_version": cert.Version1},
						nil,
					)
				}
			}
		}

		if newState.v2Cert != nil {
			if currentState.v2Cert == nil {
				//adding certs is fine, actually
			} else {
				// did IP in cert change? if so, don't set
				if !slices.Equal(currentState.v2Cert.Networks(), newState.v2Cert.Networks()) {
					return util.NewContextualError(
						"Networks in new cert was different from old",
						m{"new_networks": newState.v2Cert.Networks(), "old_networks": currentState.v2Cert.Networks(), "cert_version": cert.Version2},
						nil,
					)
				}

				if currentState.v2Cert.Curve() != newState.v2Cert.Curve() {
					return util.NewContextualError(
						"Curve in new cert was different from old",
						m{"new_curve": newState.v2Cert.Curve(), "old_curve": currentState.v2Cert.Curve(), "cert_version": cert.Version2},
						nil,
					)
				}
			}

		} else if currentState.v2Cert != nil {
			//newState.v1Cert is non-nil bc empty certstates aren't permitted
			if newState.v1Cert == nil {
				return util.NewContextualError("v1 and v2 certs are nil, this should be impossible", nil, err)
			}
			//if we're going to v1-only, we need to make sure we didn't orphan any v2-cert vpnaddrs
			if !slices.Equal(currentState.v2Cert.Networks(), newState.v1Cert.Networks()) {
				return util.NewContextualError(
					"Removing a V2 cert is not permitted unless it has identical networks to the new V1 cert",
					m{"new_v1_networks": newState.v1Cert.Networks(), "old_v2_networks": currentState.v2Cert.Networks()},
					nil,
				)
			}
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
	switch v {
	case cert.Version1:
		return cs.v1Credential
	case cert.Version2:
		return cs.v2Credential
	case cert.Version3:
		return cs.v3Credential
	}
	return nil
}

func (cs *CertState) getCertificate(v cert.Version) cert.Certificate {
	switch v {
	case cert.Version1:
		return cs.v1Cert
	case cert.Version2:
		return cs.v2Cert
	case cert.Version3:
		return cs.v3Cert
	}

	return nil
}

func newCipherSuite(curve cert.Curve, pkcs11backed bool, cipher string) (noise.CipherSuite, error) {
	var dhFunc noise.DHFunc
	switch curve {
	case cert.Curve_CURVE25519:
		dhFunc = noise.DH25519
	case cert.Curve_P256:
		if pkcs11backed {
			dhFunc = noiseutil.DHP256PKCS11
		} else {
			dhFunc = noiseutil.DHP256
		}
	default:
		return nil, fmt.Errorf("unsupported curve: %s", curve)
	}

	if cipher == "chachapoly" {
		return noise.NewCipherSuite(dhFunc, noise.CipherChaChaPoly, noise.HashSHA256), nil
	}
	return noise.NewCipherSuite(dhFunc, noiseutil.CipherAESGCM, noise.HashSHA256), nil
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

func (cs *CertState) GetHPKEPriv() []byte  { return cs.hpkePrivateKey }
func (cs *CertState) GetHPKEHybrid() bool  { return cs.hpkeHybrid }

func (cs *CertState) String() string {
	b, err := cs.MarshalJSON()
	if err != nil {
		return fmt.Sprintf("error marshaling certificate state: %v", err)
	}
	return string(b)
}

func (cs *CertState) MarshalJSON() ([]byte, error) {
	msg := []json.RawMessage{}
	if cs.v1Cert != nil {
		b, err := cs.v1Cert.MarshalJSON()
		if err != nil {
			return nil, err
		}
		msg = append(msg, b)
	}

	if cs.v2Cert != nil {
		b, err := cs.v2Cert.MarshalJSON()
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

	var crt, v1, v2, v3 cert.Certificate
	for {
		crt, rawCert, err = loadCertificate(rawCert)
		if err != nil {
			return nil, err
		}

		switch crt.Version() {
		case cert.Version1:
			if v1 != nil {
				return nil, fmt.Errorf("v1 certificate already found in pki.cert")
			}
			v1 = crt
		case cert.Version2:
			if v2 != nil {
				return nil, fmt.Errorf("v2 certificate already found in pki.cert")
			}
			v2 = crt
		case cert.Version3:
			if v3 != nil {
				return nil, fmt.Errorf("v3 certificate already found in pki.cert")
			}
			v3 = crt
		default:
			return nil, fmt.Errorf("unknown certificate version %v", crt.Version())
		}

		if len(rawCert) == 0 || strings.TrimSpace(string(rawCert)) == "" {
			break
		}
	}

	if v3 == nil && v1 == nil && v2 == nil {
		return nil, errors.New("no certificates found in pki.cert")
	}

	rawInitiatingVersion := c.GetUint32("pki.initiating_version", 3)
	if rawInitiatingVersion == 0 {
		rawInitiatingVersion = 3
	}
	var initiatingVersion cert.Version
	switch rawInitiatingVersion {
	case 1:
		if v1 == nil {
			return nil, fmt.Errorf("can not use pki.initiating_version 1 without a v1 certificate in pki.cert")
		}
		initiatingVersion = cert.Version1
	case 2:
		initiatingVersion = cert.Version2
	case 3:
		if v3 == nil {
			return nil, fmt.Errorf("can not use pki.initiating_version 3 without a v3 certificate in pki.cert")
		}
		initiatingVersion = cert.Version3
	default:
		return nil, fmt.Errorf("unknown pki.initiating_version: %v", rawInitiatingVersion)
	}

	return newCertState(initiatingVersion, v1, v2, isPkcs11, curve, rawKey, cipher, v3, hpkePriv, hpkeHybrid)
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

func newCertState(dv cert.Version, v1, v2 cert.Certificate, pkcs11backed bool, privateKeyCurve cert.Curve, privateKey []byte, cipher string, v3 cert.Certificate, hpkePriv []byte, hpkeHybrid bool) (*CertState, error) {
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

	if v1 != nil && v2 != nil {
		if !slices.Equal(v1.PublicKey(), v2.PublicKey()) {
			return nil, util.NewContextualError("v1 and v2 public keys are not the same, ignoring", nil, nil)
		}
		if v1.Curve() != v2.Curve() {
			return nil, util.NewContextualError("v1 and v2 curve are not the same, ignoring", nil, nil)
		}
		if v1.Networks()[0] != v2.Networks()[0] {
			return nil, util.NewContextualError("v1 and v2 networks are not the same", nil, nil)
		}
		cs.initiatingVersion = dv
	}

	if v1 != nil {
		if !pkcs11backed {
			if err := v1.VerifyPrivateKey(privateKeyCurve, privateKey); err != nil {
				return nil, fmt.Errorf("private key is not a pair with public key in nebula cert")
			}
		}
		v1hs, err := v1.MarshalForHandshakes()
		if err != nil {
			return nil, fmt.Errorf("error marshalling v1 certificate for handshake: %w", err)
		}
		ncs, err := newCipherSuite(v1.Curve(), pkcs11backed, cipher)
		if err != nil {
			return nil, err
		}
		cs.v1Cert = v1
		cs.v1Credential = handshake.NewCredential(v1, v1hs, nil, nil, ncs, nil)
		if cs.initiatingVersion == 0 {
			cs.initiatingVersion = cert.Version1
		}
	}

	if v2 != nil {
		if !pkcs11backed {
			if err := v2.VerifyPrivateKey(privateKeyCurve, privateKey); err != nil {
				return nil, fmt.Errorf("private key is not a pair with public key in nebula cert")
			}
		}
		v2hs, err := v2.MarshalForHandshakes()
		if err != nil {
			return nil, fmt.Errorf("error marshalling v2 certificate for handshake: %w", err)
		}
		ncs, err := newCipherSuite(v2.Curve(), pkcs11backed, cipher)
		if err != nil {
			return nil, err
		}
		cs.v2Cert = v2
		cs.v2Credential = handshake.NewCredential(v2, v2hs, nil, nil, ncs, nil)
		if cs.initiatingVersion == 0 {
			cs.initiatingVersion = cert.Version2
		}
	}

	if v3 != nil {
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

		if len(hpkePriv) > 0 && len(hpkePub) > 0 {
			if err := cert.VerifyHPKEPrivateKey(hpkePub, hpkePriv); err != nil {
				return nil, fmt.Errorf("HPKE private key does not match HPKE public key in certificate: %w", err)
			}
		}

		if v1 != nil || v2 != nil {
			ref := cs.getCertificate(cert.Version2)
			if ref == nil {
				ref = v1
			}
			if ref != nil && len(ref.Networks()) > 0 && len(v3.Networks()) > 0 &&
				!slices.Equal(ref.Networks(), v3.Networks()) {
				return nil, util.NewContextualError(
					"v3 certificate networks do not match existing v1/v2 certificate networks",
					m{"v3_networks": v3.Networks(), "existing_networks": ref.Networks()}, nil)
			}
		}

		cs.v3Cert = v3
		cs.v3Credential = handshake.NewCredential(v3, v3hs, hpkePriv, hpkePub, ncs, hSuite)
		if cs.initiatingVersion == 0 {
			cs.initiatingVersion = cert.Version3
		} else {
			cs.initiatingVersion = dv
		}
	}

	var crt cert.Certificate
	crt = cs.getCertificate(cert.Version3)
	if crt == nil {
		crt = cs.getCertificate(cert.Version2)
	}
	if crt == nil {
		crt = cs.getCertificate(cert.Version1)
	}

	for _, network := range crt.Networks() {
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
