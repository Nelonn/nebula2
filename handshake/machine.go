package handshake

import (
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"hash"
	"time"

	"github.com/flynn/noise"
	"github.com/slackhq/nebula/cert"
	"github.com/slackhq/nebula/header"
	"github.com/slackhq/nebula/hpke"
)

type IndexAllocator func() (uint32, error)

type CertVerifier func(cert.Certificate) (*cert.CachedCertificate, error)

type Result struct {
	EKey          *noise.CipherState
	DKey          *noise.CipherState
	Cipher        noise.CipherFunc
	MyCert        cert.Certificate
	RemoteCert    *cert.CachedCertificate
	RemoteIndex   uint32
	LocalIndex    uint32
	HandshakeTime uint64
	MessageIndex  uint64
	Initiator     bool

	// LocalIndex and RemoteIndex are the 32-bit session identifiers.
	// They are placed inside the AES-ECB-encrypted header so DPI never sees them.
}

type Machine struct {
	getCred        GetCredentialFunc
	allocIndex     IndexAllocator
	verifier       CertVerifier
	result         *Result
	msgs           []msgFlags
	myVersion      cert.Version
	subtype        header.MessageSubType
	indexAllocated bool
	remoteCertSet  bool
	payloadSet     bool
	failed         bool
	initiator      bool
	step           int
	remoteHPKEPub  []byte
	peerHPKEPub    []byte
	ss1            []byte
	ss2            []byte
	decryptedMsg   []byte
}

func NewMachine(
	version cert.Version,
	getCred GetCredentialFunc,
	verifier CertVerifier,
	allocIndex IndexAllocator,
	initiator bool,
	subtype header.MessageSubType,
) (*Machine, error) {
	info, err := subtypeInfoFor(subtype)
	if err != nil {
		return nil, err
	}
	cred := getCred(version)
	if cred == nil {
		return nil, fmt.Errorf("%w: %v", ErrNoCredential, version)
	}
	return &Machine{
		subtype:   subtype,
		msgs:      info.msgs,
		getCred:   getCred,
		allocIndex: allocIndex,
		verifier:  verifier,
		myVersion: version,
		initiator: initiator,
		result: &Result{
			Initiator: initiator,
			Cipher:    cred.CipherSuite,
		},
	}, nil
}

func (m *Machine) Failed() bool                  { return m.failed }
func (m *Machine) Subtype() header.MessageSubType { return m.subtype }
func (m *Machine) MessageIndex() int              { return m.step }
func (m *Machine) LocalIndex() uint32 {
	if m.result != nil {
		return m.result.LocalIndex
	}
	return 0
}

func (m *Machine) SetDecryptedPayload(buf []byte) {
	m.decryptedMsg = append([]byte(nil), buf...)
}

func (m *Machine) SetSS1(ss []byte) {
	m.ss1 = ss
}

func (m *Machine) requireComplete() error {
	if !m.payloadSet || !m.remoteCertSet {
		m.failed = true
		return ErrIncompleteHandshake
	}
	return nil
}

func (m *Machine) myMsgFlags() msgFlags {
	if m.step < len(m.msgs) {
		return m.msgs[m.step]
	}
	return msgFlags{}
}

func (m *Machine) peerMsgFlags() msgFlags {
	idx := m.step - 1
	if idx >= 0 && idx < len(m.msgs) {
		return m.msgs[idx]
	}
	return msgFlags{}
}

// Initiate builds msg1: [enc] + [ciphertext] — no plaintext header.
func (m *Machine) Initiate(out []byte, remoteHPKEPub []byte) ([]byte, error) {
	if m.failed {
		return nil, ErrMachineFailed
	}
	if !m.initiator {
		m.failed = true
		return nil, ErrInitiateOnResponder
	}
	if m.step != 0 {
		m.failed = true
		return nil, ErrInitiateAlreadyCalled
	}

	cred := m.getCred(m.myVersion)
	if cred == nil {
		m.failed = true
		return nil, fmt.Errorf("%w: %v", ErrNoCredential, m.myVersion)
	}

	m.remoteHPKEPub = remoteHPKEPub
	return m.initiateEncrypt(out, remoteHPKEPub, cred)
}

// ProcessPacket handles an incoming handshake message.
// For responder: packet = [enc] + [ct]  (msg1 from initiator)
// For initiator: packet = [enc] + [ct]  (msg2 from responder, already stripped of index prefix)
func (m *Machine) ProcessPacket(out, packet []byte) ([]byte, *Result, error) {
	if m.failed {
		return nil, nil, ErrMachineFailed
	}

	// Initiate must be called first for initiators.
	if m.initiator && m.step == 0 {
		m.failed = true
		return nil, nil, ErrInitiateNotCalled
	}

	cred := m.getCred(m.myVersion)
	if cred == nil {
		m.failed = true
		return nil, nil, fmt.Errorf("%w: %v", ErrNoCredential, m.myVersion)
	}

	suite := cred.HPKESuite
	if suite == nil {
		m.failed = true
		return nil, nil, fmt.Errorf("hpke suite not configured")
	}

	kem := suite.KEM
	encLen := kem.EncLen()

	if len(packet) < encLen+1 {
		return nil, nil, ErrPacketTooShort
	}
	enc := packet[:encLen]
	ct := packet[encLen:]

	var msg []byte
	if len(m.decryptedMsg) > 0 {
		msg = m.decryptedMsg
		m.decryptedMsg = nil
	} else {
		var ctx *hpke.Context
		var err error

		if !m.initiator {
			ctx, err = hpke.SetupBaseR(enc, cred.HPKEPriv, []byte("nebula-hpke-msg1"), suite)
			if err != nil {
				return nil, nil, fmt.Errorf("hpke base: %w", err)
			}
			m.ss1 = ctx.SharedSecret()
		} else {
			pkS := m.remoteHPKEPub
			if len(pkS) == 0 {
				m.failed = true
				return nil, nil, fmt.Errorf("no remote hpke key for auth decryption")
			}
			ctx, err = hpke.SetupAuthR(enc, cred.HPKEPriv, pkS, []byte("nebula-hpke-msg2"), suite)
			if err != nil {
				return nil, nil, fmt.Errorf("hpke auth: %w", err)
			}
			m.ss2 = ctx.SharedSecret()
		}

		msg, err = ctx.Open(nil, ct)
		if err != nil {
			return nil, nil, fmt.Errorf("hpke open: %w", err)
		}
	}

	m.step++
	flags := m.peerMsgFlags()

	if err := m.processPayload(msg, flags); err != nil {
		return nil, nil, err
	}

	if !m.initiator {
		rsp, err := m.respond(out)
		if err != nil {
			m.failed = true
			return nil, nil, err
		}
		if rsp != nil {
			return rsp, m.completed(), nil
		}
		return nil, nil, nil
	}

	if err := m.requireComplete(); err != nil {
		return nil, nil, err
	}
	return nil, m.completed(), nil
}

func hpkePubKey(c cert.Certificate) []byte {
	if hk, ok := c.(cert.HPKEPublicKeyer); ok {
		return hk.HPKEPublicKey()
	}
	return nil
}

// respond builds msg2: [initiator_index(4)] + [enc] + [ciphertext]
func (m *Machine) respond(out []byte) ([]byte, error) {
	cred := m.getCred(m.myVersion)
	if cred == nil {
		return nil, fmt.Errorf("%w: %v", ErrNoCredential, m.myVersion)
	}
	suite := cred.HPKESuite
	if suite == nil {
		return nil, fmt.Errorf("hpke suite not configured")
	}

	pkR := m.peerHPKEPub
	if len(pkR) == 0 {
		peerCert := m.result.RemoteCert.Certificate
		pkR = hpkePubKey(peerCert)
		if pkR == nil {
			pkR = peerCert.PublicKey()
		}
	}

	ctx, enc, err := hpke.SetupAuthS(pkR, cred.HPKEPriv, []byte("nebula-hpke-msg2"), suite)
	if err != nil {
		return nil, fmt.Errorf("hpke auth setup: %w", err)
	}
	m.ss2 = ctx.SharedSecret()

	flags := m.myMsgFlags()
	hsBytes, err := m.marshalOutgoing(flags)
	if err != nil {
		return nil, err
	}

	ct, err := ctx.Seal(nil, hsBytes)
	if err != nil {
		return nil, fmt.Errorf("hpke seal: %w", err)
	}

	// msg2: [initiator_index(4)] + [enc] + [ciphertext]
	idx := m.result.RemoteIndex // initiator's index
	out = append(out,
		byte(idx>>24), byte(idx>>16), byte(idx>>8), byte(idx),
	)
	out = append(out, enc...)
	out = append(out, ct...)

	m.step++
	if err := m.requireComplete(); err != nil {
		return nil, err
	}
	return out, nil
}

func (m *Machine) completed() *Result {
	cred := m.getCred(m.myVersion)
	if cred == nil {
		return m.result
	}
	suite := cred.HPKESuite
	if suite == nil {
		return m.result
	}

	// HKDF-Extract: concat(ss1, ss2) → uniform PRK (RFC 5869)
	mac := hmac.New(sha256.New, nil)
	mac.Write(m.ss1)
	mac.Write(m.ss2)
	prk := mac.Sum(nil)

	// HKDF-Expand: PRK → master key
	masterKey := hkdfExpand(sha256.New, prk, "nebula-hpke-master", 32)

	var ek [32]byte
	var dk [32]byte

	if m.initiator {
		// Initiator: EKey = "initiator-to-responder" (encrypt), DKey = "responder-to-initiator" (decrypt)
		e := hkdfExpand(sha256.New, masterKey, "initiator-to-responder", 32)
		d := hkdfExpand(sha256.New, masterKey, "responder-to-initiator", 32)
		copy(ek[:], e)
		copy(dk[:], d)
	} else {
		// Responder: EKey = "responder-to-initiator" (encrypt), DKey = "initiator-to-responder" (decrypt)
		e := hkdfExpand(sha256.New, masterKey, "responder-to-initiator", 32)
		d := hkdfExpand(sha256.New, masterKey, "initiator-to-responder", 32)
		copy(ek[:], e)
		copy(dk[:], d)
	}

	cs := cred.CipherSuite
	m.result.EKey = noise.UnsafeNewCipherState(cs, ek, 0)
	m.result.DKey = noise.UnsafeNewCipherState(cs, dk, 0)
	m.result.MessageIndex = uint64(m.step)

	return m.result
}

func hkdfExpand(h func() hash.Hash, secret []byte, label string, length int) []byte {
	key, err := hkdf.Expand(h, secret, label, length)
	if err != nil {
		panic(err)
	}
	return key
}

func (m *Machine) processPayload(msg []byte, flags msgFlags) error {
	if len(msg) == 0 {
		if flags.expectsPayload || flags.expectsCert {
			m.failed = true
			return ErrMissingContent
		}
		return nil
	}

	payload, err := UnmarshalPayload(msg)
	if err != nil {
		m.failed = true
		return fmt.Errorf("unmarshal handshake: %w", err)
	}

	hasPayloadData := payload.InitiatorIndex != 0 || payload.ResponderIndex != 0 || payload.Time != 0
	if hasPayloadData != flags.expectsPayload {
		m.failed = true
		return ErrUnexpectedContent
	}

	hasCertData := len(payload.Cert) > 0
	if hasCertData != flags.expectsCert {
		m.failed = true
		return ErrUnexpectedContent
	}

	if flags.expectsPayload {
		var remoteIndex uint32
		if m.initiator {
			remoteIndex = payload.ResponderIndex
		} else {
			remoteIndex = payload.InitiatorIndex
		}
		if remoteIndex == 0 {
			m.failed = true
			return ErrInvalidRemoteIndex
		}
		m.result.RemoteIndex = remoteIndex
		m.result.HandshakeTime = payload.Time
		m.payloadSet = true
	}

	if len(payload.HPKEPublicKey) > 0 {
		m.peerHPKEPub = append([]byte(nil), payload.HPKEPublicKey...)
	}

	if flags.expectsCert {
		if err := m.validateCert(payload); err != nil {
			return err
		}
	}
	return nil
}

func (m *Machine) validateCert(payload Payload) error {
	cred := m.getCred(m.myVersion)
	if cred == nil {
		m.failed = true
		return fmt.Errorf("%w: %v", ErrNoCredential, m.myVersion)
	}

	rc, err := cert.Recombine(
		cert.Version(payload.CertVersion),
		payload.Cert, nil, cred.Cert.Curve(),
	)
	if err != nil {
		m.failed = true
		return fmt.Errorf("recombine cert: %w", err)
	}

	if rc.Version() != m.myVersion {
		if m.getCred(rc.Version()) != nil {
			m.myVersion = rc.Version()
		}
	}

	verified, err := m.verifier(rc)
	if err != nil {
		m.failed = true
		return fmt.Errorf("verify cert: %w", err)
	}

	m.result.RemoteCert = verified
	m.remoteCertSet = true
	return nil
}

func (m *Machine) marshalOutgoing(flags msgFlags) ([]byte, error) {
	if !flags.expectsPayload && !flags.expectsCert {
		return nil, nil
	}

	var p Payload
	if flags.expectsPayload {
		if !m.indexAllocated {
			index, err := m.allocIndex()
			if err != nil {
				return nil, fmt.Errorf("%w: %w", ErrIndexAllocation, err)
			}
			m.result.LocalIndex = index
			m.indexAllocated = true
		}

		if m.initiator {
			p.InitiatorIndex = m.result.LocalIndex
		} else {
			p.ResponderIndex = m.result.LocalIndex
			p.InitiatorIndex = m.result.RemoteIndex
		}
		p.Time = uint64(time.Now().UnixNano())
	}

	if flags.expectsCert {
		cred := m.getCred(m.myVersion)
		if cred == nil {
			return nil, fmt.Errorf("%w: %v", ErrNoCredential, m.myVersion)
		}
		p.Cert = cred.Bytes
		p.CertVersion = uint32(cred.Cert.Version())
		p.HPKEPublicKey = cred.HPKEPub
		m.result.MyCert = cred.Cert
	}

	return MarshalPayload(nil, p), nil
}

func (m *Machine) initiateEncrypt(out []byte, remoteHPKEPub []byte, cred *Credential) ([]byte, error) {
	suite := cred.HPKESuite
	if suite == nil {
		return nil, fmt.Errorf("hpke suite not configured")
	}

	ctx, enc, err := hpke.SetupBaseS(remoteHPKEPub, []byte("nebula-hpke-msg1"), suite)
	if err != nil {
		return nil, fmt.Errorf("hpke setup: %w", err)
	}
	m.ss1 = ctx.SharedSecret()

	flags := m.myMsgFlags()
	hsBytes, err := m.marshalOutgoing(flags)
	if err != nil {
		return nil, err
	}

	ct, err := ctx.Seal(nil, hsBytes)
	if err != nil {
		return nil, fmt.Errorf("hpke seal: %w", err)
	}

	out = append(out, enc...)
	out = append(out, ct...)

	m.step++
	return out, nil
}
