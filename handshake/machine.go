package handshake

import (
	"crypto/hkdf"
	"crypto/sha256"
	"fmt"
	"hash"
	"slices"
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

func (m *Machine) ProcessPacket(out, packet []byte) ([]byte, *Result, error) {
	if m.failed {
		return nil, nil, ErrMachineFailed
	}
	if len(packet) < header.Len {
		return nil, nil, ErrPacketTooShort
	}
	if header.MessageSubType(packet[1]) != m.subtype {
		return nil, nil, ErrSubtypeMismatch
	}
	if m.initiator && m.step == 0 {
		m.failed = true
		return nil, nil, ErrInitiateNotCalled
	}

	cred := m.getCred(m.myVersion)
	if cred == nil {
		m.failed = true
		return nil, nil, fmt.Errorf("%w: %v", ErrNoCredential, m.myVersion)
	}

	body := packet[header.Len:]
	suite := cred.HPKESuite
	if suite == nil {
		m.failed = true
		return nil, nil, fmt.Errorf("hpke suite not configured")
	}
	kem := suite.KEM
	encLen := kem.EncLen()

	if len(body) < encLen {
		m.failed = true
		return nil, nil, fmt.Errorf("packet too short for enc, need %d got %d", encLen, len(body))
	}
	enc := body[:encLen]
	ct := body[encLen:]

	var ctx *hpke.Context
	var err error

	if !m.initiator {
		ctx, err = hpke.SetupBaseR(enc, cred.HPKEPriv, []byte("nebula-hpke-msg1"), suite)
		if err != nil {
			return nil, nil, fmt.Errorf("hpke base: %w", err)
		}
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
	}

	msg, err := ctx.Open(nil, ct)
	if err != nil {
		return nil, nil, fmt.Errorf("hpke open: %w", err)
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

	flags := m.myMsgFlags()
	hsBytes, err := m.marshalOutgoing(flags)
	if err != nil {
		return nil, err
	}

	ct, err := ctx.Seal(nil, hsBytes)
	if err != nil {
		return nil, fmt.Errorf("hpke seal: %w", err)
	}

	start := len(out)
	out = slices.Grow(out, header.Len)[:start+header.Len]
	header.Encode(
		out[start:],
		header.Version, header.Handshake, m.subtype,
		m.result.RemoteIndex,
		uint64(m.step+1),
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

	ssLen := suite.KEM.SharedSecretLen()
	ks := make([]byte, 2*ssLen)
	masterKey := hkdfExpand(sha256.New, ks, "nebula-hpke-master", 32)
	eKey := hkdfExpand(sha256.New, masterKey, "initiator-to-responder", 32)
	dKey := hkdfExpand(sha256.New, masterKey, "responder-to-initiator", 32)

	var ek [32]byte
	var dk [32]byte
	copy(ek[:], eKey)
	copy(dk[:], dKey)

	cs := cred.CipherSuite
	m.result.EKey = noise.UnsafeNewCipherState(cs, ek, 0)
	m.result.DKey = noise.UnsafeNewCipherState(cs, dk, 0)
	m.result.MessageIndex = uint64(m.step)

	if m.initiator {
		m.result.EKey, m.result.DKey = m.result.DKey, m.result.EKey
	}

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

	var rc cert.Certificate
	var err error

	v := cert.Version(payload.CertVersion)
	rc, err = cert.Recombine(v, payload.Cert, nil, cred.Cert.Curve())
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

	flags := m.myMsgFlags()
	hsBytes, err := m.marshalOutgoing(flags)
	if err != nil {
		return nil, err
	}

	ct, err := ctx.Seal(nil, hsBytes)
	if err != nil {
		return nil, fmt.Errorf("hpke seal: %w", err)
	}

	start := len(out)
	out = slices.Grow(out, header.Len)[:start+header.Len]
	header.Encode(
		out[start:],
		header.Version, header.Handshake, m.subtype,
		m.result.RemoteIndex,
		uint64(m.step+1),
	)

	out = append(out, enc...)
	out = append(out, ct...)

	m.step++
	return out, nil
}

func (m *Machine) buildResponse(out []byte) ([]byte, *noise.CipherState, *noise.CipherState, error) {
	return nil, nil, nil, fmt.Errorf("buildResponse not used in HPKE machine")
}
