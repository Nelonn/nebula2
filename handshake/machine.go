package handshake

import (
	"bytes"
	"crypto/hkdf"
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

func (m *Machine) SetPeerHPKEPub(pk []byte) {
	m.peerHPKEPub = append([]byte(nil), pk...)
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

// Initiate builds msg1: [sender_hpke_pub] + [enc] + [ciphertext].
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
// For responder: packet = [sender_hpke_pub] + [enc] + [ct]  (msg1 from initiator)
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

	var msg []byte
	if len(m.decryptedMsg) > 0 {
		msg = m.decryptedMsg
		m.decryptedMsg = nil
	} else {
		kem := suite.KEM
		encLen := kem.EncLen()
		var enc, ct []byte

		if !m.initiator {
			pubLen := kem.PublicKeyLen()
			if len(packet) < pubLen+encLen+1 {
				return nil, nil, ErrPacketTooShort
			}
			pkS := packet[:pubLen]
			enc = packet[pubLen : pubLen+encLen]
			ct = packet[pubLen+encLen:]
			if len(m.peerHPKEPub) > 0 && !bytes.Equal(m.peerHPKEPub, pkS) {
				m.failed = true
				return nil, nil, fmt.Errorf("handshake sender HPKE key changed")
			}
			m.peerHPKEPub = append(m.peerHPKEPub[:0], pkS...)
		} else {
			if len(packet) < encLen+1 {
				return nil, nil, ErrPacketTooShort
			}
			enc = packet[:encLen]
			ct = packet[encLen:]
		}

		var ctx *hpke.Context
		var err error

		if !m.initiator {
			info := hpkeInfo("nebula-hpke-msg1", m.peerHPKEPub, cred.HPKEPub)
			ctx, err = hpke.SetupAuthR(enc, cred.hpkePriv, m.peerHPKEPub, info, suite)
			if err != nil {
				return nil, nil, fmt.Errorf("hpke auth: %w", err)
			}
			m.ss1 = ctx.SharedSecret()
		} else {
			pkS := m.remoteHPKEPub
			if len(pkS) == 0 {
				m.failed = true
				return nil, nil, fmt.Errorf("no remote hpke key for auth decryption")
			}
			// msg2: responder is AuthEncap sender (pkS = responder pub known to us as remoteHPKEPub),
			// we (initiator) are the recipient. info = label + responder_pub + initiator_pub.
			info := hpkeInfo("nebula-hpke-msg2", pkS, cred.HPKEPub)
			ctx, err = hpke.SetupAuthR(enc, cred.hpkePriv, pkS, info, suite)
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
	if len(pkR) == 0 && m.result.RemoteCert != nil {
		pkR = hpkePubKey(m.result.RemoteCert.Certificate)
	}
	if len(pkR) == 0 {
		return nil, fmt.Errorf("no peer HPKE public key for auth response")
	}

	// msg2: responder (us) is AuthEncap sender, initiator (pkR) is recipient.
	// info = label + our_pub (sender) + initiator_pub (recipient).
	info := hpkeInfo("nebula-hpke-msg2", cred.HPKEPub, pkR)
	ctx, enc, err := hpke.SetupAuthS(pkR, cred.hpkePriv, info, suite)
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
	ks := make([]byte, len(m.ss1)+len(m.ss2))
	copy(ks, m.ss1)
	copy(ks[len(m.ss1):], m.ss2)
	prk, err := hkdf.Extract(sha256.New, ks, nil)
	if err != nil {
		panic(fmt.Sprintf("hkdf.Extract: %v", err))
	}

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
		panic(fmt.Sprintf("hkdf.Expand: %v", err))
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
		if len(m.peerHPKEPub) > 0 && !bytes.Equal(m.peerHPKEPub, payload.HPKEPublicKey) {
			m.failed = true
			return fmt.Errorf("payload HPKE key does not match sender HPKE key")
		}
		m.peerHPKEPub = append(m.peerHPKEPub[:0], payload.HPKEPublicKey...)
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

	// Bind all advertised HPKE keys to the validated certificate to prevent
	// HPKE-key-swapping attacks.
	certHPKEPub := payload.HPKEPublicKey
	if hk, ok := rc.(cert.HPKEPublicKeyer); ok {
		if k := hk.HPKEPublicKey(); len(k) > 0 {
			certHPKEPub = k
		}
	}
	if len(certHPKEPub) == 0 {
		m.failed = true
		return fmt.Errorf("certificate does not contain an HPKE public key")
	}
	if len(m.peerHPKEPub) > 0 && !bytes.Equal(certHPKEPub, m.peerHPKEPub) {
		m.failed = true
		return fmt.Errorf("sender HPKE key does not match certificate HPKE key")
	}
	if m.initiator && len(m.remoteHPKEPub) > 0 && !bytes.Equal(certHPKEPub, m.remoteHPKEPub) {
		m.failed = true
		return fmt.Errorf("remote HPKE key does not match certificate HPKE key")
	}
	if len(certHPKEPub) > 0 && len(payload.HPKEPublicKey) > 0 {
		if !bytes.Equal(certHPKEPub, payload.HPKEPublicKey) {
			m.failed = true
			return fmt.Errorf("payload HPKE key does not match certificate HPKE key")
		}
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

	// msg1 carries the sender HPKE public key in clear so the responder can
	// perform AuthDecap before decrypting the certificate payload.
	info := hpkeInfo("nebula-hpke-msg1", cred.HPKEPub, remoteHPKEPub)
	ctx, enc, err := hpke.SetupAuthS(remoteHPKEPub, cred.hpkePriv, info, suite)
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

	out = append(out, cred.HPKEPub...)
	out = append(out, enc...)
	out = append(out, ct...)

	m.step++
	return out, nil
}

// hpkeInfo builds the HPKE `info` parameter by binding a label, the sender
// public key, and the recipient public key together. This prevents replay and
// cross-host forwarding attacks by tying each ciphertext to a specific
// (sender, recipient) pair.
func hpkeInfo(label string, senderPub, recipientPub []byte) []byte {
	out := make([]byte, 0, len(label)+1+len(senderPub)+1+len(recipientPub))
	out = append(out, []byte(label)...)
	out = append(out, 0x00)
	out = append(out, senderPub...)
	out = append(out, 0x00)
	out = append(out, recipientPub...)
	return out
}
