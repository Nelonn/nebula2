package handshake

import (
	"net/netip"
	"testing"
	"time"

	"github.com/flynn/noise"
	"github.com/slackhq/nebula/cert"
	"github.com/slackhq/nebula/header"
	"github.com/slackhq/nebula/hpke"
	"github.com/stretchr/testify/require"
)

type testPeer struct {
	version  cert.Version
	creds    map[cert.Version]*Credential
	hpkePub  []byte
	hpkePriv []byte
}

func (p *testPeer) getCredential(v cert.Version) *Credential {
	return p.creds[v]
}

func newTestPeer(t *testing.T, ca cert.Certificate, caKey []byte, name string, networks []netip.Prefix) *testPeer {
	t.Helper()
	return newTestPeerWithCipher(t, ca, caKey, name, networks, noise.CipherChaChaPoly)
}

func newTestPeerWithCipher(t *testing.T, ca cert.Certificate, caKey []byte, name string, networks []netip.Prefix, cipher noise.CipherFunc) *testPeer {
	t.Helper()
	hSuite := hpke.DefaultHPKE
	hpkePub, hpkePriv, err := hSuite.KEM.GenerateKeyPair()
	require.NoError(t, err)

	c, err := (&cert.TBSCertificate{
		Version:       cert.Version3,
		Curve:         cert.Curve_CURVE25519,
		Name:          name,
		Networks:      networks,
		NotBefore:     ca.NotBefore(),
		NotAfter:      ca.NotAfter(),
		PublicKey:     hpkePub,
		HPKEPublicKey: hpkePub,
		IsCA:          false,
	}).Sign(ca, ca.Curve(), caKey)
	require.NoError(t, err)

	hsBytes, err := c.MarshalForHandshakes()
	require.NoError(t, err)

	ncs := noise.NewCipherSuite(noise.DH25519, cipher, noise.HashSHA256)

	return &testPeer{
		version:  cert.Version3,
		hpkePub:  hpkePub,
		hpkePriv: hpkePriv,
		creds: map[cert.Version]*Credential{
			cert.Version3: NewCredential(c, hsBytes, hpkePriv, hpkePub, ncs, hSuite),
		},
	}
}

func testVerifier(pool *cert.CAPool) CertVerifier {
	return func(c cert.Certificate) (*cert.CachedCertificate, error) {
		return pool.VerifyCertificate(time.Now(), c)
	}
}

func newTestMachine(t *testing.T, peer *testPeer, verifier CertVerifier, initiator bool, localIndex uint32) *Machine {
	t.Helper()
	m, err := NewMachine(
		peer.version, peer.getCredential,
		verifier, func() (uint32, error) { return localIndex, nil },
		initiator, header.HandshakeHPKE0,
	)
	require.NoError(t, err)
	return m
}

func doFullHandshake(t *testing.T, initPeer, respPeer *testPeer, caPool *cert.CAPool) (initResult, respResult *Result) {
	t.Helper()
	v := testVerifier(caPool)

	initM := newTestMachine(t, initPeer, v, true, 1000)
	respM := newTestMachine(t, respPeer, v, false, 2000)

	// msg1
	msg1, err := initM.Initiate(nil, respPeer.hpkePub)
	require.NoError(t, err)
	require.NotEmpty(t, msg1)

	// responder processes msg1
	resp, respResult, err := respM.ProcessPacket(nil, msg1)
	require.NoError(t, err)
	require.NotNil(t, respResult)
	require.NotEmpty(t, resp)

	// msg2 has 4-byte initiator_index prefix, strip for initiator
	_, initResult, err = initM.ProcessPacket(nil, resp[4:])
	require.NoError(t, err)
	require.NotNil(t, initResult)

	return initResult, respResult
}
