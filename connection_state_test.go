package nebula

import (
	"net/netip"
	"testing"
	"time"

	"github.com/flynn/noise"
	"github.com/slackhq/nebula/cert"
	ct "github.com/slackhq/nebula/cert_test"
	"github.com/slackhq/nebula/handshake"
	"github.com/slackhq/nebula/header"
	"github.com/slackhq/nebula/hpke"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// runTestHandshake runs a complete IX handshake between two freshly-built
// peers and returns the initiator and responder Results. Used to produce
// real cipher states for tests that need to exercise post-handshake glue.
func runTestHandshake(t *testing.T) (initR, respR *handshake.Result) {
	t.Helper()

	ca, _, caKey, _ := ct.NewTestCaCert(
		cert.Version3, cert.Curve_CURVE25519, time.Time{}, time.Time{}, nil, nil, nil,
	)
	caPool := ct.NewTestCAPool(ca)

	type testPeer struct {
		creds   handshake.GetCredentialFunc
		hpkePub []byte
		hpkePriv []byte
	}

	makePeer := func(name string, networks []netip.Prefix) *testPeer {
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
		ncs := noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashSHA256)
		cred := handshake.NewCredential(c, hsBytes, hpkePriv, hpkePub, ncs, hSuite)
		return &testPeer{
			creds: func(v cert.Version) *handshake.Credential {
				if v == cert.Version3 {
					return cred
				}
				return nil
			},
			hpkePub:  hpkePub,
			hpkePriv: hpkePriv,
		}
	}

	verifier := func(c cert.Certificate) (*cert.CachedCertificate, error) {
		return caPool.VerifyCertificate(time.Now(), c)
	}

	initPeer := makePeer("initiator", []netip.Prefix{netip.MustParsePrefix("10.0.0.1/24")})
	respPeer := makePeer("responder", []netip.Prefix{netip.MustParsePrefix("10.0.0.2/24")})

	initM, err := handshake.NewMachine(
		cert.Version3, initPeer.creds, verifier,
		func() (uint32, error) { return 1000, nil },
		true, header.HandshakeHPKE0,
	)
	require.NoError(t, err)

	respM, err := handshake.NewMachine(
		cert.Version3, respPeer.creds, verifier,
		func() (uint32, error) { return 2000, nil },
		false, header.HandshakeHPKE0,
	)
	require.NoError(t, err)

	msg1, err := initM.Initiate(nil, respPeer.hpkePub)
	require.NoError(t, err)

	resp, respR, err := respM.ProcessPacket(nil, msg1)
	require.NoError(t, err)
	require.NotNil(t, respR)

	_, initR, err = initM.ProcessPacket(nil, resp[4:])
	require.NoError(t, err)
	require.NotNil(t, initR)

	return initR, respR
}

func TestNewConnectionStateFromResult(t *testing.T) {
	initR, respR := runTestHandshake(t)

	t.Run("initiator", func(t *testing.T) {
		ci := newConnectionStateFromResult(initR)
		assert.True(t, ci.initiator)
		assert.Equal(t, initR.MyCert, ci.myCert)
		assert.Equal(t, initR.RemoteCert, ci.peerCert)
		assert.NotNil(t, ci.eKey)
		assert.NotNil(t, ci.dKey)

		// IX has 2 handshake messages; the next data-plane send is counter=3.
		assert.Equal(t, uint64(2), ci.messageCounter.Load(),
			"messageCounter must equal Result.MessageIndex so the next send is N+1")

		// Both handshake counters must be marked seen so they don't appear lost.
		// Check returns false if an index has already been recorded.
		assert.False(t, ci.window.Check(nil, 1), "counter 1 must already be seen")
		assert.False(t, ci.window.Check(nil, 2), "counter 2 must already be seen")
		// Counter 3 is the next data-plane message and must NOT be pre-marked.
		assert.True(t, ci.window.Check(nil, 3), "counter 3 must not be pre-seeded")
	})

	t.Run("responder", func(t *testing.T) {
		ci := newConnectionStateFromResult(respR)
		assert.False(t, ci.initiator)
		assert.Equal(t, respR.MyCert, ci.myCert)
		assert.Equal(t, respR.RemoteCert, ci.peerCert)
		assert.NotNil(t, ci.eKey)
		assert.NotNil(t, ci.dKey)
		assert.Equal(t, uint64(2), ci.messageCounter.Load())
	})
}
