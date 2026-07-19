package handshake

import (
	"net/netip"
	"testing"
	"time"

	"github.com/flynn/noise"
	"github.com/slackhq/nebula/cert"
	ct "github.com/slackhq/nebula/cert_test"
	"github.com/slackhq/nebula/hpke"
	"github.com/slackhq/nebula/noiseutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHPKEHappyPath(t *testing.T) {
	ca, _, caKey, _ := ct.NewTestCaCert(
		cert.Version2, cert.Curve_CURVE25519, time.Time{}, time.Time{}, nil, nil, nil,
	)
	caPool := ct.NewTestCAPool(ca)

	initPeer := newTestPeer(t, ca, caKey, "init", []netip.Prefix{netip.MustParsePrefix("10.0.0.1/24")})
	respPeer := newTestPeer(t, ca, caKey, "resp", []netip.Prefix{netip.MustParsePrefix("10.0.0.2/24")})

	initR, respR := doFullHandshake(t, initPeer, respPeer, caPool)

	// Cert names
	assert.Equal(t, "resp", initR.RemoteCert.Certificate.Name())
	assert.Equal(t, "init", respR.RemoteCert.Certificate.Name())

	// Indexes
	assert.Equal(t, uint32(1000), initR.LocalIndex)
	assert.Equal(t, uint32(2000), initR.RemoteIndex)
	assert.Equal(t, uint32(2000), respR.LocalIndex)
	assert.Equal(t, uint32(1000), respR.RemoteIndex)

	// Message index
	assert.Equal(t, uint64(2), initR.MessageIndex, "HPKE has 2 messages")
	assert.Equal(t, uint64(2), respR.MessageIndex, "HPKE has 2 messages")

	// Data plane encryption works in both directions
	ct1, err := initR.EKey.Encrypt(nil, nil, []byte("hello from init"))
	require.NoError(t, err)
	pt, err := respR.DKey.Decrypt(nil, nil, ct1)
	require.NoError(t, err)
	assert.Equal(t, []byte("hello from init"), pt)

	ct2, err := respR.EKey.Encrypt(nil, nil, []byte("hello from resp"))
	require.NoError(t, err)
	pt2, err := initR.DKey.Decrypt(nil, nil, ct2)
	require.NoError(t, err)
	assert.Equal(t, []byte("hello from resp"), pt2)

	// Initiator/responder flags
	assert.True(t, initR.Initiator)
	assert.False(t, respR.Initiator)

	// Handshake time is set
	assert.NotZero(t, initR.HandshakeTime)
	assert.NotZero(t, respR.HandshakeTime)

	// Both sides have each other's certs
	assert.NotNil(t, initR.RemoteCert)
	assert.NotNil(t, respR.RemoteCert)
	assert.Equal(t, initR.MyCert.PublicKey(), respR.RemoteCert.Certificate.PublicKey())
}

func TestHPKEWithAESCipher(t *testing.T) {
	ca, _, caKey, _ := ct.NewTestCaCert(
		cert.Version2, cert.Curve_CURVE25519, time.Time{}, time.Time{}, nil, nil, nil,
	)
	caPool := ct.NewTestCAPool(ca)

	initPeer := newTestPeerWithCipher(t, ca, caKey, "init",
		[]netip.Prefix{netip.MustParsePrefix("10.0.0.1/24")}, noiseutil.CipherAESGCM)
	respPeer := newTestPeerWithCipher(t, ca, caKey, "resp",
		[]netip.Prefix{netip.MustParsePrefix("10.0.0.2/24")}, noiseutil.CipherAESGCM)

	initR, respR := doFullHandshake(t, initPeer, respPeer, caPool)
	assert.NotNil(t, initR)
	assert.NotNil(t, respR)

	// Data plane works with AES-GCM
	ct, err := initR.EKey.Encrypt(nil, nil, []byte("aes test"))
	require.NoError(t, err)
	pt, err := respR.DKey.Decrypt(nil, nil, ct)
	require.NoError(t, err)
	assert.Equal(t, []byte("aes test"), pt)
}

func TestHPKEKeyDerivation(t *testing.T) {
	// Verify both sides derive identical data plane keys
	ca, _, caKey, _ := ct.NewTestCaCert(
		cert.Version2, cert.Curve_CURVE25519, time.Time{}, time.Time{}, nil, nil, nil,
	)
	caPool := ct.NewTestCAPool(ca)

	initPeer := newTestPeer(t, ca, caKey, "init", []netip.Prefix{netip.MustParsePrefix("10.0.0.1/24")})
	respPeer := newTestPeer(t, ca, caKey, "resp", []netip.Prefix{netip.MustParsePrefix("10.0.0.2/24")})

	initR, respR := doFullHandshake(t, initPeer, respPeer, caPool)

	// initR.EKey == respR.DKey (init→resp direction)
	eKeyBytes := initR.EKey.UnsafeKey()
	dKeyBytes := respR.DKey.UnsafeKey()
	assert.Equal(t, eKeyBytes, dKeyBytes, "init EKey must equal resp DKey")

	// respR.EKey == initR.DKey (resp→init direction)
	respEKey := respR.EKey.UnsafeKey()
	initDKey := initR.DKey.UnsafeKey()
	assert.Equal(t, respEKey, initDKey, "resp EKey must equal init DKey")

	// Two directions must differ
	assert.NotEqual(t, eKeyBytes, respEKey, "directional keys must be different")
}

func TestHPKEInitiateErrors(t *testing.T) {
	ca, _, caKey, _ := ct.NewTestCaCert(
		cert.Version2, cert.Curve_CURVE25519, time.Time{}, time.Time{}, nil, nil, nil,
	)
	caPool := ct.NewTestCAPool(ca)
	peer := newTestPeer(t, ca, caKey, "test", []netip.Prefix{netip.MustParsePrefix("10.0.0.1/24")})
	v := testVerifier(caPool)

	t.Run("initiate on responder", func(t *testing.T) {
		m := newTestMachine(t, peer, v, false, 100)
		_, err := m.Initiate(nil, nil)
		require.ErrorIs(t, err, ErrInitiateOnResponder)
		assert.True(t, m.Failed())
	})

	t.Run("initiate called twice", func(t *testing.T) {
		m := newTestMachine(t, peer, v, true, 100)
		_, err := m.Initiate(nil, peer.hpkePub)
		require.NoError(t, err)
		_, err = m.Initiate(nil, peer.hpkePub)
		require.ErrorIs(t, err, ErrInitiateAlreadyCalled)
		assert.True(t, m.Failed())
	})

	t.Run("process packet before initiate on initiator", func(t *testing.T) {
		m := newTestMachine(t, peer, v, true, 100)
		_, _, err := m.ProcessPacket(nil, make([]byte, 100))
		require.ErrorIs(t, err, ErrInitiateNotCalled)
		assert.True(t, m.Failed())
	})

	t.Run("calling failed machine", func(t *testing.T) {
		m := newTestMachine(t, peer, v, false, 100)
		_, err := m.Initiate(nil, nil)
		require.Error(t, err)
		assert.True(t, m.Failed())
		_, _, err = m.ProcessPacket(nil, nil)
		require.ErrorIs(t, err, ErrMachineFailed)
	})
}

func TestHPKEProcessPacketErrors(t *testing.T) {
	ca, _, caKey, _ := ct.NewTestCaCert(
		cert.Version2, cert.Curve_CURVE25519, time.Time{}, time.Time{}, nil, nil, nil,
	)
	caPool := ct.NewTestCAPool(ca)
	peer := newTestPeer(t, ca, caKey, "test", []netip.Prefix{netip.MustParsePrefix("10.0.0.1/24")})
	v := testVerifier(caPool)

	t.Run("packet too short", func(t *testing.T) {
		m := newTestMachine(t, peer, v, false, 100)
		_, _, err := m.ProcessPacket(nil, []byte{1, 2, 3})
		require.ErrorIs(t, err, ErrPacketTooShort)
		assert.False(t, m.Failed(), "short packet should not kill machine")
	})

	t.Run("invalid cert is fatal", func(t *testing.T) {
		otherCA, _, otherCAKey, _ := ct.NewTestCaCert(
			cert.Version2, cert.Curve_CURVE25519, time.Time{}, time.Time{}, nil, nil, nil,
		)
		otherPeer := newTestPeer(t, otherCA, otherCAKey, "other", []netip.Prefix{netip.MustParsePrefix("10.0.0.2/24")})

		initM := newTestMachine(t, otherPeer, testVerifier(ct.NewTestCAPool(otherCA)), true, 100)
		msg1, err := initM.Initiate(nil, peer.hpkePub)
		require.NoError(t, err)

		respM := newTestMachine(t, peer, v, false, 200)
		_, _, err = respM.ProcessPacket(nil, msg1)
		require.Error(t, err)
		assert.True(t, respM.Failed())
	})

	t.Run("garbage packet does not fail machine", func(t *testing.T) {
		m := newTestMachine(t, peer, v, false, 200)
		rnd := make([]byte, 64)
		_, _, err := m.ProcessPacket(nil, rnd)
		require.Error(t, err)
		assert.False(t, m.Failed(), "garbage should not kill the machine")
	})
}

func TestHPKEExpiredCert(t *testing.T) {
	ca, _, caKey, _ := ct.NewTestCaCert(
		cert.Version2, cert.Curve_CURVE25519,
		time.Now().Add(-24*time.Hour), time.Now().Add(24*time.Hour),
		nil, nil, nil,
	)
	caPool := ct.NewTestCAPool(ca)

	expCert, _, _, _ := ct.NewTestCert(
		cert.Version2, cert.Curve_CURVE25519, ca, caKey,
		"expired", time.Now().Add(-2*time.Hour), time.Now().Add(-1*time.Hour),
		[]netip.Prefix{netip.MustParsePrefix("10.0.0.1/24")}, nil, nil,
	)
	expHsBytes, err := expCert.MarshalForHandshakes()
	require.NoError(t, err)
	ncs := noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashSHA256)
	hSuite := hpke.DefaultHPKE
	expHPKEPub, expHPKEPriv, err := hpke.DHKEM_X25519.GenerateKeyPair()
	require.NoError(t, err)

	expiredPeer := &testPeer{
		version:  cert.Version2,
		hpkePub:  expHPKEPub,
		hpkePriv: expHPKEPriv,
		creds: map[cert.Version]*Credential{
			cert.Version2: NewCredential(expCert, expHsBytes, expHPKEPriv, expHPKEPub, ncs, hSuite),
		},
	}

	respPeer := newTestPeer(t, ca, caKey, "resp", []netip.Prefix{netip.MustParsePrefix("10.0.0.2/24")})

	v := testVerifier(caPool)
	initM := newTestMachine(t, expiredPeer, v, true, 100)
	msg1, err := initM.Initiate(nil, respPeer.hpkePub)
	require.NoError(t, err)

	respM := newTestMachine(t, respPeer, v, false, 200)
	_, _, err = respM.ProcessPacket(nil, msg1)
	require.ErrorContains(t, err, "verify cert")
	assert.True(t, respM.Failed())
}

func TestHPKEMsg2Prefix(t *testing.T) {
	// Verify msg2 has initiator_index prefix
	ca, _, caKey, _ := ct.NewTestCaCert(
		cert.Version2, cert.Curve_CURVE25519, time.Time{}, time.Time{}, nil, nil, nil,
	)
	caPool := ct.NewTestCAPool(ca)
	v := testVerifier(caPool)

	initPeer := newTestPeer(t, ca, caKey, "init", []netip.Prefix{netip.MustParsePrefix("10.0.0.1/24")})
	respPeer := newTestPeer(t, ca, caKey, "resp", []netip.Prefix{netip.MustParsePrefix("10.0.0.2/24")})

	initM := newTestMachine(t, initPeer, v, true, 100)
	respM := newTestMachine(t, respPeer, v, false, 200)

	msg1, err := initM.Initiate(nil, respPeer.hpkePub)
	require.NoError(t, err)

	resp, result, err := respM.ProcessPacket(nil, msg1)
	require.NoError(t, err)
	require.NotNil(t, result)

	// First 4 bytes must be non-zero initiator index
	require.GreaterOrEqual(t, len(resp), 4)
	idx := uint32(resp[0])<<24 | uint32(resp[1])<<16 | uint32(resp[2])<<8 | uint32(resp[3])
	assert.Equal(t, uint32(100), idx, "first 4 bytes should be initiator's local index")

	// Strip prefix and feed to initiator
	_, initResult, err := initM.ProcessPacket(nil, resp[4:])
	require.NoError(t, err)
	require.NotNil(t, initResult)
}

func TestHPKEMessageIndexTracking(t *testing.T) {
	ca, _, caKey, _ := ct.NewTestCaCert(
		cert.Version2, cert.Curve_CURVE25519, time.Time{}, time.Time{}, nil, nil, nil,
	)
	caPool := ct.NewTestCAPool(ca)
	v := testVerifier(caPool)

	initPeer := newTestPeer(t, ca, caKey, "init", []netip.Prefix{netip.MustParsePrefix("10.0.0.1/24")})
	respPeer := newTestPeer(t, ca, caKey, "resp", []netip.Prefix{netip.MustParsePrefix("10.0.0.2/24")})

	initM := newTestMachine(t, initPeer, v, true, 100)
	respM := newTestMachine(t, respPeer, v, false, 200)

	assert.Equal(t, 0, initM.MessageIndex())
	assert.Equal(t, 0, respM.MessageIndex())

	msg1, err := initM.Initiate(nil, respPeer.hpkePub)
	require.NoError(t, err)
	assert.Equal(t, 1, initM.MessageIndex())

	resp1, result1, err := respM.ProcessPacket(nil, msg1)
	require.NoError(t, err)
	assert.NotNil(t, result1)
	assert.Equal(t, 2, respM.MessageIndex())

	_, result2, err := initM.ProcessPacket(nil, resp1[4:])
	require.NoError(t, err)
	assert.NotNil(t, result2)
	assert.Equal(t, 2, initM.MessageIndex())
}

func TestHPKEBufferReuse(t *testing.T) {
	ca, _, caKey, _ := ct.NewTestCaCert(
		cert.Version2, cert.Curve_CURVE25519, time.Time{}, time.Time{}, nil, nil, nil,
	)
	caPool := ct.NewTestCAPool(ca)
	initPeer := newTestPeer(t, ca, caKey, "init", []netip.Prefix{netip.MustParsePrefix("10.0.0.1/24")})
	respPeer := newTestPeer(t, ca, caKey, "resp", []netip.Prefix{netip.MustParsePrefix("10.0.0.2/24")})
	v := testVerifier(caPool)

	initM := newTestMachine(t, initPeer, v, true, 1000)
	respM := newTestMachine(t, respPeer, v, false, 2000)

	msg1, err := initM.Initiate(nil, respPeer.hpkePub)
	require.NoError(t, err)

	t.Run("response writes into provided buffer", func(t *testing.T) {
		buf := make([]byte, 0, 4096)
		resp, result, err := respM.ProcessPacket(buf, msg1)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.NotEmpty(t, resp)
		if len(resp) > 0 && len(buf) > 0 {
			assert.Equal(t, &buf[:1][0], &resp[:1][0],
				"response should reuse the provided buffer")
		}
	})

	t.Run("initiate writes into provided buffer", func(t *testing.T) {
		initM2 := newTestMachine(t, initPeer, v, true, 3000)
		buf := make([]byte, 0, 4096)
		msg, err := initM2.Initiate(buf, respPeer.hpkePub)
		require.NoError(t, err)
		assert.NotEmpty(t, msg)
		if len(msg) > 0 && len(buf) > 0 {
			assert.Equal(t, &buf[:1][0], &msg[:1][0],
				"initiate should reuse the provided buffer")
		}
	})

	t.Run("nil out still works", func(t *testing.T) {
		initM2 := newTestMachine(t, initPeer, v, true, 4000)
		respM2 := newTestMachine(t, respPeer, v, false, 5000)

		msg1, err := initM2.Initiate(nil, respPeer.hpkePub)
		require.NoError(t, err)

		resp, _, err := respM2.ProcessPacket(nil, msg1)
		require.NoError(t, err)

		out, result, err := initM2.ProcessPacket(nil, resp[4:])
		require.NoError(t, err)
		assert.NotNil(t, result)
		assert.Nil(t, out, "initiator should have no response for HPKE msg2")
	})
}

func TestHPKEResultFields(t *testing.T) {
	ca, _, caKey, _ := ct.NewTestCaCert(
		cert.Version2, cert.Curve_CURVE25519, time.Time{}, time.Time{}, nil, nil, nil,
	)
	caPool := ct.NewTestCAPool(ca)

	initPeer := newTestPeer(t, ca, caKey, "init", []netip.Prefix{netip.MustParsePrefix("10.0.0.1/24")})
	respPeer := newTestPeer(t, ca, caKey, "resp", []netip.Prefix{netip.MustParsePrefix("10.0.0.2/24")})

	initR, respR := doFullHandshake(t, initPeer, respPeer, caPool)

	assert.True(t, initR.Initiator)
	assert.False(t, respR.Initiator)
	assert.NotZero(t, initR.HandshakeTime)
	assert.NotZero(t, respR.HandshakeTime)
	assert.NotNil(t, initR.RemoteCert)
	assert.NotNil(t, respR.RemoteCert)
}

func TestHPKEMachineProcessPayload(t *testing.T) {
	ca, _, caKey, _ := ct.NewTestCaCert(
		cert.Version2, cert.Curve_CURVE25519, time.Time{}, time.Time{}, nil, nil, nil,
	)
	caPool := ct.NewTestCAPool(ca)
	peer := newTestPeer(t, ca, caKey, "test", []netip.Prefix{netip.MustParsePrefix("10.0.0.1/24")})
	v := testVerifier(caPool)

	t.Run("empty message with expects fails", func(t *testing.T) {
		m := newTestMachine(t, peer, v, false, 100)
		err := m.processPayload(nil, msgFlags{expectsPayload: true, expectsCert: true})
		require.ErrorIs(t, err, ErrMissingContent)
		assert.True(t, m.Failed())
	})

	t.Run("empty message with no expects passes", func(t *testing.T) {
		m := newTestMachine(t, peer, v, false, 100)
		err := m.processPayload(nil, msgFlags{})
		require.NoError(t, err)
		assert.False(t, m.Failed())
	})

	t.Run("malformed protobuf is fatal", func(t *testing.T) {
		m := newTestMachine(t, peer, v, false, 100)
		err := m.processPayload([]byte{0xff, 0xff, 0xff}, msgFlags{expectsPayload: true, expectsCert: true})
		require.Error(t, err)
		assert.True(t, m.Failed())
	})

	t.Run("unexpected payload data when not expected is fatal", func(t *testing.T) {
		m := newTestMachine(t, peer, v, false, 100)
		p := Payload{InitiatorIndex: 1}
		b := MarshalPayload(nil, p)
		err := m.processPayload(b, msgFlags{})
		require.ErrorIs(t, err, ErrUnexpectedContent)
		assert.True(t, m.Failed())
	})

	t.Run("zero initiator index on responder is fatal", func(t *testing.T) {
		m := newTestMachine(t, peer, v, false, 100)
		p := Payload{Cert: []byte{1}, CertVersion: 2, InitiatorIndex: 0, Time: 1}
		b := MarshalPayload(nil, p)
		err := m.processPayload(b, msgFlags{expectsPayload: true, expectsCert: true})
		require.ErrorIs(t, err, ErrInvalidRemoteIndex)
		assert.True(t, m.Failed())
	})
}

func TestHPKERequireComplete(t *testing.T) {
	ca, _, caKey, _ := ct.NewTestCaCert(
		cert.Version2, cert.Curve_CURVE25519, time.Time{}, time.Time{}, nil, nil, nil,
	)
	caPool := ct.NewTestCAPool(ca)
	peer := newTestPeer(t, ca, caKey, "test", []netip.Prefix{netip.MustParsePrefix("10.0.0.1/24")})
	v := testVerifier(caPool)

	t.Run("missing both fails", func(t *testing.T) {
		m := newTestMachine(t, peer, v, false, 100)
		err := m.requireComplete()
		require.ErrorIs(t, err, ErrIncompleteHandshake)
		assert.True(t, m.Failed())
	})

	t.Run("payload only fails", func(t *testing.T) {
		m := newTestMachine(t, peer, v, false, 100)
		m.payloadSet = true
		err := m.requireComplete()
		require.ErrorIs(t, err, ErrIncompleteHandshake)
		assert.True(t, m.Failed())
	})

	t.Run("cert only fails", func(t *testing.T) {
		m := newTestMachine(t, peer, v, false, 100)
		m.remoteCertSet = true
		err := m.requireComplete()
		require.ErrorIs(t, err, ErrIncompleteHandshake)
		assert.True(t, m.Failed())
	})

	t.Run("both set passes", func(t *testing.T) {
		m := newTestMachine(t, peer, v, false, 100)
		m.payloadSet = true
		m.remoteCertSet = true
		err := m.requireComplete()
		require.NoError(t, err)
		assert.False(t, m.Failed())
	})
}

func TestHPKEDecryptionRecovery(t *testing.T) {
	ca, _, caKey, _ := ct.NewTestCaCert(
		cert.Version2, cert.Curve_CURVE25519, time.Time{}, time.Time{}, nil, nil, nil,
	)
	caPool := ct.NewTestCAPool(ca)
	v := testVerifier(caPool)
	initPeer := newTestPeer(t, ca, caKey, "init", []netip.Prefix{netip.MustParsePrefix("10.0.0.1/24")})
	respPeer := newTestPeer(t, ca, caKey, "resp", []netip.Prefix{netip.MustParsePrefix("10.0.0.2/24")})

	// Create a valid full handshake, then corrupt msg2 and verify recovery
	initM := newTestMachine(t, initPeer, v, true, 100)
	respM := newTestMachine(t, respPeer, v, false, 200)

	msg1, err := initM.Initiate(nil, respPeer.hpkePub)
	require.NoError(t, err)

	resp, _, err := respM.ProcessPacket(nil, msg1)
	require.NoError(t, err)

	// Corrupt msg2 body (after 4-byte prefix)
	respBody := resp[4:]
	corrupted := make([]byte, len(respBody))
	copy(corrupted, respBody)
	for i := 4; i < len(corrupted); i++ {
		corrupted[i] ^= 0xff
	}

	// Decryption failure should NOT fail the machine
	_, _, err = initM.ProcessPacket(nil, corrupted)
	require.Error(t, err)
	assert.False(t, initM.Failed(), "HPKE decryption failure should be recoverable")

	// Machine should still complete with the legitimate packet
	_, result, err := initM.ProcessPacket(nil, respBody)
	require.NoError(t, err)
	require.NotNil(t, result)
}
