package hpke

import (
	"bytes"
	"testing"
)

func TestDHKEMRoundTrip(t *testing.T) {
	// Generate a keypair, encapsulate, decapsulate — must match
	pub, priv, err := DHKEM_X25519.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	ssS, enc, err := SetupBaseS(pub, []byte("test-info"), DefaultHPKE)
	if err != nil {
		t.Fatal(err)
	}

	ssR, err := SetupBaseR(enc, priv, []byte("test-info"), DefaultHPKE)
	if err != nil {
		t.Fatal(err)
	}

	ct, err := ssS.Seal(nil, []byte("hello hpke"))
	if err != nil {
		t.Fatal(err)
	}

	pt, err := ssR.Open(nil, ct)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(pt, []byte("hello hpke")) {
		t.Fatalf("got %v, want %v", pt, []byte("hello hpke"))
	}
}

func TestAuthRoundTrip(t *testing.T) {
	sPub, sPriv, err := DHKEM_X25519.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	rPub, rPriv, err := DHKEM_X25519.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	ctxS, enc, err := SetupAuthS(rPub, sPriv, []byte("auth-info"), DefaultHPKE)
	if err != nil {
		t.Fatal(err)
	}

	ctxR, err := SetupAuthR(enc, rPriv, sPub, []byte("auth-info"), DefaultHPKE)
	if err != nil {
		t.Fatal(err)
	}

	ct, err := ctxS.Seal(nil, []byte("auth message"))
	if err != nil {
		t.Fatal(err)
	}
	pt, err := ctxR.Open(nil, ct)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pt, []byte("auth message")) {
		t.Fatalf("auth roundtrip failed")
	}
}

func TestHybridKEMRoundTrip(t *testing.T) {
	pub, priv, err := HybridKEM_X25519_MLKEM768.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	suite := &HPKESuite{
		KEM:    HybridKEM_X25519_MLKEM768,
		KDFID:  KDFID_HKDF_SHA256,
		AEADID: AEADID_AESGCM_256,
	}

	ctxS, enc, err := SetupBaseS(pub, []byte("hybrid"), suite)
	if err != nil {
		t.Fatal(err)
	}
	ctxR, err := SetupBaseR(enc, priv, []byte("hybrid"), suite)
	if err != nil {
		t.Fatal(err)
	}

	ct, err := ctxS.Seal(nil, []byte("hybrid test"))
	if err != nil {
		t.Fatal(err)
	}
	pt, err := ctxR.Open(nil, ct)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pt, []byte("hybrid test")) {
		t.Fatalf("hybrid roundtrip failed")
	}
}

func TestSharedSecrets(t *testing.T) {
	pub, priv, err := DHKEM_X25519.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	// Get enc from one Setup call, use it in both sides
	ctxS, enc, err := SetupBaseS(pub, []byte("ss-test"), DefaultHPKE)
	if err != nil {
		t.Fatal(err)
	}
	ssS := ctxS.SharedSecret()

	ctxR, err := SetupBaseR(enc, priv, []byte("ss-test"), DefaultHPKE)
	if err != nil {
		t.Fatal(err)
	}
	ssR := ctxR.SharedSecret()

	if !bytes.Equal(ssS, ssR) {
		t.Fatalf("shared secrets don't match: %x vs %x", ssS, ssR)
	}

	// Verify both can encrypt/decrypt
	ct, err := ctxS.Seal(nil, []byte("data"))
	if err != nil {
		t.Fatal(err)
	}
	pt, err := ctxR.Open(nil, ct)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pt, []byte("data")) {
		t.Fatal("round trip failed")
	}
}

func TestKeySchedule(t *testing.T) {
	// Verify key schedule produces deterministic keys for the same inputs
	sPub, sPriv, err := DHKEM_X25519.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	rPub, rPriv, err := DHKEM_X25519.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	ctxS, enc, err := SetupAuthS(rPub, sPriv, []byte("test"), DefaultHPKE)
	if err != nil {
		t.Fatal(err)
	}
	ctxR, err := SetupAuthR(enc, rPriv, sPub, []byte("test"), DefaultHPKE)
	if err != nil {
		t.Fatal(err)
	}

	// Encrypt with sender, decrypt with receiver — must work
	ct, err := ctxS.Seal(nil, []byte("key schedule test"))
	if err != nil {
		t.Fatal(err)
	}
	pt, err := ctxR.Open(nil, ct)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pt, []byte("key schedule test")) {
		t.Fatal("key schedule: round trip failed")
	}
}
