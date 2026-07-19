package cert

import (
	"bytes"
	"io"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/slackhq/nebula/cert/p256"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewCAPoolFromBytes(t *testing.T) {
	now := time.Now()
	rootCA, _, _, rootCAPEM := NewTestCaCert(Version3, Curve_CURVE25519, now, now.Add(time.Hour), nil, nil, nil)
	rootCA01, _, _, rootCA01PEM := NewTestCaCert(Version3, Curve_CURVE25519, now, now.Add(time.Hour), nil, nil, nil)
	expiredCA, _, _, expiredPEM := NewTestCaCert(Version3, Curve_CURVE25519, now.Add(-2*time.Hour), now.Add(-time.Hour), nil, nil, nil)
	rootCAP256, _, _, p256PEM := NewTestCaCert(Version3, Curve_P256, now, now.Add(time.Hour), nil, nil, nil)

	noNewLines := append(rootCAPEM, rootCA01PEM...)
	withNewLines := append([]byte("\n# root ca\n\n"), rootCAPEM...)
	withNewLines = append(withNewLines, []byte("\n# root ca 01\n\n")...)
	withNewLines = append(withNewLines, rootCA01PEM...)

	p, err := NewCAPoolFromPEM([]byte(noNewLines))
	require.NoError(t, err)
	fpRootCA, err := rootCA.Fingerprint()
	require.NoError(t, err)
	fpRootCA01, err := rootCA01.Fingerprint()
	require.NoError(t, err)
	assert.Equal(t, p.CAs[fpRootCA].Certificate.Name(), rootCA.Name())
	assert.Equal(t, p.CAs[fpRootCA01].Certificate.Name(), rootCA01.Name())

	pp, err := NewCAPoolFromPEM([]byte(withNewLines))
	require.NoError(t, err)
	assert.Equal(t, pp.CAs[fpRootCA].Certificate.Name(), rootCA.Name())
	assert.Equal(t, pp.CAs[fpRootCA01].Certificate.Name(), rootCA01.Name())

	// expired cert, no valid certs
	ppp, err := NewCAPoolFromPEM(expiredPEM)
	assert.Equal(t, ErrExpired, err)
	fpExpired, err := expiredCA.Fingerprint()
	require.NoError(t, err)
	assert.Equal(t, expiredCA.Name(), ppp.CAs[fpExpired].Certificate.Name())

	// expired cert, with valid certs
	pppp, err := NewCAPoolFromPEM(append(expiredPEM, noNewLines...))
	assert.Equal(t, ErrExpired, err)
	assert.Equal(t, rootCA.Name(), pppp.CAs[fpRootCA].Certificate.Name())
	assert.Equal(t, rootCA01.Name(), pppp.CAs[fpRootCA01].Certificate.Name())
	assert.Equal(t, expiredCA.Name(), pppp.CAs[fpExpired].Certificate.Name())
	assert.Len(t, pppp.CAs, 3)

	ppppp, err := NewCAPoolFromPEM(p256PEM)
	require.NoError(t, err)
	fpRootCAP256, err := rootCAP256.Fingerprint()
	require.NoError(t, err)
	assert.Equal(t, rootCAP256.Name(), ppppp.CAs[fpRootCAP256].Certificate.Name())
	assert.Len(t, ppppp.CAs, 1)
}

// oneByteReader wraps a reader to return at most 1 byte per Read call,
// exercising the streaming accumulation logic in NewCAPoolFromPEMReader.
type oneByteReader struct {
	r io.Reader
}

func (o *oneByteReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	return o.r.Read(p[:1])
}

func TestNewCAPoolFromPEMReader_EmptyReader(t *testing.T) {
	pool, err := NewCAPoolFromPEMReader(bytes.NewReader(nil))
	require.NoError(t, err)
	assert.Empty(t, pool.CAs)

	pool, err = NewCAPoolFromPEMReader(strings.NewReader("   \n\t\n  "))
	require.NoError(t, err)
	assert.Empty(t, pool.CAs)
}

func TestNewCAPoolFromPEMReader_OneByteReads(t *testing.T) {
	ca1, _, _, pem1 := NewTestCaCert(Version3, Curve_CURVE25519, time.Now(), time.Now().Add(time.Hour), nil, nil, nil)
	ca2, _, _, pem2 := NewTestCaCert(Version3, Curve_CURVE25519, time.Now(), time.Now().Add(time.Hour), nil, nil, nil)

	bundle := append(pem1, pem2...)
	pool, err := NewCAPoolFromPEMReader(&oneByteReader{r: bytes.NewReader(bundle)})
	require.NoError(t, err)
	assert.Len(t, pool.CAs, 2)

	fp1, err := ca1.Fingerprint()
	require.NoError(t, err)
	fp2, err := ca2.Fingerprint()
	require.NoError(t, err)

	assert.Contains(t, pool.CAs, fp1)
	assert.Contains(t, pool.CAs, fp2)
}

func TestNewCAPoolFromPEMReader_TruncatedPEM(t *testing.T) {
	_, err := NewCAPoolFromPEMReader(strings.NewReader("-----BEGIN NEBULA CERTIFICATE-----\npartialdata"))
	assert.ErrorIs(t, err, ErrInvalidPEMBlock)
}

func TestNewCAPoolFromPEMReader_TrailingGarbage(t *testing.T) {
	_, _, _, pem1 := NewTestCaCert(Version3, Curve_CURVE25519, time.Now(), time.Now().Add(time.Hour), nil, nil, nil)

	bundle := append(pem1, []byte("some trailing garbage")...)
	_, err := NewCAPoolFromPEMReader(bytes.NewReader(bundle))
	assert.ErrorIs(t, err, ErrInvalidPEMBlock)
}

func TestCertificateV1_Verify(t *testing.T) {
	ca, _, caKey, _ := NewTestCaCert(Version3, Curve_CURVE25519, time.Now(), time.Now().Add(10*time.Minute), nil, nil, nil)
	c, _, _, _ := NewTestCert(Version3, Curve_CURVE25519, ca, caKey, "test cert", time.Now(), time.Now().Add(5*time.Minute), nil, nil, nil)

	caPool := NewCAPool()
	require.NoError(t, caPool.AddCA(ca))

	f, err := c.Fingerprint()
	require.NoError(t, err)
	caPool.BlocklistFingerprint(f)

	_, err = caPool.VerifyCertificate(time.Now(), c)
	require.EqualError(t, err, "certificate is in the block list")

	caPool.ResetCertBlocklist()
	_, err = caPool.VerifyCertificate(time.Now(), c)
	require.NoError(t, err)

	_, err = caPool.VerifyCertificate(time.Now().Add(time.Hour*1000), c)
	require.EqualError(t, err, "root certificate is expired")

	assert.PanicsWithError(t, "certificate is valid before the signing certificate", func() {
		NewTestCert(Version3, Curve_CURVE25519, ca, caKey, "test cert2", time.Time{}, time.Time{}, nil, nil, nil)
	})

	// Test group assertion
	ca, _, caKey, _ = NewTestCaCert(Version3, Curve_CURVE25519, time.Now(), time.Now().Add(10*time.Minute), nil, nil, []string{"test1", "test2"})
	caPem, err := ca.MarshalPEM()
	require.NoError(t, err)

	caPool = NewCAPool()
	b, err := caPool.AddCAFromPEM(caPem)
	require.NoError(t, err)
	assert.Empty(t, b)

	assert.PanicsWithError(t, "certificate contained a group not present on the signing ca: bad", func() {
		NewTestCert(Version3, Curve_CURVE25519, ca, caKey, "test", time.Now(), time.Now().Add(5*time.Minute), nil, nil, []string{"test1", "bad"})
	})

	c, _, _, _ = NewTestCert(Version3, Curve_CURVE25519, ca, caKey, "test2", time.Now(), time.Now().Add(5*time.Minute), nil, nil, []string{"test1"})
	require.NoError(t, err)
	_, err = caPool.VerifyCertificate(time.Now(), c)
	require.NoError(t, err)
}

func TestCertificateV1_VerifyP256(t *testing.T) {
	ca, _, caKey, _ := NewTestCaCert(Version3, Curve_P256, time.Now(), time.Now().Add(10*time.Minute), nil, nil, nil)
	c, _, _, _ := NewTestCert(Version3, Curve_P256, ca, caKey, "test", time.Now(), time.Now().Add(5*time.Minute), nil, nil, nil)

	caPool := NewCAPool()
	require.NoError(t, caPool.AddCA(ca))

	f, err := c.Fingerprint()
	require.NoError(t, err)
	caPool.BlocklistFingerprint(f)

	_, err = caPool.VerifyCertificate(time.Now(), c)
	require.EqualError(t, err, "certificate is in the block list")

	// Create a copy of the cert and swap to the alternate form for the signature
	nc := c.Copy()
	b, err := p256.Swap(c.Signature())
	require.NoError(t, err)
	require.NoError(t, nc.(*certificateV3).setSignature(b))

	_, err = caPool.VerifyCertificate(time.Now(), nc)
	require.EqualError(t, err, "certificate is in the block list")

	caPool.ResetCertBlocklist()
	_, err = caPool.VerifyCertificate(time.Now(), c)
	require.NoError(t, err)

	_, err = caPool.VerifyCertificate(time.Now().Add(time.Hour*1000), c)
	require.EqualError(t, err, "root certificate is expired")

	assert.PanicsWithError(t, "certificate is valid before the signing certificate", func() {
		NewTestCert(Version3, Curve_P256, ca, caKey, "test", time.Time{}, time.Time{}, nil, nil, nil)
	})

	// Test group assertion
	ca, _, caKey, _ = NewTestCaCert(Version3, Curve_P256, time.Now(), time.Now().Add(10*time.Minute), nil, nil, []string{"test1", "test2"})
	caPem, err := ca.MarshalPEM()
	require.NoError(t, err)

	caPool = NewCAPool()
	b, err = caPool.AddCAFromPEM(caPem)
	require.NoError(t, err)
	assert.Empty(t, b)

	assert.PanicsWithError(t, "certificate contained a group not present on the signing ca: bad", func() {
		NewTestCert(Version3, Curve_P256, ca, caKey, "test", time.Now(), time.Now().Add(5*time.Minute), nil, nil, []string{"test1", "bad"})
	})

	c, _, _, _ = NewTestCert(Version3, Curve_P256, ca, caKey, "test", time.Now(), time.Now().Add(5*time.Minute), nil, nil, []string{"test1"})
	cc, err := caPool.VerifyCertificate(time.Now(), c)
	require.NoError(t, err)

	// Reset the blocklist and block the alternate form fingerprint
	caPool.ResetCertBlocklist()
	caPool.BlocklistFingerprint(cc.fingerprint2)
	err = caPool.VerifyCachedCertificate(time.Now(), cc)
	require.EqualError(t, err, "certificate is in the block list")

	caPool.ResetCertBlocklist()
	err = caPool.VerifyCachedCertificate(time.Now(), cc)
	require.NoError(t, err)
}

func TestCertificateV1_Verify_IPs(t *testing.T) {
	caIp1 := mustParsePrefixUnmapped("10.0.0.0/16")
	caIp2 := mustParsePrefixUnmapped("192.168.0.0/24")
	ca, _, caKey, _ := NewTestCaCert(Version3, Curve_CURVE25519, time.Now(), time.Now().Add(10*time.Minute), []netip.Prefix{caIp1, caIp2}, nil, []string{"test"})

	caPem, err := ca.MarshalPEM()
	require.NoError(t, err)

	caPool := NewCAPool()
	b, err := caPool.AddCAFromPEM(caPem)
	require.NoError(t, err)
	assert.Empty(t, b)

	// ip is outside the network
	cIp1 := mustParsePrefixUnmapped("10.1.0.0/24")
	cIp2 := mustParsePrefixUnmapped("192.168.0.1/16")
	assert.PanicsWithError(t, "certificate contained a network assignment outside the limitations of the signing ca: 10.1.0.0/24", func() {
		NewTestCert(Version3, Curve_CURVE25519, ca, caKey, "test", time.Now(), time.Now().Add(5*time.Minute), []netip.Prefix{cIp1, cIp2}, nil, []string{"test"})
	})

	// ip is outside the network reversed order of above
	cIp1 = mustParsePrefixUnmapped("192.168.0.1/24")
	cIp2 = mustParsePrefixUnmapped("10.1.0.0/24")
	assert.PanicsWithError(t, "certificate contained a network assignment outside the limitations of the signing ca: 10.1.0.0/24", func() {
		NewTestCert(Version3, Curve_CURVE25519, ca, caKey, "test", time.Now(), time.Now().Add(5*time.Minute), []netip.Prefix{cIp1, cIp2}, nil, []string{"test"})
	})

	// ip is within the network but mask is outside
	cIp1 = mustParsePrefixUnmapped("10.0.1.0/15")
	cIp2 = mustParsePrefixUnmapped("192.168.0.1/24")
	assert.PanicsWithError(t, "certificate contained a network assignment outside the limitations of the signing ca: 10.0.1.0/15", func() {
		NewTestCert(Version3, Curve_CURVE25519, ca, caKey, "test", time.Now(), time.Now().Add(5*time.Minute), []netip.Prefix{cIp1, cIp2}, nil, []string{"test"})
	})

	// ip is within the network but mask is outside reversed order of above
	cIp1 = mustParsePrefixUnmapped("192.168.0.1/24")
	cIp2 = mustParsePrefixUnmapped("10.0.1.0/15")
	assert.PanicsWithError(t, "certificate contained a network assignment outside the limitations of the signing ca: 10.0.1.0/15", func() {
		NewTestCert(Version3, Curve_CURVE25519, ca, caKey, "test", time.Now(), time.Now().Add(5*time.Minute), []netip.Prefix{cIp1, cIp2}, nil, []string{"test"})
	})

	// ip and mask are within the network
	cIp1 = mustParsePrefixUnmapped("10.0.1.0/16")
	cIp2 = mustParsePrefixUnmapped("192.168.0.1/25")
	c, _, _, _ := NewTestCert(Version3, Curve_CURVE25519, ca, caKey, "test", time.Now(), time.Now().Add(5*time.Minute), []netip.Prefix{cIp1, cIp2}, nil, []string{"test"})
	_, err = caPool.VerifyCertificate(time.Now(), c)
	require.NoError(t, err)

	// Exact matches
	c, _, _, _ = NewTestCert(Version3, Curve_CURVE25519, ca, caKey, "test", time.Now(), time.Now().Add(5*time.Minute), []netip.Prefix{caIp1, caIp2}, nil, []string{"test"})
	require.NoError(t, err)
	_, err = caPool.VerifyCertificate(time.Now(), c)
	require.NoError(t, err)

	// Exact matches reversed
	c, _, _, _ = NewTestCert(Version3, Curve_CURVE25519, ca, caKey, "test", time.Now(), time.Now().Add(5*time.Minute), []netip.Prefix{caIp2, caIp1}, nil, []string{"test"})
	require.NoError(t, err)
	_, err = caPool.VerifyCertificate(time.Now(), c)
	require.NoError(t, err)

	// Exact matches reversed with just 1
	c, _, _, _ = NewTestCert(Version3, Curve_CURVE25519, ca, caKey, "test", time.Now(), time.Now().Add(5*time.Minute), []netip.Prefix{caIp1}, nil, []string{"test"})
	require.NoError(t, err)
	_, err = caPool.VerifyCertificate(time.Now(), c)
	require.NoError(t, err)
}

func TestCertificateV1_Verify_Subnets(t *testing.T) {
	caIp1 := mustParsePrefixUnmapped("10.0.0.0/16")
	caIp2 := mustParsePrefixUnmapped("192.168.0.0/24")
	ca, _, caKey, _ := NewTestCaCert(Version3, Curve_CURVE25519, time.Now(), time.Now().Add(10*time.Minute), nil, []netip.Prefix{caIp1, caIp2}, []string{"test"})

	caPem, err := ca.MarshalPEM()
	require.NoError(t, err)

	caPool := NewCAPool()
	b, err := caPool.AddCAFromPEM(caPem)
	require.NoError(t, err)
	assert.Empty(t, b)

	// ip is outside the network
	cIp1 := mustParsePrefixUnmapped("10.1.0.0/24")
	cIp2 := mustParsePrefixUnmapped("192.168.0.1/16")
	assert.PanicsWithError(t, "certificate contained an unsafe network assignment outside the limitations of the signing ca: 10.1.0.0/24", func() {
		NewTestCert(Version3, Curve_CURVE25519, ca, caKey, "test", time.Now(), time.Now().Add(5*time.Minute), nil, []netip.Prefix{cIp1, cIp2}, []string{"test"})
	})

	// ip is outside the network reversed order of above
	cIp1 = mustParsePrefixUnmapped("192.168.0.1/24")
	cIp2 = mustParsePrefixUnmapped("10.1.0.0/24")
	assert.PanicsWithError(t, "certificate contained an unsafe network assignment outside the limitations of the signing ca: 10.1.0.0/24", func() {
		NewTestCert(Version3, Curve_CURVE25519, ca, caKey, "test", time.Now(), time.Now().Add(5*time.Minute), nil, []netip.Prefix{cIp1, cIp2}, []string{"test"})
	})

	// ip is within the network but mask is outside
	cIp1 = mustParsePrefixUnmapped("10.0.1.0/15")
	cIp2 = mustParsePrefixUnmapped("192.168.0.1/24")
	assert.PanicsWithError(t, "certificate contained an unsafe network assignment outside the limitations of the signing ca: 10.0.1.0/15", func() {
		NewTestCert(Version3, Curve_CURVE25519, ca, caKey, "test", time.Now(), time.Now().Add(5*time.Minute), nil, []netip.Prefix{cIp1, cIp2}, []string{"test"})
	})

	// ip is within the network but mask is outside reversed order of above
	cIp1 = mustParsePrefixUnmapped("192.168.0.1/24")
	cIp2 = mustParsePrefixUnmapped("10.0.1.0/15")
	assert.PanicsWithError(t, "certificate contained an unsafe network assignment outside the limitations of the signing ca: 10.0.1.0/15", func() {
		NewTestCert(Version3, Curve_CURVE25519, ca, caKey, "test", time.Now(), time.Now().Add(5*time.Minute), nil, []netip.Prefix{cIp1, cIp2}, []string{"test"})
	})

	// ip and mask are within the network
	cIp1 = mustParsePrefixUnmapped("10.0.1.0/16")
	cIp2 = mustParsePrefixUnmapped("192.168.0.1/25")
	c, _, _, _ := NewTestCert(Version3, Curve_CURVE25519, ca, caKey, "test", time.Now(), time.Now().Add(5*time.Minute), nil, []netip.Prefix{cIp1, cIp2}, []string{"test"})
	require.NoError(t, err)
	_, err = caPool.VerifyCertificate(time.Now(), c)
	require.NoError(t, err)

	// Exact matches
	c, _, _, _ = NewTestCert(Version3, Curve_CURVE25519, ca, caKey, "test", time.Now(), time.Now().Add(5*time.Minute), nil, []netip.Prefix{caIp1, caIp2}, []string{"test"})
	require.NoError(t, err)
	_, err = caPool.VerifyCertificate(time.Now(), c)
	require.NoError(t, err)

	// Exact matches reversed
	c, _, _, _ = NewTestCert(Version3, Curve_CURVE25519, ca, caKey, "test", time.Now(), time.Now().Add(5*time.Minute), nil, []netip.Prefix{caIp2, caIp1}, []string{"test"})
	require.NoError(t, err)
	_, err = caPool.VerifyCertificate(time.Now(), c)
	require.NoError(t, err)

	// Exact matches reversed with just 1
	c, _, _, _ = NewTestCert(Version3, Curve_CURVE25519, ca, caKey, "test", time.Now(), time.Now().Add(5*time.Minute), nil, []netip.Prefix{caIp1}, []string{"test"})
	require.NoError(t, err)
	_, err = caPool.VerifyCertificate(time.Now(), c)
	require.NoError(t, err)
}

func TestCertificateV3_Verify(t *testing.T) {
	ca, _, caKey, _ := NewTestCaCert(Version3, Curve_CURVE25519, time.Now(), time.Now().Add(10*time.Minute), nil, nil, nil)
	c, _, _, _ := NewTestCert(Version3, Curve_CURVE25519, ca, caKey, "test cert", time.Now(), time.Now().Add(5*time.Minute), nil, nil, nil)

	caPool := NewCAPool()
	require.NoError(t, caPool.AddCA(ca))

	f, err := c.Fingerprint()
	require.NoError(t, err)
	caPool.BlocklistFingerprint(f)

	_, err = caPool.VerifyCertificate(time.Now(), c)
	require.EqualError(t, err, "certificate is in the block list")

	caPool.ResetCertBlocklist()
	_, err = caPool.VerifyCertificate(time.Now(), c)
	require.NoError(t, err)

	_, err = caPool.VerifyCertificate(time.Now().Add(time.Hour*1000), c)
	require.EqualError(t, err, "root certificate is expired")

	assert.PanicsWithError(t, "certificate is valid before the signing certificate", func() {
		NewTestCert(Version3, Curve_CURVE25519, ca, caKey, "test cert2", time.Time{}, time.Time{}, nil, nil, nil)
	})

	// Test group assertion
	ca, _, caKey, _ = NewTestCaCert(Version3, Curve_CURVE25519, time.Now(), time.Now().Add(10*time.Minute), nil, nil, []string{"test1", "test2"})
	caPem, err := ca.MarshalPEM()
	require.NoError(t, err)

	caPool = NewCAPool()
	b, err := caPool.AddCAFromPEM(caPem)
	require.NoError(t, err)
	assert.Empty(t, b)

	assert.PanicsWithError(t, "certificate contained a group not present on the signing ca: bad", func() {
		NewTestCert(Version3, Curve_CURVE25519, ca, caKey, "test", time.Now(), time.Now().Add(5*time.Minute), nil, nil, []string{"test1", "bad"})
	})

	c, _, _, _ = NewTestCert(Version3, Curve_CURVE25519, ca, caKey, "test2", time.Now(), time.Now().Add(5*time.Minute), nil, nil, []string{"test1"})
	require.NoError(t, err)
	_, err = caPool.VerifyCertificate(time.Now(), c)
	require.NoError(t, err)
}

func TestCertificateV3_VerifyP256(t *testing.T) {
	ca, _, caKey, _ := NewTestCaCert(Version3, Curve_P256, time.Now(), time.Now().Add(10*time.Minute), nil, nil, nil)
	c, _, _, _ := NewTestCert(Version3, Curve_P256, ca, caKey, "test", time.Now(), time.Now().Add(5*time.Minute), nil, nil, nil)

	caPool := NewCAPool()
	require.NoError(t, caPool.AddCA(ca))

	f, err := c.Fingerprint()
	require.NoError(t, err)
	caPool.BlocklistFingerprint(f)

	_, err = caPool.VerifyCertificate(time.Now(), c)
	require.EqualError(t, err, "certificate is in the block list")

	// Create a copy of the cert and swap to the alternate form for the signature
	nc := c.Copy()
	b, err := p256.Swap(c.Signature())
	require.NoError(t, err)
	require.NoError(t, nc.(*certificateV3).setSignature(b))

	_, err = caPool.VerifyCertificate(time.Now(), nc)
	require.EqualError(t, err, "certificate is in the block list")

	caPool.ResetCertBlocklist()
	_, err = caPool.VerifyCertificate(time.Now(), c)
	require.NoError(t, err)

	_, err = caPool.VerifyCertificate(time.Now().Add(time.Hour*1000), c)
	require.EqualError(t, err, "root certificate is expired")

	assert.PanicsWithError(t, "certificate is valid before the signing certificate", func() {
		NewTestCert(Version3, Curve_P256, ca, caKey, "test", time.Time{}, time.Time{}, nil, nil, nil)
	})

	// Test group assertion
	ca, _, caKey, _ = NewTestCaCert(Version3, Curve_P256, time.Now(), time.Now().Add(10*time.Minute), nil, nil, []string{"test1", "test2"})
	caPem, err := ca.MarshalPEM()
	require.NoError(t, err)

	caPool = NewCAPool()
	b, err = caPool.AddCAFromPEM(caPem)
	require.NoError(t, err)
	assert.Empty(t, b)

	assert.PanicsWithError(t, "certificate contained a group not present on the signing ca: bad", func() {
		NewTestCert(Version3, Curve_P256, ca, caKey, "test", time.Now(), time.Now().Add(5*time.Minute), nil, nil, []string{"test1", "bad"})
	})

	c, _, _, _ = NewTestCert(Version3, Curve_P256, ca, caKey, "test", time.Now(), time.Now().Add(5*time.Minute), nil, nil, []string{"test1"})
	cc, err := caPool.VerifyCertificate(time.Now(), c)
	require.NoError(t, err)

	// Reset the blocklist and block the alternate form fingerprint
	caPool.ResetCertBlocklist()
	caPool.BlocklistFingerprint(cc.fingerprint2)
	err = caPool.VerifyCachedCertificate(time.Now(), cc)
	require.EqualError(t, err, "certificate is in the block list")

	caPool.ResetCertBlocklist()
	err = caPool.VerifyCachedCertificate(time.Now(), cc)
	require.NoError(t, err)
}

func TestCertificateV3_Verify_IPs(t *testing.T) {
	caIp1 := mustParsePrefixUnmapped("10.0.0.0/16")
	caIp2 := mustParsePrefixUnmapped("192.168.0.0/24")
	ca, _, caKey, _ := NewTestCaCert(Version3, Curve_CURVE25519, time.Now(), time.Now().Add(10*time.Minute), []netip.Prefix{caIp1, caIp2}, nil, []string{"test"})

	caPem, err := ca.MarshalPEM()
	require.NoError(t, err)

	caPool := NewCAPool()
	b, err := caPool.AddCAFromPEM(caPem)
	require.NoError(t, err)
	assert.Empty(t, b)

	// ip is outside the network
	cIp1 := mustParsePrefixUnmapped("10.1.0.0/24")
	cIp2 := mustParsePrefixUnmapped("192.168.0.1/16")
	assert.PanicsWithError(t, "certificate contained a network assignment outside the limitations of the signing ca: 10.1.0.0/24", func() {
		NewTestCert(Version3, Curve_CURVE25519, ca, caKey, "test", time.Now(), time.Now().Add(5*time.Minute), []netip.Prefix{cIp1, cIp2}, nil, []string{"test"})
	})

	// ip is outside the network reversed order of above
	cIp1 = mustParsePrefixUnmapped("192.168.0.1/24")
	cIp2 = mustParsePrefixUnmapped("10.1.0.0/24")
	assert.PanicsWithError(t, "certificate contained a network assignment outside the limitations of the signing ca: 10.1.0.0/24", func() {
		NewTestCert(Version3, Curve_CURVE25519, ca, caKey, "test", time.Now(), time.Now().Add(5*time.Minute), []netip.Prefix{cIp1, cIp2}, nil, []string{"test"})
	})

	// ip is within the network but mask is outside
	cIp1 = mustParsePrefixUnmapped("10.0.1.0/15")
	cIp2 = mustParsePrefixUnmapped("192.168.0.1/24")
	assert.PanicsWithError(t, "certificate contained a network assignment outside the limitations of the signing ca: 10.0.1.0/15", func() {
		NewTestCert(Version3, Curve_CURVE25519, ca, caKey, "test", time.Now(), time.Now().Add(5*time.Minute), []netip.Prefix{cIp1, cIp2}, nil, []string{"test"})
	})

	// ip is within the network but mask is outside reversed order of above
	cIp1 = mustParsePrefixUnmapped("192.168.0.1/24")
	cIp2 = mustParsePrefixUnmapped("10.0.1.0/15")
	assert.PanicsWithError(t, "certificate contained a network assignment outside the limitations of the signing ca: 10.0.1.0/15", func() {
		NewTestCert(Version3, Curve_CURVE25519, ca, caKey, "test", time.Now(), time.Now().Add(5*time.Minute), []netip.Prefix{cIp1, cIp2}, nil, []string{"test"})
	})

	// ip and mask are within the network
	cIp1 = mustParsePrefixUnmapped("10.0.1.0/16")
	cIp2 = mustParsePrefixUnmapped("192.168.0.1/25")
	c, _, _, _ := NewTestCert(Version3, Curve_CURVE25519, ca, caKey, "test", time.Now(), time.Now().Add(5*time.Minute), []netip.Prefix{cIp1, cIp2}, nil, []string{"test"})
	_, err = caPool.VerifyCertificate(time.Now(), c)
	require.NoError(t, err)

	// Exact matches
	c, _, _, _ = NewTestCert(Version3, Curve_CURVE25519, ca, caKey, "test", time.Now(), time.Now().Add(5*time.Minute), []netip.Prefix{caIp1, caIp2}, nil, []string{"test"})
	require.NoError(t, err)
	_, err = caPool.VerifyCertificate(time.Now(), c)
	require.NoError(t, err)

	// Exact matches reversed
	c, _, _, _ = NewTestCert(Version3, Curve_CURVE25519, ca, caKey, "test", time.Now(), time.Now().Add(5*time.Minute), []netip.Prefix{caIp2, caIp1}, nil, []string{"test"})
	require.NoError(t, err)
	_, err = caPool.VerifyCertificate(time.Now(), c)
	require.NoError(t, err)

	// Exact matches reversed with just 1
	c, _, _, _ = NewTestCert(Version3, Curve_CURVE25519, ca, caKey, "test", time.Now(), time.Now().Add(5*time.Minute), []netip.Prefix{caIp1}, nil, []string{"test"})
	require.NoError(t, err)
	_, err = caPool.VerifyCertificate(time.Now(), c)
	require.NoError(t, err)
}

func TestCertificateV3_Verify_Subnets(t *testing.T) {
	caIp1 := mustParsePrefixUnmapped("10.0.0.0/16")
	caIp2 := mustParsePrefixUnmapped("192.168.0.0/24")
	ca, _, caKey, _ := NewTestCaCert(Version3, Curve_CURVE25519, time.Now(), time.Now().Add(10*time.Minute), nil, []netip.Prefix{caIp1, caIp2}, []string{"test"})

	caPem, err := ca.MarshalPEM()
	require.NoError(t, err)

	caPool := NewCAPool()
	b, err := caPool.AddCAFromPEM(caPem)
	require.NoError(t, err)
	assert.Empty(t, b)

	// ip is outside the network
	cIp1 := mustParsePrefixUnmapped("10.1.0.0/24")
	cIp2 := mustParsePrefixUnmapped("192.168.0.1/16")
	assert.PanicsWithError(t, "certificate contained an unsafe network assignment outside the limitations of the signing ca: 10.1.0.0/24", func() {
		NewTestCert(Version3, Curve_CURVE25519, ca, caKey, "test", time.Now(), time.Now().Add(5*time.Minute), nil, []netip.Prefix{cIp1, cIp2}, []string{"test"})
	})

	// ip is outside the network reversed order of above
	cIp1 = mustParsePrefixUnmapped("192.168.0.1/24")
	cIp2 = mustParsePrefixUnmapped("10.1.0.0/24")
	assert.PanicsWithError(t, "certificate contained an unsafe network assignment outside the limitations of the signing ca: 10.1.0.0/24", func() {
		NewTestCert(Version3, Curve_CURVE25519, ca, caKey, "test", time.Now(), time.Now().Add(5*time.Minute), nil, []netip.Prefix{cIp1, cIp2}, []string{"test"})
	})

	// ip is within the network but mask is outside
	cIp1 = mustParsePrefixUnmapped("10.0.1.0/15")
	cIp2 = mustParsePrefixUnmapped("192.168.0.1/24")
	assert.PanicsWithError(t, "certificate contained an unsafe network assignment outside the limitations of the signing ca: 10.0.1.0/15", func() {
		NewTestCert(Version3, Curve_CURVE25519, ca, caKey, "test", time.Now(), time.Now().Add(5*time.Minute), nil, []netip.Prefix{cIp1, cIp2}, []string{"test"})
	})

	// ip is within the network but mask is outside reversed order of above
	cIp1 = mustParsePrefixUnmapped("192.168.0.1/24")
	cIp2 = mustParsePrefixUnmapped("10.0.1.0/15")
	assert.PanicsWithError(t, "certificate contained an unsafe network assignment outside the limitations of the signing ca: 10.0.1.0/15", func() {
		NewTestCert(Version3, Curve_CURVE25519, ca, caKey, "test", time.Now(), time.Now().Add(5*time.Minute), nil, []netip.Prefix{cIp1, cIp2}, []string{"test"})
	})

	// ip and mask are within the network
	cIp1 = mustParsePrefixUnmapped("10.0.1.0/16")
	cIp2 = mustParsePrefixUnmapped("192.168.0.1/25")
	c, _, _, _ := NewTestCert(Version3, Curve_CURVE25519, ca, caKey, "test", time.Now(), time.Now().Add(5*time.Minute), nil, []netip.Prefix{cIp1, cIp2}, []string{"test"})
	require.NoError(t, err)
	_, err = caPool.VerifyCertificate(time.Now(), c)
	require.NoError(t, err)

	// Exact matches
	c, _, _, _ = NewTestCert(Version3, Curve_CURVE25519, ca, caKey, "test", time.Now(), time.Now().Add(5*time.Minute), nil, []netip.Prefix{caIp1, caIp2}, []string{"test"})
	require.NoError(t, err)
	_, err = caPool.VerifyCertificate(time.Now(), c)
	require.NoError(t, err)

	// Exact matches reversed
	c, _, _, _ = NewTestCert(Version3, Curve_CURVE25519, ca, caKey, "test", time.Now(), time.Now().Add(5*time.Minute), nil, []netip.Prefix{caIp2, caIp1}, []string{"test"})
	require.NoError(t, err)
	_, err = caPool.VerifyCertificate(time.Now(), c)
	require.NoError(t, err)

	// Exact matches reversed with just 1
	c, _, _, _ = NewTestCert(Version3, Curve_CURVE25519, ca, caKey, "test", time.Now(), time.Now().Add(5*time.Minute), nil, []netip.Prefix{caIp1}, []string{"test"})
	require.NoError(t, err)
	_, err = caPool.VerifyCertificate(time.Now(), c)
	require.NoError(t, err)
}

func TestCertificateV3_CurveMismatch(t *testing.T) {
	caIp1 := mustParsePrefixUnmapped("10.0.0.0/16")
	caIp2 := mustParsePrefixUnmapped("192.168.0.0/24")
	ca, _, caKey, _ := NewTestCaCert(Version3, Curve_P256, time.Now(), time.Now().Add(10*time.Minute), []netip.Prefix{caIp1, caIp2}, nil, []string{"test"})

	caPem, err := ca.MarshalPEM()
	require.NoError(t, err)

	caPool := NewCAPool()
	b, err := caPool.AddCAFromPEM(caPem)
	require.NoError(t, err)
	assert.Empty(t, b)

	// ip is outside the network
	cIp1 := mustParsePrefixUnmapped("10.0.0.1/24")
	c, _, _, _ := NewTestCert(Version3, Curve_P256, ca, caKey, "test", time.Now(), time.Now().Add(5*time.Minute), []netip.Prefix{cIp1}, nil, []string{"test"})

	fp, _ := c.Fingerprint()
	_, err = caPool.verify(c, time.Now(), fp, c.Issuer())
	require.NoError(t, err)
	//
	c2 := c.(*certificateV3)
	c2.curve = Curve_CURVE25519
	fp, _ = c.Fingerprint()
	_, err = caPool.verify(c, time.Now(), fp, c.Issuer())
	require.Error(t, err)
}
