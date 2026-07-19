package cert

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/netip"
	"slices"
	"time"

	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"
)

type certificateV3 struct {
	details detailsV3

	rawDetails   []byte
	curve        Curve
	publicKey    []byte
	hpkePublicKey []byte
	signature    []byte
}

type detailsV3 struct {
	name           string
	networks       []netip.Prefix
	unsafeNetworks []netip.Prefix
	groups         []string
	isCA           bool
	notBefore      time.Time
	notAfter       time.Time
	issuer         string
}

const (
	// v3 ASN.1 tags extend v2 with an HPKE public key
	TagCertHPKEPublicKey = 4 | classContextSpecific
)

func (c *certificateV3) Version() Version { return Version3 }

func (c *certificateV3) Curve() Curve           { return c.curve }
func (c *certificateV3) Groups() []string       { return c.details.groups }
func (c *certificateV3) IsCA() bool             { return c.details.isCA }
func (c *certificateV3) Issuer() string         { return c.details.issuer }
func (c *certificateV3) Name() string           { return c.details.name }
func (c *certificateV3) Networks() []netip.Prefix  { return c.details.networks }
func (c *certificateV3) NotAfter() time.Time    { return c.details.notAfter }
func (c *certificateV3) NotBefore() time.Time   { return c.details.notBefore }
func (c *certificateV3) PublicKey() []byte      { return c.publicKey }
func (c *certificateV3) Signature() []byte      { return c.signature }
func (c *certificateV3) UnsafeNetworks() []netip.Prefix { return c.details.unsafeNetworks }

func (c *certificateV3) HPKEPublicKey() []byte { return c.hpkePublicKey }

func (c *certificateV3) MarshalPublicKeyPEM() []byte {
	return marshalCertPublicKeyToPEM(c)
}

func (c *certificateV3) Fingerprint() (string, error) {
	if len(c.rawDetails) == 0 {
		return "", ErrMissingDetails
	}
	b := make([]byte, 0, len(c.rawDetails)+1+len(c.publicKey)+2+len(c.hpkePublicKey)+len(c.signature))
	b = append(b, c.rawDetails...)
	b = append(b, byte(c.curve))
	b = append(b, c.publicKey...)
	hpkeLen := len(c.hpkePublicKey)
	b = append(b, byte(hpkeLen>>8), byte(hpkeLen))
	b = append(b, c.hpkePublicKey...)
	b = append(b, c.signature...)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

func (c *certificateV3) CheckSignature(key []byte) bool {
	if len(c.rawDetails) == 0 {
		return false
	}
	b := make([]byte, 0, len(c.rawDetails)+1+len(c.publicKey)+2+len(c.hpkePublicKey))
	b = append(b, c.rawDetails...)
	b = append(b, byte(c.curve))
	b = append(b, c.publicKey...)
	hpkeLen := len(c.hpkePublicKey)
	b = append(b, byte(hpkeLen>>8), byte(hpkeLen))
	b = append(b, c.hpkePublicKey...)

	switch c.curve {
	case Curve_CURVE25519:
		if len(key) != ed25519.PublicKeySize {
			return false
		}
		return ed25519.Verify(key, b, c.signature)
	case Curve_P256:
		pubKey, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), key)
		if err != nil {
			return false
		}
		hashed := sha256.Sum256(b)
		return ecdsa.VerifyASN1(pubKey, hashed[:], c.signature)
	default:
		return false
	}
}

func (c *certificateV3) Expired(t time.Time) bool {
	return c.details.notBefore.After(t) || c.details.notAfter.Before(t)
}

func (c *certificateV3) VerifyPrivateKey(curve Curve, key []byte) error {
	if curve != c.curve {
		return ErrPublicPrivateCurveMismatch
	}
	switch curve {
	case Curve_CURVE25519:
		if len(key) != ed25519.PrivateKeySize {
			return ErrInvalidPrivateKey
		}
		if !ed25519.PublicKey(c.publicKey).Equal(ed25519.PrivateKey(key).Public()) {
			return ErrPublicPrivateKeyMismatch
		}
	case Curve_P256:
		privKey, err := ecdh.P256().NewPrivateKey(key)
		if err != nil {
			return ErrInvalidPrivateKey
		}
		pub := privKey.PublicKey().Bytes()
		if !bytes.Equal(pub, c.publicKey) {
			return ErrPublicPrivateKeyMismatch
		}
	default:
		return fmt.Errorf("invalid curve: %s", curve)
	}
	return nil
}

func (c *certificateV3) String() string {
	mb, err := c.marshalJSON()
	if err != nil {
		return fmt.Sprintf("<error marshalling certificate: %v>", err)
	}
	b, err := json.MarshalIndent(mb, "", "\t")
	if err != nil {
		return fmt.Sprintf("<error marshalling certificate: %v>", err)
	}
	return string(b)
}

func (c *certificateV3) MarshalForHandshakes() ([]byte, error) {
	if c.rawDetails == nil {
		return nil, ErrEmptyRawDetails
	}
	var b cryptobyte.Builder
	b.AddASN1(asn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddBytes(c.rawDetails)
		if c.curve != Curve_CURVE25519 {
			b.AddASN1(TagCertCurve, func(b *cryptobyte.Builder) {
				b.AddBytes([]byte{byte(c.curve)})
			})
		}
		if c.publicKey != nil {
			b.AddASN1(TagCertPublicKey, func(b *cryptobyte.Builder) {
				b.AddBytes(c.publicKey)
			})
		}
		if c.hpkePublicKey != nil {
			b.AddASN1(TagCertHPKEPublicKey, func(b *cryptobyte.Builder) {
				b.AddBytes(c.hpkePublicKey)
			})
		}
		b.AddASN1(TagCertSignature, func(b *cryptobyte.Builder) {
			b.AddBytes(c.signature)
		})
	})
	return b.Bytes()
}

func (c *certificateV3) Marshal() ([]byte, error) {
	if c.rawDetails == nil {
		return nil, ErrEmptyRawDetails
	}
	var b cryptobyte.Builder
	b.AddASN1(asn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddBytes(c.rawDetails)
		if c.curve != Curve_CURVE25519 {
			b.AddASN1(TagCertCurve, func(b *cryptobyte.Builder) {
				b.AddBytes([]byte{byte(c.curve)})
			})
		}
		if c.publicKey != nil {
			b.AddASN1(TagCertPublicKey, func(b *cryptobyte.Builder) {
				b.AddBytes(c.publicKey)
			})
		}
		if c.hpkePublicKey != nil {
			b.AddASN1(TagCertHPKEPublicKey, func(b *cryptobyte.Builder) {
				b.AddBytes(c.hpkePublicKey)
			})
		}
		b.AddASN1(TagCertSignature, func(b *cryptobyte.Builder) {
			b.AddBytes(c.signature)
		})
	})
	return b.Bytes()
}

func (c *certificateV3) MarshalPEM() ([]byte, error) {
	b, err := c.Marshal()
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: CertificateV3Banner, Bytes: b}), nil
}

func (c *certificateV3) MarshalJSON() ([]byte, error) {
	b, err := c.marshalJSON()
	if err != nil {
		return nil, err
	}
	return json.Marshal(b)
}

func (c *certificateV3) marshalJSON() (m, error) {
	fp, err := c.Fingerprint()
	if err != nil {
		return nil, err
	}
	return m{
		"details": m{
			"name":           c.details.name,
			"networks":       c.details.networks,
			"unsafeNetworks": c.details.unsafeNetworks,
			"groups":         c.details.groups,
			"notBefore":      c.details.notBefore,
			"notAfter":       c.details.notAfter,
			"isCa":           c.details.isCA,
			"issuer":         c.details.issuer,
		},
		"version":       Version3,
		"publicKey":     fmt.Sprintf("%x", c.publicKey),
		"hpkePublicKey": fmt.Sprintf("%x", c.hpkePublicKey),
		"curve":         c.curve.String(),
		"fingerprint":   fp,
		"signature":     fmt.Sprintf("%x", c.Signature()),
	}, nil
}

func (c *certificateV3) Copy() Certificate {
	nc := &certificateV3{
		details: detailsV3{
			name:      c.details.name,
			notBefore: c.details.notBefore,
			notAfter:  c.details.notAfter,
			isCA:      c.details.isCA,
			issuer:    c.details.issuer,
		},
		curve:        c.curve,
		publicKey:    make([]byte, len(c.publicKey)),
		hpkePublicKey: make([]byte, len(c.hpkePublicKey)),
		signature:    make([]byte, len(c.signature)),
		rawDetails:   make([]byte, len(c.rawDetails)),
	}
	if c.details.groups != nil {
		nc.details.groups = make([]string, len(c.details.groups))
		copy(nc.details.groups, c.details.groups)
	}
	if c.details.networks != nil {
		nc.details.networks = make([]netip.Prefix, len(c.details.networks))
		copy(nc.details.networks, c.details.networks)
	}
	if c.details.unsafeNetworks != nil {
		nc.details.unsafeNetworks = make([]netip.Prefix, len(c.details.unsafeNetworks))
		copy(nc.details.unsafeNetworks, c.details.unsafeNetworks)
	}
	copy(nc.rawDetails, c.rawDetails)
	copy(nc.signature, c.signature)
	copy(nc.publicKey, c.publicKey)
	copy(nc.hpkePublicKey, c.hpkePublicKey)
	return nc
}

func (c *certificateV3) fromTBSCertificate(t *TBSCertificate) error {
	c.details = detailsV3{
		name:           t.Name,
		networks:       t.Networks,
		unsafeNetworks: t.UnsafeNetworks,
		groups:         t.Groups,
		isCA:           t.IsCA,
		notBefore:      t.NotBefore,
		notAfter:       t.NotAfter,
		issuer:         t.issuer,
	}
	c.curve = t.Curve
	c.publicKey = t.PublicKey
	c.hpkePublicKey = t.HPKEPublicKey
	return c.validate()
}

func (c *certificateV3) validate() error {
	if len(c.publicKey) == 0 {
		return ErrInvalidPublicKey
	}
	if !c.details.isCA && len(c.details.networks) == 0 {
		return NewErrInvalidCertificateProperties("non-CA certificate must contain at least 1 network")
	}

	hasV4Networks := false
	hasV6Networks := false
	for _, network := range c.details.networks {
		if !network.IsValid() || !network.Addr().IsValid() {
			return NewErrInvalidCertificateProperties("invalid network: %s", network)
		}
		if network.Addr().IsUnspecified() {
			return NewErrInvalidCertificateProperties("non-CA certificates must not use the zero address as a network: %s", network)
		}
		if network.Addr().Zone() != "" {
			return NewErrInvalidCertificateProperties("networks may not contain zones: %s", network)
		}
		if network.Addr().Is4In6() {
			return NewErrInvalidCertificateProperties("4in6 networks are not allowed: %s", network)
		}
		hasV4Networks = hasV4Networks || network.Addr().Is4()
		hasV6Networks = hasV6Networks || network.Addr().Is6()
	}
	slices.SortFunc(c.details.networks, comparePrefix)
	if err := findDuplicatePrefix(c.details.networks); err != nil {
		return err
	}
	for _, network := range c.details.unsafeNetworks {
		if !network.IsValid() || !network.Addr().IsValid() {
			return NewErrInvalidCertificateProperties("invalid unsafe network: %s", network)
		}
		if network.Addr().Zone() != "" {
			return NewErrInvalidCertificateProperties("unsafe networks may not contain zones: %s", network)
		}
		if !c.details.isCA {
			if network.Addr().Is6() && !hasV6Networks {
				return NewErrInvalidCertificateProperties("IPv6 unsafe networks require an IPv6 address assignment: %s", network)
			}
			if network.Addr().Is4() && !hasV4Networks {
				return NewErrInvalidCertificateProperties("IPv4 unsafe networks require an IPv4 address assignment: %s", network)
			}
		}
	}
	slices.SortFunc(c.details.unsafeNetworks, comparePrefix)
	if err := findDuplicatePrefix(c.details.unsafeNetworks); err != nil {
		return err
	}
	return nil
}

func (c *certificateV3) marshalForSigning() ([]byte, error) {
	d, err := c.details.Marshal()
	if err != nil {
		return nil, fmt.Errorf("marshalling certificate details failed: %w", err)
	}
	c.rawDetails = d

	b := make([]byte, 0, len(c.rawDetails)+1+len(c.publicKey)+2+len(c.hpkePublicKey))
	b = append(b, c.rawDetails...)
	b = append(b, byte(c.curve))
	b = append(b, c.publicKey...)
	hpkeLen := len(c.hpkePublicKey)
	b = append(b, byte(hpkeLen>>8), byte(hpkeLen))
	b = append(b, c.hpkePublicKey...)
	return b, nil
}

func (c *certificateV3) setSignature(b []byte) error {
	if len(b) == 0 {
		return ErrEmptySignature
	}
	c.signature = b
	return nil
}

func (d *detailsV3) Marshal() ([]byte, error) {
	var b cryptobyte.Builder
	var err error
	b.AddASN1(TagCertDetails, func(b *cryptobyte.Builder) {
		b.AddASN1(TagDetailsName, func(b *cryptobyte.Builder) {
			b.AddBytes([]byte(d.name))
		})
		if len(d.networks) > 0 {
			b.AddASN1(TagDetailsNetworks, func(b *cryptobyte.Builder) {
				for _, n := range d.networks {
					sb, innerErr := n.MarshalBinary()
					if innerErr != nil {
						err = innerErr
						return
					}
					b.AddASN1OctetString(sb)
				}
			})
		}
		if len(d.unsafeNetworks) > 0 {
			b.AddASN1(TagDetailsUnsafeNetworks, func(b *cryptobyte.Builder) {
				for _, n := range d.unsafeNetworks {
					sb, innerErr := n.MarshalBinary()
					if innerErr != nil {
						err = innerErr
						return
					}
					b.AddASN1OctetString(sb)
				}
			})
		}
		if len(d.groups) > 0 {
			b.AddASN1(TagDetailsGroups, func(b *cryptobyte.Builder) {
				for _, group := range d.groups {
					b.AddASN1(asn1.UTF8String, func(b *cryptobyte.Builder) {
						b.AddBytes([]byte(group))
					})
				}
			})
		}
		if d.isCA {
			b.AddASN1(TagDetailsIsCA, func(b *cryptobyte.Builder) {
				b.AddUint8(0xff)
			})
		}
		b.AddASN1Int64WithTag(d.notBefore.Unix(), TagDetailsNotBefore)
		b.AddASN1Int64WithTag(d.notAfter.Unix(), TagDetailsNotAfter)
		if d.issuer != "" {
			issuerBytes, innerErr := hex.DecodeString(d.issuer)
			if innerErr != nil {
				err = innerErr
				return
			}
			b.AddASN1(TagDetailsIssuer, func(b *cryptobyte.Builder) {
				b.AddBytes(issuerBytes)
			})
		}
	})
	if err != nil {
		return nil, err
	}
	return b.Bytes()
}

func unmarshalCertificateV3(b []byte, publicKey []byte, curve Curve) (*certificateV3, error) {
	l := len(b)
	if l == 0 || l > MaxCertificateSize {
		return nil, ErrBadFormat
	}

	input := cryptobyte.String(b)
	if !input.ReadASN1(&input, asn1.SEQUENCE) || input.Empty() {
		return nil, ErrBadFormat
	}

	var rawDetails cryptobyte.String
	if !input.ReadASN1Element(&rawDetails, TagCertDetails) || rawDetails.Empty() {
		return nil, ErrBadFormat
	}

	var rawCurve byte
	if !readOptionalASN1Byte(&input, &rawCurve, TagCertCurve, byte(curve)) {
		return nil, ErrBadFormat
	}
	curve = Curve(rawCurve)

	var rawPublicKey cryptobyte.String
	if len(publicKey) > 0 {
		if input.PeekASN1Tag(TagCertPublicKey) {
			return nil, ErrCertPubkeyPresent
		}
		rawPublicKey = make(cryptobyte.String, len(publicKey))
		copy(rawPublicKey, publicKey)
	} else if !input.ReadOptionalASN1(&rawPublicKey, nil, TagCertPublicKey) {
		return nil, ErrBadFormat
	}
	if len(rawPublicKey) == 0 {
		return nil, ErrBadFormat
	}

	var rawHPKEPublicKey cryptobyte.String
	input.ReadOptionalASN1(&rawHPKEPublicKey, nil, TagCertHPKEPublicKey)

	var rawSignature cryptobyte.String
	if !input.ReadASN1(&rawSignature, TagCertSignature) || rawSignature.Empty() {
		return nil, ErrBadFormat
	}

	details, err := unmarshalDetailsV3(rawDetails)
	if err != nil {
		return nil, err
	}

	c := &certificateV3{
		details:        details,
		rawDetails:     rawDetails,
		curve:          curve,
		publicKey:      rawPublicKey,
		hpkePublicKey:  rawHPKEPublicKey,
		signature:      rawSignature,
	}
	if err = c.validate(); err != nil {
		return nil, err
	}
	return c, nil
}

func unmarshalDetailsV3(b cryptobyte.String) (detailsV3, error) {
	if !b.ReadASN1(&b, TagCertDetails) || b.Empty() {
		return detailsV3{}, ErrBadFormat
	}

	var name cryptobyte.String
	if !b.ReadASN1(&name, TagDetailsName) || name.Empty() || len(name) > MaxNameLength {
		return detailsV3{}, ErrBadFormat
	}

	var subString cryptobyte.String
	var found bool

	if !b.ReadOptionalASN1(&subString, &found, TagDetailsNetworks) {
		return detailsV3{}, ErrBadFormat
	}
	var networks []netip.Prefix
	var val cryptobyte.String
	if found {
		for !subString.Empty() {
			if !subString.ReadASN1(&val, asn1.OCTET_STRING) || val.Empty() || len(val) > MaxNetworkLength {
				return detailsV3{}, ErrBadFormat
			}
			var n netip.Prefix
			if err := n.UnmarshalBinary(val); err != nil {
				return detailsV3{}, ErrBadFormat
			}
			networks = append(networks, n)
		}
	}

	if !b.ReadOptionalASN1(&subString, &found, TagDetailsUnsafeNetworks) {
		return detailsV3{}, ErrBadFormat
	}
	var unsafeNetworks []netip.Prefix
	if found {
		for !subString.Empty() {
			if !subString.ReadASN1(&val, asn1.OCTET_STRING) || val.Empty() || len(val) > MaxNetworkLength {
				return detailsV3{}, ErrBadFormat
			}
			var n netip.Prefix
			if err := n.UnmarshalBinary(val); err != nil {
				return detailsV3{}, ErrBadFormat
			}
			unsafeNetworks = append(unsafeNetworks, n)
		}
	}

	if !b.ReadOptionalASN1(&subString, &found, TagDetailsGroups) {
		return detailsV3{}, ErrBadFormat
	}
	var groups []string
	if found {
		for !subString.Empty() {
			if !subString.ReadASN1(&val, asn1.UTF8String) || val.Empty() {
				return detailsV3{}, ErrBadFormat
			}
			groups = append(groups, string(val))
		}
	}

	var isCa bool
	if !readOptionalASN1Boolean(&b, &isCa, TagDetailsIsCA, false) {
		return detailsV3{}, ErrBadFormat
	}

	var notBefore int64
	if !b.ReadASN1Int64WithTag(&notBefore, TagDetailsNotBefore) {
		return detailsV3{}, ErrBadFormat
	}
	var notAfter int64
	if !b.ReadASN1Int64WithTag(&notAfter, TagDetailsNotAfter) {
		return detailsV3{}, ErrBadFormat
	}

	var issuer cryptobyte.String
	if !b.ReadOptionalASN1(&issuer, nil, TagDetailsIssuer) {
		return detailsV3{}, ErrBadFormat
	}

	return detailsV3{
		name:           string(name),
		networks:       networks,
		unsafeNetworks: unsafeNetworks,
		groups:         groups,
		isCA:           isCa,
		notBefore:      time.Unix(notBefore, 0),
		notAfter:       time.Unix(notAfter, 0),
		issuer:         hex.EncodeToString(issuer),
	}, nil
}

// HPKEPublicKeyer is implemented by certificates that carry an HPKE public key.
type HPKEPublicKeyer interface {
	HPKEPublicKey() []byte
}

const hybridPubKeyLen = 32 + mlkem.EncapsulationKeySize768

func VerifyHPKEPrivateKey(hpkePub, hpkePriv []byte) error {
	switch {
	case len(hpkePub) == 32 && len(hpkePriv) == 32:
		priv, err := ecdh.X25519().NewPrivateKey(hpkePriv)
		if err != nil {
			return ErrInvalidPrivateKey
		}
		pub := priv.PublicKey().Bytes()
		if !bytes.Equal(pub, hpkePub) {
			return ErrPublicPrivateKeyMismatch
		}
		return nil

	case len(hpkePub) == hybridPubKeyLen && len(hpkePriv) == 32+mlkem.SeedSize:
		// Hybrid: private key is [x25519_priv(32)] + [mlkem_seed(SeedSize)]
		priv, err := ecdh.X25519().NewPrivateKey(hpkePriv[:32])
		if err != nil {
			return ErrInvalidPrivateKey
		}
		pub := priv.PublicKey().Bytes()
		if !bytes.Equal(pub, hpkePub[:32]) {
			return ErrPublicPrivateKeyMismatch
		}
		mlkemPriv, err := mlkem.NewDecapsulationKey768(hpkePriv[32:])
		if err != nil {
			return ErrInvalidPrivateKey
		}
		expectedPub := mlkemPriv.EncapsulationKey().Bytes()
		if !bytes.Equal(expectedPub, hpkePub[32:]) {
			return ErrPublicPrivateKeyMismatch
		}
		return nil

	default:
		return ErrInvalidPrivateKey
	}
}

// GenerateHPKEKeyPair generates an HPKE key pair.
// If hybrid is true, generates X25519 + ML-KEM768 hybrid keys.
func GenerateHPKEKeyPair(hybrid bool) (pub, priv []byte, err error) {
	privKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	pubKey := privKey.PublicKey().Bytes()
	if hybrid {
		mlkemSeed := make([]byte, mlkem.SeedSize)
		if _, err := io.ReadFull(rand.Reader, mlkemSeed); err != nil {
			return nil, nil, err
		}
		mlkemPriv, err := mlkem.NewDecapsulationKey768(mlkemSeed)
		if err != nil {
			return nil, nil, err
		}
		mlkemPubBytes := mlkemPriv.EncapsulationKey().Bytes()
		hybridPub := make([]byte, 32+len(mlkemPubBytes))
		copy(hybridPub, pubKey)
		copy(hybridPub[32:], mlkemPubBytes)
		hybridPriv := make([]byte, 32+mlkem.SeedSize)
		copy(hybridPriv, privKey.Bytes())
		copy(hybridPriv[32:], mlkemSeed)
		return hybridPub, hybridPriv, nil
	}
	return pubKey, privKey.Bytes(), nil
}
