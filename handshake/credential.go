package handshake

import (
	"github.com/flynn/noise"
	"github.com/slackhq/nebula/cert"
	"github.com/slackhq/nebula/hpke"
)

type Credential struct {
	Cert        cert.Certificate
	Bytes       []byte
	hpkePriv    []byte
	HPKEPub     []byte
	CipherSuite noise.CipherSuite
	HPKESuite   *hpke.HPKESuite
}

func (c *Credential) GetHPKEPriv() []byte { return c.hpkePriv }

func NewCredential(
	c cert.Certificate,
	hsBytes []byte,
	hpkePriv []byte,
	hpkePub []byte,
	cipherSuite noise.CipherSuite,
	hpkeSuite *hpke.HPKESuite,
) *Credential {
	return &Credential{
		Cert:        c,
		Bytes:       hsBytes,
		hpkePriv:    hpkePriv,
		HPKEPub:     hpkePub,
		CipherSuite: cipherSuite,
		HPKESuite:   hpkeSuite,
	}
}

type GetCredentialFunc func(v cert.Version) *Credential
