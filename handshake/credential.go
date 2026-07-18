package handshake

import (
	"github.com/flynn/noise"
	"github.com/slackhq/nebula/cert"
	"github.com/slackhq/nebula/hpke"
)

type Credential struct {
	Cert       cert.Certificate
	Bytes      []byte
	HPKEPriv   []byte
	HPKEPub    []byte
	CipherSuite noise.CipherSuite
	HPKESuite  *hpke.HPKESuite
}

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
		HPKEPriv:    hpkePriv,
		HPKEPub:     hpkePub,
		CipherSuite: cipherSuite,
		HPKESuite:   hpkeSuite,
	}
}

type GetCredentialFunc func(v cert.Version) *Credential
