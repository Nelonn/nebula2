package hpke

import (
	"crypto/mlkem"
	"fmt"
)

const (
	HybridPubKeyLen  = X25519PK + mlkem.EncapsulationKeySize768
	HybridPrivKeyLen = X25519PK + mlkem.SeedSize
	HybridSSLens     = X25519PK + mlkem.SharedKeySize
	HybridEncLen     = X25519PK + mlkem.CiphertextSize768
)

type hybridKEMX25519MLKEM768 struct{}

var HybridKEM_X25519_MLKEM768 KEM = &hybridKEMX25519MLKEM768{}

func (*hybridKEMX25519MLKEM768) ID() uint16 { return KEMID_Hybrid_X25519_MLKEM768 }

func (*hybridKEMX25519MLKEM768) PublicKeyLen() int    { return HybridPubKeyLen }
func (*hybridKEMX25519MLKEM768) PrivateKeyLen() int   { return HybridPrivKeyLen }
func (*hybridKEMX25519MLKEM768) SharedSecretLen() int { return HybridSSLens }
func (*hybridKEMX25519MLKEM768) EncLen() int          { return HybridEncLen }

func (*hybridKEMX25519MLKEM768) GenerateKeyPair() ([]byte, []byte, error) {
	dhPub, dhPriv, err := DHKEM_X25519.GenerateKeyPair()
	if err != nil {
		return nil, nil, err
	}
	mlkemPriv, err := mlkem.GenerateKey768()
	if err != nil {
		return nil, nil, err
	}
	mlkemPub := mlkemPriv.EncapsulationKey()
	pub := make([]byte, HybridPubKeyLen)
	copy(pub, dhPub)
	copy(pub[X25519PK:], mlkemPub.Bytes())
	priv := make([]byte, HybridPrivKeyLen)
	copy(priv, dhPriv)
	copy(priv[X25519PK:], mlkemPriv.Bytes())
	return pub, priv, nil
}

func (*hybridKEMX25519MLKEM768) Encap(pkR []byte) ([]byte, []byte, error) {
	if len(pkR) != HybridPubKeyLen {
		return nil, nil, fmt.Errorf("hpke: invalid hybrid public key length %d", len(pkR))
	}
	dhSS, dhEnc, err := DHKEM_X25519.Encap(pkR[:X25519PK])
	if err != nil {
		return nil, nil, err
	}
	mlkemPub, err := mlkem.NewEncapsulationKey768(pkR[X25519PK:])
	if err != nil {
		return nil, nil, err
	}
	mlkemSS, mlkemCt := mlkemPub.Encapsulate()
	ss := make([]byte, 0, HybridSSLens)
	ss = append(ss, dhSS...)
	ss = append(ss, mlkemSS...)
	enc := make([]byte, 0, HybridEncLen)
	enc = append(enc, dhEnc...)
	enc = append(enc, mlkemCt...)
	return ss, enc, nil
}

func (*hybridKEMX25519MLKEM768) Decap(enc, skR []byte) ([]byte, error) {
	if len(enc) != HybridEncLen {
		return nil, fmt.Errorf("hpke: invalid hybrid enc length %d", len(enc))
	}
	if len(skR) != HybridPrivKeyLen {
		return nil, fmt.Errorf("hpke: invalid hybrid private key length %d", len(skR))
	}
	dhSS, err := DHKEM_X25519.Decap(enc[:X25519PK], skR[:X25519PK])
	if err != nil {
		return nil, err
	}
	mlkemPriv, err := mlkem.NewDecapsulationKey768(skR[X25519PK:])
	if err != nil {
		return nil, err
	}
	mlkemSS, err := mlkemPriv.Decapsulate(enc[X25519PK:])
	if err != nil {
		return nil, err
	}
	ss := make([]byte, 0, HybridSSLens)
	ss = append(ss, dhSS...)
	ss = append(ss, mlkemSS...)
	return ss, nil
}

func (*hybridKEMX25519MLKEM768) AuthEncap(pkR []byte, skS []byte) ([]byte, []byte, error) {
	if len(pkR) != HybridPubKeyLen {
		return nil, nil, fmt.Errorf("hpke: invalid hybrid public key length %d", len(pkR))
	}
	if len(skS) != HybridPrivKeyLen {
		return nil, nil, fmt.Errorf("hpke: invalid hybrid private key length %d", len(skS))
	}
	dhSS, dhEnc, err := DHKEM_X25519.AuthEncap(pkR[:X25519PK], skS[:X25519PK])
	if err != nil {
		return nil, nil, err
	}
	mlkemPub, err := mlkem.NewEncapsulationKey768(pkR[X25519PK:])
	if err != nil {
		return nil, nil, err
	}
	mlkemSS, mlkemCt := mlkemPub.Encapsulate()
	ss := make([]byte, 0, HybridSSLens)
	ss = append(ss, dhSS...)
	ss = append(ss, mlkemSS...)
	enc := make([]byte, 0, HybridEncLen)
	enc = append(enc, dhEnc...)
	enc = append(enc, mlkemCt...)
	return ss, enc, nil
}

func (*hybridKEMX25519MLKEM768) AuthDecap(enc, skR, pkS []byte) ([]byte, error) {
	if len(enc) != HybridEncLen {
		return nil, fmt.Errorf("hpke: invalid hybrid enc length %d", len(enc))
	}
	if len(skR) != HybridPrivKeyLen {
		return nil, fmt.Errorf("hpke: invalid hybrid private key length %d", len(skR))
	}
	if len(pkS) < X25519PK {
		return nil, fmt.Errorf("hpke: invalid hybrid sender public key length %d", len(pkS))
	}
	dhSS, err := DHKEM_X25519.AuthDecap(enc[:X25519PK], skR[:X25519PK], pkS[:X25519PK])
	if err != nil {
		return nil, err
	}
	mlkemPriv, err := mlkem.NewDecapsulationKey768(skR[X25519PK:])
	if err != nil {
		return nil, err
	}
	mlkemSS, err := mlkemPriv.Decapsulate(enc[X25519PK:])
	if err != nil {
		return nil, err
	}
	ss := make([]byte, 0, HybridSSLens)
	ss = append(ss, dhSS...)
	ss = append(ss, mlkemSS...)
	return ss, nil
}
