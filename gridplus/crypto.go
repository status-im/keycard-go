package gridplus

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/asn1"
	"errors"
	"math/big"

	"github.com/decred/dcrd/dcrec/secp256k1/v2"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	log "github.com/sirupsen/logrus"
)

var SafecardCertCAPubKey = []byte{
	0x04,
	0x5c, 0xfd, 0xf7, 0x7a, 0x00, 0xb4, 0xb6, 0xb4,
	0xa5, 0xb8, 0xbb, 0x26, 0xb5, 0x49, 0x7d, 0xbc,
	0x7a, 0x4d, 0x01, 0xcb, 0xef, 0xd7, 0xaa, 0xea,
	0xf5, 0xf6, 0xf8, 0xf8, 0x86, 0x59, 0x76, 0xe7,
	0x94, 0x1a, 0xb0, 0xec, 0x16, 0x51, 0x20, 0x9c,
	0x44, 0x40, 0x09, 0xfd, 0x48, 0xd9, 0x25, 0xa1,
	0x7d, 0xe5, 0x04, 0x0b, 0xa4, 0x7e, 0xaf, 0x3f,
	0x5b, 0x51, 0x72, 0x0d, 0xd4, 0x0b, 0x2f, 0x9d,
}

func ValidateCardCertificate(cert SafecardCert) bool {
	//Hash of cert bytes
	certBytes := append(cert.Permissions, cert.PubKey...)
	certHash := sha256.Sum256(certBytes)

	//Components of CA certificate public key
	X := new(big.Int)
	Y := new(big.Int)
	X.SetBytes(SafecardCertCAPubKey[1:33])
	Y.SetBytes(SafecardCertCAPubKey[33:])

	CApubKey := &ecdsa.PublicKey{
		Curve: secp256k1.S256(),
		X:     X,
		Y:     Y,
	}

	type ECDSASignature struct {
		R, S *big.Int
	}
	signature := &ECDSASignature{}
	_, err := asn1.Unmarshal(cert.Sig, signature)
	if err != nil {
		log.Error("could not unmarshal certificate signature.", err)
	}

	log.Debugf("certHash: % X", certHash)

	return ecdsa.Verify(CApubKey, certHash[0:], signature.R, signature.S)
}

func SerializePubKey(pubKey ecdsa.PublicKey) []byte {
	var ECC_POINT_FORMAT_UNCOMPRESSED byte = 0x04
	pubKeyBytes := []byte{ECC_POINT_FORMAT_UNCOMPRESSED}
	pubKeyBytes = append(pubKeyBytes, pubKey.X.Bytes()...)
	pubKeyBytes = append(pubKeyBytes, pubKey.Y.Bytes()...)

	return pubKeyBytes
}

func ValidateECCPubKey(pubKey *ecdsa.PublicKey) bool {
	if !pubKey.IsOnCurve(pubKey.X, pubKey.Y) {
		log.Error("pubkey is not valid point on curve")
		return false
	}

	//TODO: more checks for point is not at infinity, not sure if these are needed
	return true
}

func ParseCertPubkeyToECDSA(cert []byte) (*ecdsa.PublicKey, error) {
	//check length to avoid panics if cert is malformed
	if len(cert) < 67 {
		return nil, errors.New("certificate invalid length")
	}
	//Offset start of pubkey by 3 for 2 byte TLV header + DER type byte
	pubKey := &ecdsa.PublicKey{
		Curve: ethcrypto.S256(),
		X:     new(big.Int).SetBytes(cert[3:35]),
		Y:     new(big.Int).SetBytes(cert[35:67]),
	}
	return pubKey, nil
}
