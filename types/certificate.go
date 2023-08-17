package types

import (
	"crypto/sha256"
	"errors"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/status-im/keycard-go/apdu"
)

type Certificate struct {
	identPub  []byte
	signature *Signature
}

var (
	TagCertificate = uint8(0x8A)
)

func ParseCertificate(data []byte) (*Certificate, error) {
	if len(data) != 98 {
		return nil, errors.New("certificate must be 98 byte long")
	}

	identPub := data[0:33]
	sigData := data[33:97]
	msg := sha256.Sum256(identPub)

	sig, err := ParseRecoverableSignature(msg[:], sigData)
	if err != nil {
		return nil, err
	}

	return &Certificate{
		identPub:  identPub,
		signature: sig,
	}, nil
}

func VerifyIdentity(challenge []byte, tlvData []byte) ([]byte, error) {
	template, err := apdu.FindTag(tlvData, apdu.Tag{TagSignatureTemplate})
	if err != nil {
		return nil, err
	}

	certData, err := apdu.FindTag(template, apdu.Tag{TagCertificate})
	if err != nil {
		return nil, err
	}

	cert, err := ParseCertificate(certData)
	if err != nil {
		return nil, err
	}

	r, s, err := DERSignatureToRS(template)
	if err != nil {
		return nil, err
	}

	sig := append(r, s...)

	if !crypto.VerifySignature(cert.identPub, challenge, sig) {
		return nil, errors.New("invalid signature")
	}

	return compressPublicKey(cert.signature.pubKey), nil
}

func compressPublicKey(pubKey []byte) []byte {
	if len(pubKey) == 33 {
		return pubKey
	}

	if (pubKey[63] & 1) == 1 {
		pubKey[0] = 3
	} else {
		pubKey[0] = 2
	}

	return pubKey[0:33]
}
