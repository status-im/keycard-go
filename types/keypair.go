package types

import (
	"github.com/status-im/keycard-go/apdu"
)

var (
	TagKeyPairTemplate = uint8(0xA1)
)

type KeyPair struct {
	pubKey  []byte
	privKey []byte
}

func ParseKeyPair(resp []byte) (*KeyPair, error) {
	pubKey, err := apdu.FindTag(resp, apdu.Tag{TagKeyPairTemplate}, apdu.Tag{0x80})
	if err != nil {
		pubKey = nil
	}

	privKey, err := apdu.FindTag(resp, apdu.Tag{TagKeyPairTemplate}, apdu.Tag{0x81})
	if err != nil {
		privKey = nil
	}

	return &KeyPair{
		pubKey:  pubKey,
		privKey: privKey,
	}, nil
}

func (kp *KeyPair) PubKey() []byte {
	return kp.pubKey
}

func (kp *KeyPair) PrivKey() []byte {
	return kp.privKey
}
