package types

import (
	"fmt"

	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/status-im/keycard-go/apdu"
)

var (
	TagExportKeyTemplate = uint8(0xA1)
	TagExportKeyPublic   = uint8(0x81)
)

func ParseExportKeyResponse(data []byte) ([]byte, []byte, error) {
	tpl, err := apdu.FindTag(data, apdu.Tag{0xA1})
	if err != nil {
		return nil, nil, err
	}

	pubKey := tryFindTag(tpl, apdu.Tag{0x80})
	privKey := tryFindTag(tpl, apdu.Tag{0x81})

	if len(pubKey) == 0 && len(privKey) > 0 {
		ecdsaKey, err := ethcrypto.HexToECDSA(fmt.Sprintf("%x", privKey))
		if err != nil {
			return nil, nil, err
		}

		pubKey = ethcrypto.FromECDSAPub(&ecdsaKey.PublicKey)
	}

	return privKey, pubKey, nil
}

func tryFindTag(tpl []byte, tags ...apdu.Tag) []byte {
	data, err := apdu.FindTag(tpl, tags...)
	if err != nil {
		return nil
	}

	return data
}
