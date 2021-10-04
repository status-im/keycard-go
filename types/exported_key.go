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

	privKey, err := apdu.FindTag(tpl, apdu.Tag{0x81})
	if err != nil {
		return nil, nil, err
	}

	ecdsaKey, err := ethcrypto.HexToECDSA(fmt.Sprintf("%x", privKey))
	if err != nil {
		return nil, nil, err
	}

	return privKey, ethcrypto.FromECDSAPub(&ecdsaKey.PublicKey), nil
}
