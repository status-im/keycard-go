package lightwallet

import (
	"github.com/status-im/smartcard-go/apdu"
	"github.com/status-im/smartcard-go/globalplatform"
)

const (
	InsInit = uint8(0xFE)

	tagSelectResponsePreInitialized = uint8(0x80)
)

func NewCommandInit(data []byte) *apdu.Command {
	return apdu.NewCommand(
		globalplatform.ClaGp,
		InsInit,
		uint8(0x00),
		uint8(0x00),
		data,
	)
}
