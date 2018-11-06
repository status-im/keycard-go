package lightwallet

import (
	"github.com/status-im/hardware-wallet-go/apdu"
	"github.com/status-im/hardware-wallet-go/globalplatform"
)

const (
	InsInit              = uint8(0xFE)
	InsOpenSecureChannel = uint8(0x10)
	InsPair              = uint8(0x12)

	TagSelectResponsePreInitialized = uint8(0x80)
	TagApplicationInfoTemplate      = uint8(0xA4)

	P1PairingFirstStep = uint8(0x00)
	P1PairingFinalStep = uint8(0x01)
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

func NewCommandPairFirstStep(challenge []byte) *apdu.Command {
	return apdu.NewCommand(
		globalplatform.ClaGp,
		InsPair,
		P1PairingFirstStep,
		uint8(0x00),
		challenge,
	)
}

func NewCommandPairFinalStep(cryptogramHash []byte) *apdu.Command {
	return apdu.NewCommand(
		globalplatform.ClaGp,
		InsPair,
		P1PairingFinalStep,
		uint8(0x00),
		cryptogramHash,
	)
}

func NewCommandOpenSecureChannel(pairingIndex uint8, pubKey []byte) *apdu.Command {
	return apdu.NewCommand(
		globalplatform.ClaGp,
		InsOpenSecureChannel,
		pairingIndex,
		uint8(0x00),
		pubKey,
	)
}
