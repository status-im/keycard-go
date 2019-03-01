package lightwallet

import (
	"github.com/status-im/keycard-go/apdu"
	"github.com/status-im/keycard-go/globalplatform"
)

const (
	InsInit                 = uint8(0xFE)
	InsOpenSecureChannel    = uint8(0x10)
	InsMutuallyAuthenticate = uint8(0x11)
	InsPair                 = uint8(0x12)
	InsGetStatus            = uint8(0xF2)

	TagSelectResponsePreInitialized = uint8(0x80)
	TagApplicationStatusTemplate    = uint8(0xA3)
	TagApplicationInfoTemplate      = uint8(0xA4)

	P1PairingFirstStep     = uint8(0x00)
	P1PairingFinalStep     = uint8(0x01)
	P1GetStatusApplication = uint8(0x00)
	P1GetStatusKeyPath     = uint8(0x01)
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

func NewCommandMutuallyAuthenticate(data []byte) *apdu.Command {
	return apdu.NewCommand(
		globalplatform.ClaGp,
		InsMutuallyAuthenticate,
		uint8(0x00),
		uint8(0x00),
		data,
	)
}

func NewCommandGetStatus(p1 uint8) *apdu.Command {
	return apdu.NewCommand(
		globalplatform.ClaGp,
		InsGetStatus,
		p1,
		uint8(0x00),
		[]byte{},
	)
}

func NewCommandGetStatusApplication() *apdu.Command {
	return NewCommandGetStatus(P1GetStatusApplication)
}

func NewCommandGetStatusKeyPath() *apdu.Command {
	return NewCommandGetStatus(P1GetStatusKeyPath)
}
