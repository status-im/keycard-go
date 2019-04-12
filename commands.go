package keycard

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/status-im/keycard-go/apdu"
	"github.com/status-im/keycard-go/derivationpath"
	"github.com/status-im/keycard-go/globalplatform"
)

const (
	InsInit                 = 0xFE
	InsOpenSecureChannel    = 0x10
	InsMutuallyAuthenticate = 0x11
	InsPair                 = 0x12
	InsUnpair               = 0x13
	InsGetStatus            = 0xF2
	InsGenerateKey          = 0xD4
	InsRemoveKey            = 0xD3
	InsVerifyPIN            = 0x20
	InsChangePIN            = 0x21
	InsLoadKey              = 0xD0
	InsDeriveKey            = 0xD1
	InsExportKey            = 0xC2
	InsSign                 = 0xC0
	InsSetPinlessPath       = 0xC1

	P1PairingFirstStep         = 0x00
	P1PairingFinalStep         = 0x01
	P1GetStatusApplication     = 0x00
	P1GetStatusKeyPath         = 0x01
	P1DeriveKeyFromMaster      = 0x00
	P1DeriveKeyFromParent      = 0x01
	P1DeriveKeyFromCurrent     = 0x10
	P1ChangePinPIN             = 0x00
	P1ChangePinPUK             = 0x01
	P1ChangePinPairingSecret   = 0x02
	P1SignCurrentKey           = 0x00
	P1SignDerive               = 0x01
	P1SignDeriveAndMakeCurrent = 0x02
	P1SignPinless              = 0x03

	SwNoAvailablePairingSlots = 0x6A84
)

func NewCommandInit(data []byte) *apdu.Command {
	return apdu.NewCommand(
		globalplatform.ClaGp,
		InsInit,
		0,
		0,
		data,
	)
}

func NewCommandPairFirstStep(challenge []byte) *apdu.Command {
	return apdu.NewCommand(
		globalplatform.ClaGp,
		InsPair,
		P1PairingFirstStep,
		0,
		challenge,
	)
}

func NewCommandPairFinalStep(cryptogramHash []byte) *apdu.Command {
	return apdu.NewCommand(
		globalplatform.ClaGp,
		InsPair,
		P1PairingFinalStep,
		0,
		cryptogramHash,
	)
}

func NewCommandUnpair(index uint8) *apdu.Command {
	return apdu.NewCommand(
		globalplatform.ClaGp,
		InsUnpair,
		index,
		0,
		[]byte{},
	)
}

func NewCommandOpenSecureChannel(pairingIndex uint8, pubKey []byte) *apdu.Command {
	return apdu.NewCommand(
		globalplatform.ClaGp,
		InsOpenSecureChannel,
		pairingIndex,
		0,
		pubKey,
	)
}

func NewCommandMutuallyAuthenticate(data []byte) *apdu.Command {
	return apdu.NewCommand(
		globalplatform.ClaGp,
		InsMutuallyAuthenticate,
		0,
		0,
		data,
	)
}

func NewCommandGetStatus(p1 uint8) *apdu.Command {
	return apdu.NewCommand(
		globalplatform.ClaGp,
		InsGetStatus,
		p1,
		0,
		[]byte{},
	)
}

func NewCommandGenerateKey() *apdu.Command {
	return apdu.NewCommand(
		globalplatform.ClaGp,
		InsGenerateKey,
		0,
		0,
		[]byte{},
	)
}

func NewCommandRemoveKey() *apdu.Command {
	return apdu.NewCommand(
		globalplatform.ClaGp,
		InsRemoveKey,
		0,
		0,
		[]byte{},
	)
}

func NewCommandVerifyPIN(pin string) *apdu.Command {
	return apdu.NewCommand(
		globalplatform.ClaGp,
		InsVerifyPIN,
		0,
		0,
		[]byte(pin),
	)
}

func NewCommandChangePIN(pin string) *apdu.Command {
	return apdu.NewCommand(
		globalplatform.ClaGp,
		InsChangePIN,
		P1ChangePinPIN,
		0,
		[]byte(pin),
	)
}

func NewCommandChangePUK(puk string) *apdu.Command {
	return apdu.NewCommand(
		globalplatform.ClaGp,
		InsChangePIN,
		P1ChangePinPUK,
		0,
		[]byte(puk),
	)
}

func NewCommandChangePairingSecret(secret []byte) *apdu.Command {
	return apdu.NewCommand(
		globalplatform.ClaGp,
		InsChangePIN,
		P1ChangePinPairingSecret,
		0,
		secret,
	)
}

func NewCommandDeriveKey(pathStr string) (*apdu.Command, error) {
	startingPoint, path, err := derivationpath.Decode(pathStr)
	if err != nil {
		return nil, err
	}

	var p1 uint8
	switch startingPoint {
	case derivationpath.StartingPointMaster:
		p1 = P1DeriveKeyFromMaster
	case derivationpath.StartingPointParent:
		p1 = P1DeriveKeyFromParent
	case derivationpath.StartingPointCurrent:
		p1 = P1DeriveKeyFromCurrent
	default:
		return nil, fmt.Errorf("invalid startingPoint %d", startingPoint)
	}

	data := new(bytes.Buffer)
	for _, segment := range path {
		if err := binary.Write(data, binary.BigEndian, segment); err != nil {
			return nil, err
		}
	}

	return apdu.NewCommand(
		globalplatform.ClaGp,
		InsDeriveKey,
		p1,
		0,
		data.Bytes(),
	), nil
}

func NewCommandLoadKey(isSeed bool, data []byte) (*apdu.Command) {
	var p1 uint8
	if isSeed == true {
		p1 = 0x03
	} else {
		// This assumes the user is sending a normal keypair, as opposed
		// to an extended keypair
		// Alex: This is because I've never heard of an "extended keypair"
		//		Seeking clarification from Status
		p1 = 0x01
	}
	return apdu.NewCommand(
		globalplatform.ClaGp,
		InsLoadKey,
		p1,
		0,
		data,
	)
}

// Export a key
//	@param {p1}
//		0x00: current key - returns the key that is currently loaded and ready for signing. Does not use derivation path
//		0x01: derive - returns derived key
//		0x02: derive and make current - returns derived key and also sets it to the current key
//  @param {p2}
//		0x00: return public and private key pair
//		0x01: return only the public key
//  @param {pathStr}
//		Derivation path of format "m/x/x/x/x/x", e.g. "m/44'/0'/0'/0/0"
func NewCommandExportKey(p1 uint8, p2 uint8, pathStr string) (*apdu.Command, error) {
	
	// Choose to derive based on the value of p1
	data := new(bytes.Buffer)
	if (p1 == 0x01 || p1 == 0x02) {
		_, path, err := derivationpath.Decode(pathStr)
		if err != nil {
			return nil, err
		}
		for _, segment := range path {
			if err := binary.Write(data, binary.BigEndian, segment); err != nil {
				return nil, err
			}
		}
	}

	return apdu.NewCommand(
		globalplatform.ClaGp,
		InsExportKey,
		p1,
		p2,
		data.Bytes(),
	), nil
}

func NewCommandSetPinlessPath(pathStr string) (*apdu.Command, error) {
	startingPoint, path, err := derivationpath.Decode(pathStr)
	if err != nil {
		return nil, err
	}

	if len(path) > 0 && startingPoint != derivationpath.StartingPointMaster {
		return nil, fmt.Errorf("pinless path must be set with an absolute path")
	}

	data := new(bytes.Buffer)
	for _, segment := range path {
		if err := binary.Write(data, binary.BigEndian, segment); err != nil {
			return nil, err
		}
	}

	return apdu.NewCommand(
		globalplatform.ClaGp,
		InsSetPinlessPath,
		0,
		0,
		data.Bytes(),
	), nil
}

func NewCommandSign(data []byte, p1 uint8) (*apdu.Command, error) {
	if len(data) != 32 {
		return nil, fmt.Errorf("data length must be 32, got %d", len(data))
	}

	return apdu.NewCommand(
		globalplatform.ClaGp,
		InsSign,
		p1,
		0,
		data,
	), nil
}
