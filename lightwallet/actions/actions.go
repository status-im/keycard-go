package actions

import (
	"errors"

	"github.com/status-im/smartcard-go/apdu"
	"github.com/status-im/smartcard-go/globalplatform"
	"github.com/status-im/smartcard-go/lightwallet"
)

var (
	ErrAlreadyInitialized             = errors.New("card already initialized")
	ErrNotInitialized                 = errors.New("card not initialized")
	ErrUnknownApplicationInfoTemplate = errors.New("unknown application info template")
)

type ApplicationInfo struct {
	InstanceUID    []byte
	PublicKey      []byte
	Version        []byte
	AvailableSlots []byte
}

func Select(c globalplatform.Channel, aid []byte) (*ApplicationInfo, error) {
	sel := globalplatform.NewCommandSelect(aid)
	resp, err := c.Send(sel)
	if err != nil {
		return nil, err
	}

	if resp.Data[0] == lightwallet.TagSelectResponsePreInitialized {
		return nil, ErrNotInitialized
	}

	return parseApplicationInfo(resp)
}

func Init(c globalplatform.Channel, secrets *lightwallet.Secrets, aid []byte) error {
	sel := globalplatform.NewCommandSelect(aid)
	resp, err := c.Send(sel)
	if err != nil {
		return err
	}

	if resp.Data[0] != lightwallet.TagSelectResponsePreInitialized {
		return ErrAlreadyInitialized
	}

	cardKeyData := resp.Data[2:]
	secureChannel, err := lightwallet.NewSecureChannel(c, cardKeyData)
	if err != nil {
		return err
	}

	data, err := secureChannel.OneShotEncrypt(secrets)
	if err != nil {
		return err
	}

	init := lightwallet.NewCommandInit(data)
	_, err = c.Send(init)

	return err
}

func parseApplicationInfo(resp *apdu.Response) (*ApplicationInfo, error) {
	if resp.Data[0] != lightwallet.TagApplicationInfoTemplate {
		return nil, ErrUnknownApplicationInfoTemplate
	}

	instanceUID, err := apdu.FindTag(resp.Data, lightwallet.TagApplicationInfoTemplate, uint8(0x8F))
	if err != nil {
		return nil, err
	}

	pubKey, err := apdu.FindTag(resp.Data, lightwallet.TagApplicationInfoTemplate, uint8(0x80))
	if err != nil {
		return nil, err
	}

	appVersion, err := apdu.FindTag(resp.Data, lightwallet.TagApplicationInfoTemplate, uint8(0x02))
	if err != nil {
		return nil, err
	}

	availableSlots, err := apdu.FindTagN(resp.Data, 1, lightwallet.TagApplicationInfoTemplate, uint8(0x02))
	if err != nil {
		return nil, err
	}

	return &ApplicationInfo{
		InstanceUID:    instanceUID,
		PublicKey:      pubKey,
		Version:        appVersion,
		AvailableSlots: availableSlots,
	}, nil
}
