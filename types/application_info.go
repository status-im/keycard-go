package types

import (
	"errors"

	"github.com/status-im/keycard-go/apdu"
)

var ErrWrongApplicationInfoTemplate = errors.New("wrong application info template")

const (
	TagSelectResponsePreInitialized = uint8(0x80)
	TagApplicationStatusTemplate    = uint8(0xA3)
	TagApplicationInfoTemplate      = uint8(0xA4)
)

type ApplicationInfo struct {
	Installed      bool
	Initialized    bool
	InstanceUID    []byte
	PublicKey      []byte
	Version        []byte
	AvailableSlots []byte
	// KeyUID is the sha256 of of the master public key on the card.
	// It's empty if the card doesn't contain any key.
	KeyUID []byte
}

func ParseApplicationInfo(data []byte) (info ApplicationInfo, err error) {
	info.Installed = true
	if data[0] == TagSelectResponsePreInitialized {
		info.PublicKey = data[2:]
		return info, nil
	}

	info.Initialized = true

	if data[0] != TagApplicationInfoTemplate {
		return info, ErrWrongApplicationInfoTemplate
	}

	instanceUID, err := apdu.FindTag(data, TagApplicationInfoTemplate, uint8(0x8F))
	if err != nil {
		return info, err
	}

	pubKey, err := apdu.FindTag(data, TagApplicationInfoTemplate, uint8(0x80))
	if err != nil {
		return info, err
	}

	appVersion, err := apdu.FindTag(data, TagApplicationInfoTemplate, uint8(0x02))
	if err != nil {
		return info, err
	}

	availableSlots, err := apdu.FindTagN(data, 1, TagApplicationInfoTemplate, uint8(0x02))
	if err != nil {
		return info, err
	}

	keyUID, err := apdu.FindTagN(data, 0, TagApplicationInfoTemplate, uint8(0x8E))
	if err != nil {
		return info, err
	}

	info.InstanceUID = instanceUID
	info.PublicKey = pubKey
	info.Version = appVersion
	info.AvailableSlots = availableSlots
	info.KeyUID = keyUID

	return info, nil
}
