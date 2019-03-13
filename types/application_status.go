package types

import (
	"bytes"
	"errors"

	"github.com/status-im/keycard-go/apdu"
)

var ErrApplicationStatusTemplateNotFound = errors.New("application status template not found")

type ApplicationStatus struct {
	PinRetryCount    int
	PUKRetryCount    int
	KeyInitialized   bool
	PubKeyDerivation bool
}

func ParseApplicationStatus(data []byte) (*ApplicationStatus, error) {
	appStatus := &ApplicationStatus{}

	tpl, err := apdu.FindTag(data, TagApplicationStatusTemplate)
	if err != nil {
		return nil, ErrApplicationStatusTemplateNotFound
	}

	if pinRetryCount, err := apdu.FindTag(tpl, uint8(0x02)); err == nil && len(pinRetryCount) == 1 {
		appStatus.PinRetryCount = int(pinRetryCount[0])
	}

	if pukRetryCount, err := apdu.FindTagN(tpl, 1, uint8(0x02)); err == nil && len(pukRetryCount) == 1 {
		appStatus.PUKRetryCount = int(pukRetryCount[0])
	}

	if keyInitialized, err := apdu.FindTag(tpl, uint8(0x01)); err == nil {
		if bytes.Equal(keyInitialized, []byte{0xFF}) {
			appStatus.KeyInitialized = true
		}
	}

	if keyDerivationSupported, err := apdu.FindTagN(tpl, 1, uint8(0x01)); err == nil {
		if bytes.Equal(keyDerivationSupported, []byte{0xFF}) {
			appStatus.PubKeyDerivation = true
		}
	}

	return appStatus, nil
}
