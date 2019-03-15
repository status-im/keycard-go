package types

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"

	"github.com/status-im/keycard-go/apdu"
)

const hardenedStart = 0x80000000 // 2^31

var ErrApplicationStatusTemplateNotFound = errors.New("application status template not found")

type ApplicationStatus struct {
	PinRetryCount  int
	PUKRetryCount  int
	KeyInitialized bool
	Path           string
}

func ParseApplicationStatus(data []byte) (*ApplicationStatus, error) {
	tpl, err := apdu.FindTag(data, TagApplicationStatusTemplate)
	if err != nil {
		return parseKeyPathStatus(data)
	}

	appStatus := &ApplicationStatus{}

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

	return appStatus, nil
}

func parseKeyPathStatus(data []byte) (*ApplicationStatus, error) {
	appStatus := &ApplicationStatus{}
	buf := bytes.NewBuffer(data)
	rawPath := make([]uint32, buf.Len()/4)
	err := binary.Read(buf, binary.BigEndian, &rawPath)
	if err != nil {
		return nil, err
	}

	segments := []string{"m"}
	for _, i := range rawPath {
		suffix := ""
		if i >= hardenedStart {
			i = i - hardenedStart
			suffix = "'"
		}
		segments = append(segments, fmt.Sprintf("%d%s", i, suffix))
	}

	appStatus.Path = strings.Join(segments, "/")

	return appStatus, nil
}
