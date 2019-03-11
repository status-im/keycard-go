package keycard

import (
	"github.com/status-im/keycard-go/apdu"
	"github.com/status-im/keycard-go/globalplatform"
	"github.com/status-im/keycard-go/identifiers"
	"github.com/status-im/keycard-go/types"
)

type CommandSet struct {
	c               types.Channel
	ApplicationInfo types.ApplicationInfo
}

func NewCommandSet(c types.Channel) *CommandSet {
	return &CommandSet{
		c: c,
	}
}

func (cs *CommandSet) Select() error {
	instanceAID, err := identifiers.KeycardInstanceAID(identifiers.KeycardDefaultInstanceIndex)
	if err != nil {
		return err
	}

	cmd := apdu.NewCommand(
		0x00,
		globalplatform.InsSelect,
		uint8(0x04),
		uint8(0x00),
		instanceAID,
	)

	cmd.SetLe(0)
	resp, err := cs.c.Send(cmd)

	err = cs.checkOK(resp, err)
	if err == nil {
		appInfo, err := types.ParseApplicationInfo(resp.Data)
		if err != nil {
			return err
		}

		cs.ApplicationInfo = appInfo

		return nil
	}

	return err
}

func (cs *CommandSet) Init(secrets *Secrets) error {
	secureChannel, err := NewSecureChannel(cs.c, cs.ApplicationInfo.PublicKey)
	if err != nil {
		return err
	}

	data, err := secureChannel.OneShotEncrypt(secrets)
	if err != nil {
		return err
	}

	init := NewCommandInit(data)
	resp, err := cs.c.Send(init)

	return cs.checkOK(resp, err)
}

func (cs *CommandSet) checkOK(resp *apdu.Response, err error, allowedResponses ...uint16) error {
	if len(allowedResponses) == 0 {
		allowedResponses = []uint16{apdu.SwOK}
	}

	for _, code := range allowedResponses {
		if code == resp.Sw {
			return nil
		}
	}

	return apdu.NewErrBadResponse(resp.Sw, "unexpected response")
}
