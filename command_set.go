package keycard

import (
	"crypto/rand"
	"crypto/sha256"

	"github.com/status-im/keycard-go/apdu"
	"github.com/status-im/keycard-go/crypto"
	"github.com/status-im/keycard-go/globalplatform"
	"github.com/status-im/keycard-go/identifiers"
	"github.com/status-im/keycard-go/types"
)

type CommandSet struct {
	c               types.Channel
	sc              *SecureChannel
	ApplicationInfo types.ApplicationInfo
	PairingInfo     *types.PairingInfo
}

func NewCommandSet(c types.Channel) *CommandSet {
	return &CommandSet{
		c:  c,
		sc: NewSecureChannel(c),
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
	if err = cs.checkOK(resp, err); err != nil {
		return err
	}

	appInfo, err := types.ParseApplicationInfo(resp.Data)
	if err != nil {
		return err
	}

	cs.ApplicationInfo = appInfo

	if cs.ApplicationInfo.HasSecureChannelCapability() {
		err = cs.sc.GenerateSecret(cs.ApplicationInfo.PublicKey)
		if err != nil {
			return err
		}

		cs.sc.Reset()
	}

	return nil
}

func (cs *CommandSet) Init(secrets *Secrets) error {
	data, err := cs.sc.OneShotEncrypt(secrets)
	if err != nil {
		return err
	}

	init := NewCommandInit(data)
	resp, err := cs.c.Send(init)

	return cs.checkOK(resp, err)
}

func (cs *CommandSet) Pair(pairingPass string) error {
	challenge := make([]byte, 32)
	if _, err := rand.Read(challenge); err != nil {
		return err
	}

	cmd := NewCommandPairFirstStep(challenge)
	resp, err := cs.c.Send(cmd)
	if err = cs.checkOK(resp, err); err != nil {
		return err
	}

	cardCryptogram := resp.Data[:32]
	cardChallenge := resp.Data[32:]

	secretHash, err := crypto.VerifyCryptogram(challenge, pairingPass, cardCryptogram)
	if err != nil {
		return err
	}

	h := sha256.New()
	h.Write(secretHash[:])
	h.Write(cardChallenge)
	cmd = NewCommandPairFinalStep(h.Sum(nil))
	resp, err = cs.c.Send(cmd)
	if err = cs.checkOK(resp, err); err != nil {
		return err
	}

	h.Reset()
	h.Write(secretHash[:])
	h.Write(resp.Data[1:])

	pairingKey := h.Sum(nil)
	pairingIndex := resp.Data[0]

	cs.PairingInfo = &types.PairingInfo{
		Key:   pairingKey,
		Index: int(pairingIndex),
	}

	return nil
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
