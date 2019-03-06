package globalplatform

import (
	"crypto/rand"
	"errors"
	"fmt"
	"os"

	"github.com/status-im/keycard-go/apdu"
	"github.com/status-im/keycard-go/identifiers"
)

type LoadingCallback = func(loadingBlock, totalBlocks int)

const defaultKeycardInstanceAID = 1

type CommandSet struct {
	c       Channel
	session *Session
}

func NewCommandSet(c Channel) *CommandSet {
	return &CommandSet{
		c: c,
	}
}

func (cs *CommandSet) Select() ([]byte, error) {
	cmd := apdu.NewCommand(
		0x00,
		InsSelect,
		uint8(0x04),
		uint8(0x00),
		nil,
	)

	cmd.SetLe(0)
	resp, err := cs.c.Send(cmd)
	if err = cs.checkOK(resp, err); err != nil {
		return nil, err
	}

	// issuer security domain
	isd, _ := apdu.FindTag(resp.Data, 0x6F, 0x84)
	return isd, err
}

func (cs *CommandSet) OpenSecureChannel() error {
	hostChallenge, err := generateHostChallenge()
	if err != nil {
		return err
	}

	err = cs.initializeUpdate(hostChallenge)
	if err != nil {
		return err
	}

	return cs.externalAuthenticate()
}

func (cs *CommandSet) DeleteKeycardInstancesAndPackage() error {
	instanceAID, err := identifiers.KeycardInstanceAID(defaultKeycardInstanceAID)
	if err != nil {
		return err
	}

	ids := [][]byte{
		identifiers.NdefInstanceAID,
		instanceAID,
		identifiers.PackageAID,
	}

	for _, id := range ids {
		cmd := NewCommandDelete(id)
		resp, err := cs.c.Send(cmd)
		if cs.checkOK(resp, err, SwOK, SwReferencedDataNotFound) != nil {
			return err
		}
	}

	return nil
}

func (cs *CommandSet) LoadKeycardPackage(capFile *os.File, callback LoadingCallback) error {
	preLoad := NewCommandInstallForLoad(identifiers.PackageAID, []byte{})
	resp, err := cs.c.Send(preLoad)
	if err = cs.checkOK(resp, err); err != nil {
		return err
	}

	load, err := NewLoadCommandStream(capFile)
	if err != nil {
		return err
	}

	for load.Next() {
		cmd := load.GetCommand()
		callback(int(load.Index()), load.BlocksCount())
		resp, err = cs.c.Send(cmd)
		if err = cs.checkOK(resp, err); err != nil {
			return err
		}
	}

	return nil
}

func (cs *CommandSet) InstallNDEFApplet(ndefRecord []byte) error {
	return cs.installForInstall(
		identifiers.PackageAID,
		identifiers.NdefAID,
		identifiers.NdefInstanceAID,
		ndefRecord)
}

func (cs *CommandSet) InstallKeycardApplet() error {
	instanceAID, err := identifiers.KeycardInstanceAID(defaultKeycardInstanceAID)
	if err != nil {
		return err
	}

	return cs.installForInstall(
		identifiers.PackageAID,
		identifiers.KeycardAID,
		instanceAID,
		[]byte{})
}

func (cs *CommandSet) installForInstall(packageAID, appletAID, instanceAID, params []byte) error {
	cmd := NewCommandInstallForInstall(packageAID, appletAID, instanceAID, params)
	resp, err := cs.c.Send(cmd)
	return cs.checkOK(resp, err)
}

func (cs *CommandSet) initializeUpdate(hostChallenge []byte) error {
	cmd := NewCommandInitializeUpdate(hostChallenge)
	resp, err := cs.c.Send(cmd)
	if err = cs.checkOK(resp, err); err != nil {
		return err
	}

	// verify cryptogram and initialize session keys
	keys := NewSCP02Keys(identifiers.CardTestKey, identifiers.CardTestKey)
	session, err := NewSession(keys, resp, hostChallenge)
	cs.c = NewSecureChannel(session, cs.c)
	cs.session = session

	return nil
}

func (cs *CommandSet) externalAuthenticate() error {
	if cs.session == nil {
		return errors.New("session must be initialized using initializeUpdate")
	}

	encKey := cs.session.Keys().Enc()
	cmd, err := NewCommandExternalAuthenticate(encKey, cs.session.CardChallenge(), cs.session.HostChallenge())
	if err != nil {
		return err
	}

	resp, err := cs.c.Send(cmd)
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

	return fmt.Errorf("unexpected response: %x", resp.Sw)
}

func generateHostChallenge() ([]byte, error) {
	c := make([]byte, 8)
	_, err := rand.Read(c)
	return c, err
}
