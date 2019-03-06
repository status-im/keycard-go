package globalplatform

import (
	"crypto/rand"
	"errors"
	"fmt"
	"os"

	"github.com/status-im/keycard-go/apdu"
)

var (
	CardManagerAID = []byte{0xa0, 0x00, 0x00, 0x01, 0x51, 0x00, 0x00, 0x00}
	CardTestKey    = []byte{0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f}
	AppletPkgAID   = []byte{0xA0, 0x00, 0x00, 0x08, 0x04, 0x00, 0x01}

	WalletAID         = []byte{0xA0, 0x00, 0x00, 0x08, 0x04, 0x00, 0x01, 0x01}
	WalletInstanceAID = []byte{0xA0, 0x00, 0x00, 0x08, 0x04, 0x00, 0x01, 0x01, 0x01}

	NdefAppletAID   = []byte{0xA0, 0x00, 0x00, 0x08, 0x04, 0x00, 0x01, 0x02}
	NdefInstanceAID = []byte{0xD2, 0x76, 0x00, 0x00, 0x85, 0x01, 0x01}
)

type LoadingCallback = func(loadingBlock, totalBlocks int)

type CommandSet struct {
	c       Channel
	session *Session
}

func NewCommandSet(c Channel) *CommandSet {
	return &CommandSet{
		c: c,
	}
}

func (cs *CommandSet) Select() error {
	cmd := apdu.NewCommand(
		0x00,
		InsSelect,
		uint8(0x04),
		uint8(0x00),
		CardManagerAID,
	)

	resp, err := cs.c.Send(cmd)
	return cs.checkOK(resp, err)
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
	ids := [][]byte{
		NdefInstanceAID,
		WalletInstanceAID,
		AppletPkgAID,
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
	preLoad := NewCommandInstallForLoad(AppletPkgAID, CardManagerAID)
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
	return cs.installForInstall(AppletPkgAID, NdefAppletAID, NdefInstanceAID, ndefRecord)
}

func (cs *CommandSet) InstallKeycardApplet() error {
	return cs.installForInstall(AppletPkgAID, WalletAID, WalletInstanceAID, []byte{})
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
	keys := NewSCP02Keys(CardTestKey, CardTestKey)
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
