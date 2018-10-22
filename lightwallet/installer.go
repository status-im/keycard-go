package lightwallet

import (
	"crypto/rand"
	"errors"
	"fmt"
	"os"

	"github.com/status-im/smartcard-go/apdu"
	"github.com/status-im/smartcard-go/globalplatform"
)

var (
	cardManagerAID = []byte{0xa0, 0x00, 0x00, 0x01, 0x51, 0x00, 0x00, 0x00}
	testKey        = []byte{0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f}

	pkgAID = []byte{0x53, 0x74, 0x61, 0x74, 0x75, 0x73, 0x57, 0x61, 0x6C, 0x6C, 0x65, 0x74}
	// applet and instance aid
	walletAID       = []byte{0x53, 0x74, 0x61, 0x74, 0x75, 0x73, 0x57, 0x61, 0x6C, 0x6C, 0x65, 0x74, 0x41, 0x70, 0x70}
	ndefAppletAID   = []byte{0x53, 0x74, 0x61, 0x74, 0x75, 0x73, 0x57, 0x61, 0x6C, 0x6C, 0x65, 0x74, 0x4E, 0x46, 0x43}
	ndefInstanceAID = []byte{0xD2, 0x76, 0x00, 0x00, 0x85, 0x01, 0x01}
)

// Installer defines a struct with methods to install an applet to a smartcard.
type Installer struct {
	c globalplatform.Channel
}

// NewInstaller returns a new Installer that communicates to Transmitter t.
func NewInstaller(t globalplatform.Transmitter) *Installer {
	return &Installer{
		c: globalplatform.NewNormalChannel(t),
	}
}

// Install installs the applet from the specified capFile.
func (i *Installer) Install(capFile *os.File, overwriteApplet bool) error {
	err := i.initSecureChannel(cardManagerAID)
	if err != nil {
		return err
	}

	installed, err := i.isAppletInstalled()
	if err != nil {
		return err
	}

	if installed && !overwriteApplet {
		return errors.New("applet already installed")
	}

	err = i.deleteAID(ndefInstanceAID, walletAID, pkgAID)
	if err != nil {
		return err
	}

	err = i.installApplets(capFile)
	if err != nil {
		return err
	}

	return err
}

func (i *Installer) Init() (*Secrets, error) {
	secrets, err := NewSecrets()
	if err != nil {
		return nil, err
	}

	sel := globalplatform.NewCommandSelect(walletAID)
	resp, err := i.send("select applet", sel)
	if err != nil {
		return nil, err
	}

	cardKeyData := resp.Data[2:]
	secureChannel, err := NewSecureChannel(i.c, cardKeyData)
	if err != nil {
		return nil, err
	}

	data, err := secureChannel.OneShotEncrypt(secrets)
	if err != nil {
		return nil, err
	}

	cmd := NewCommandInit(data)
	resp, err = i.send("init card", cmd)
	if err != nil {
		return nil, err
	}

	fmt.Printf("RESP: %+v\n", resp)

	return secrets, nil
}

// Info returns if the applet is already installed in the card.
func (i *Installer) Info() (bool, error) {
	err := i.initSecureChannel(cardManagerAID)
	if err != nil {
		return false, err
	}

	return i.isAppletInstalled()
}

// Delete deletes the applet and related package from the card.
func (i *Installer) Delete() error {
	err := i.initSecureChannel(cardManagerAID)
	if err != nil {
		return err
	}

	return i.deleteAID(ndefInstanceAID, walletAID, pkgAID)
}

func (i *Installer) isAppletInstalled() (bool, error) {
	cmd := globalplatform.NewCommandGetStatus(walletAID, globalplatform.P1GetStatusApplications)
	resp, err := i.send("get status", cmd, globalplatform.SwOK, globalplatform.SwReferencedDataNotFound)
	if err != nil {
		return false, err
	}

	if resp.Sw == globalplatform.SwReferencedDataNotFound {
		return false, nil
	}

	return true, nil
}

func (i *Installer) initSecureChannel(sdaid []byte) error {
	// select card manager
	err := i.selectAID(sdaid)
	if err != nil {
		return err
	}

	// initialize update
	session, err := i.initializeUpdate()
	if err != nil {
		return err
	}

	i.c = globalplatform.NewSecureChannel(session, i.c)

	// external authenticate
	return i.externalAuthenticate(session)
}

func (i *Installer) selectAID(aid []byte) error {
	sel := globalplatform.NewCommandSelect(cardManagerAID)
	_, err := i.send("select", sel)

	return err
}

func (i *Installer) initializeUpdate() (*globalplatform.Session, error) {
	hostChallenge, err := generateHostChallenge()
	if err != nil {
		return nil, err
	}

	init := globalplatform.NewCommandInitializeUpdate(hostChallenge)
	resp, err := i.send("initialize update", init)
	if err != nil {
		return nil, err
	}

	// verify cryptogram and initialize session keys
	keys := globalplatform.NewKeyProvider(testKey, testKey)
	session, err := globalplatform.NewSession(keys, resp, hostChallenge)

	return session, err
}

func (i *Installer) externalAuthenticate(session *globalplatform.Session) error {
	encKey := session.KeyProvider().Enc()
	extAuth, err := globalplatform.NewCommandExternalAuthenticate(encKey, session.CardChallenge(), session.HostChallenge())
	if err != nil {
		return err
	}

	_, err = i.send("external authenticate", extAuth)

	return err
}

func (i *Installer) deleteAID(aids ...[]byte) error {
	for _, aid := range aids {
		del := globalplatform.NewCommandDelete(aid)
		_, err := i.send("delete", del, globalplatform.SwOK, globalplatform.SwReferencedDataNotFound)
		if err != nil {
			return err
		}
	}

	return nil
}

func (i *Installer) installApplets(capFile *os.File) error {
	// install for load
	preLoad := globalplatform.NewCommandInstallForLoad(pkgAID, cardManagerAID)
	_, err := i.send("install for load", preLoad)
	if err != nil {
		return err
	}

	// load
	load, err := globalplatform.NewLoadCommandStream(capFile)
	if err != nil {
		return err
	}

	for load.Next() {
		cmd := load.GetCommand()
		_, err = i.send(fmt.Sprintf("load %d of 36", load.Index()), cmd)
		if err != nil {
			return err
		}
	}

	installNdef := globalplatform.NewCommandInstallForInstall(pkgAID, ndefAppletAID, ndefInstanceAID, []byte{})
	_, err = i.send("install for install (ndef)", installNdef)
	if err != nil {
		return err
	}

	installWallet := globalplatform.NewCommandInstallForInstall(pkgAID, walletAID, walletAID, []byte{})
	_, err = i.send("install for install (wallet)", installWallet)

	return err
}

func (i *Installer) send(description string, cmd *apdu.Command, allowedResponses ...uint16) (*apdu.Response, error) {
	logger.Debug("sending apdu command", "name", description)
	resp, err := i.c.Send(cmd)
	if err != nil {
		return nil, err
	}

	if len(allowedResponses) == 0 {
		allowedResponses = []uint16{apdu.SwOK}
	}

	for _, code := range allowedResponses {
		if code == resp.Sw {
			return resp, nil
		}
	}

	err = fmt.Errorf("unexpected response from command %s: %x", description, resp.Sw)

	return nil, err
}

func generateHostChallenge() ([]byte, error) {
	c := make([]byte, 8)
	_, err := rand.Read(c)
	return c, err
}
