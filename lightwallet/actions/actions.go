package actions

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/status-im/hardware-wallet-go/apdu"
	"github.com/status-im/hardware-wallet-go/globalplatform"
	"github.com/status-im/hardware-wallet-go/lightwallet"
	"github.com/status-im/hardware-wallet-go/lightwallet/crypto"
)

var (
	ErrAlreadyInitialized                = errors.New("card already initialized")
	ErrNotInitialized                    = errors.New("card not initialized")
	ErrWrongApplicationInfoTemplate      = errors.New("wrong application info template")
	ErrApplicationStatusTemplateNotFound = errors.New("application status template not found")
)

func Select(c globalplatform.Channel, aid []byte) (*lightwallet.ApplicationInfo, error) {
	sel := globalplatform.NewCommandSelect(aid)
	resp, err := c.Send(sel)
	if err != nil {
		return nil, err
	}

	err = checkResponse(resp, globalplatform.SwOK, globalplatform.SwFileNotFound)
	if err != nil {
		return nil, err
	}

	info := &lightwallet.ApplicationInfo{}
	if resp.Sw == globalplatform.SwFileNotFound {
		return info, nil
	}

	info.Installed = true
	if resp.Data[0] == lightwallet.TagSelectResponsePreInitialized {
		info.PublicKey = resp.Data[2:]
		return info, nil
	}

	info.Initialized = true

	return parseApplicationInfo(resp.Data, info)
}

func SelectNotInitialized(c globalplatform.Channel, aid []byte) ([]byte, error) {
	sel := globalplatform.NewCommandSelect(aid)
	resp, err := c.Send(sel)
	if err = checkOKResponse(err, resp); err != nil {
		return nil, err
	}

	if resp.Data[0] != lightwallet.TagSelectResponsePreInitialized {
		return nil, ErrAlreadyInitialized
	}

	return resp.Data[2:], nil
}

func SelectInitialized(c globalplatform.Channel, aid []byte) (*lightwallet.ApplicationInfo, error) {
	sel := globalplatform.NewCommandSelect(aid)
	resp, err := c.Send(sel)
	if err = checkOKResponse(err, resp); err != nil {
		return nil, err
	}

	if resp.Data[0] == lightwallet.TagSelectResponsePreInitialized {
		return nil, ErrNotInitialized
	}

	return parseApplicationInfo(resp.Data, &lightwallet.ApplicationInfo{})
}

func Init(c globalplatform.Channel, cardPubKey []byte, secrets *lightwallet.Secrets, aid []byte) error {
	secureChannel, err := lightwallet.NewSecureChannel(c, cardPubKey)
	if err != nil {
		return err
	}

	data, err := secureChannel.OneShotEncrypt(secrets)
	if err != nil {
		return err
	}

	init := lightwallet.NewCommandInit(data)
	resp, err := c.Send(init)

	return checkOKResponse(err, resp)
}

func Pair(c globalplatform.Channel, pairingPass string, pin string) (*lightwallet.PairingInfo, error) {
	challenge := make([]byte, 32)
	if _, err := rand.Read(challenge); err != nil {
		return nil, err
	}

	cmd := lightwallet.NewCommandPairFirstStep(challenge)
	resp, err := c.Send(cmd)
	if err = checkOKResponse(err, resp); err != nil {
		return nil, err
	}

	cardCryptogram := resp.Data[:32]
	cardChallenge := resp.Data[32:]

	secretHash, err := crypto.VerifyCryptogram(challenge, pairingPass, cardCryptogram)
	if err != nil {
		return nil, err
	}

	h := sha256.New()
	h.Write(secretHash[:])
	h.Write(cardChallenge)
	cmd = lightwallet.NewCommandPairFinalStep(h.Sum(nil))
	resp, err = c.Send(cmd)
	if err = checkOKResponse(err, resp); err != nil {
		return nil, err
	}

	h.Reset()
	h.Write(secretHash[:])
	h.Write(resp.Data[1:])

	pairingKey := h.Sum(nil)
	pairingIndex := resp.Data[0]

	return &lightwallet.PairingInfo{
		Key:   pairingKey,
		Index: int(pairingIndex),
	}, nil
}

func OpenSecureChannel(c globalplatform.Channel, appInfo *lightwallet.ApplicationInfo, pairingIndex uint8, pairingKey []byte) (*lightwallet.SecureChannel, error) {
	sc, err := lightwallet.NewSecureChannel(c, appInfo.PublicKey)
	cmd := lightwallet.NewCommandOpenSecureChannel(pairingIndex, sc.RawPublicKey())
	resp, err := c.Send(cmd)
	if err = checkOKResponse(err, resp); err != nil {
		return nil, err
	}

	encKey, macKey, iv := crypto.DeriveSessionKeys(sc.Secret(), pairingKey, resp.Data)
	sc.Init(iv, encKey, macKey)

	err = mutualAuthenticate(sc)
	if err != nil {
		return nil, err
	}

	return sc, nil
}

func mutualAuthenticate(sc *lightwallet.SecureChannel) error {
	data := make([]byte, 32)
	if _, err := rand.Read(data); err != nil {
		return err
	}

	cmd := lightwallet.NewCommandMutuallyAuthenticate(data)
	resp, err := sc.Send(cmd)

	return checkOKResponse(err, resp)
}

func GetStatusApplication(c globalplatform.Channel) (*lightwallet.ApplicationStatus, error) {
	cmd := lightwallet.NewCommandGetStatusApplication()
	resp, err := c.Send(cmd)
	if err = checkOKResponse(err, resp); err != nil {
		return nil, err
	}

	return parseApplicationStatus(resp.Data)
}

func parseApplicationInfo(data []byte, info *lightwallet.ApplicationInfo) (*lightwallet.ApplicationInfo, error) {
	if data[0] != lightwallet.TagApplicationInfoTemplate {
		return nil, ErrWrongApplicationInfoTemplate
	}

	instanceUID, err := apdu.FindTag(data, lightwallet.TagApplicationInfoTemplate, uint8(0x8F))
	if err != nil {
		return nil, err
	}

	pubKey, err := apdu.FindTag(data, lightwallet.TagApplicationInfoTemplate, uint8(0x80))
	if err != nil {
		return nil, err
	}

	appVersion, err := apdu.FindTag(data, lightwallet.TagApplicationInfoTemplate, uint8(0x02))
	if err != nil {
		return nil, err
	}

	availableSlots, err := apdu.FindTagN(data, 1, lightwallet.TagApplicationInfoTemplate, uint8(0x02))
	if err != nil {
		return nil, err
	}

	keyUID, err := apdu.FindTagN(data, 0, lightwallet.TagApplicationInfoTemplate, uint8(0x8E))
	if err != nil {
		return nil, err
	}

	info.InstanceUID = instanceUID
	info.PublicKey = pubKey
	info.Version = appVersion
	info.AvailableSlots = availableSlots
	info.KeyUID = keyUID

	return info, nil
}

func parseApplicationStatus(data []byte) (*lightwallet.ApplicationStatus, error) {
	appStatus := &lightwallet.ApplicationStatus{}

	tpl, err := apdu.FindTag(data, lightwallet.TagApplicationStatusTemplate)
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

func checkOKResponse(err error, resp *apdu.Response) error {
	if err != nil {
		return err
	}

	return checkResponse(resp, apdu.SwOK)
}

func checkResponse(resp *apdu.Response, allowedResponses ...uint16) error {
	for _, code := range allowedResponses {
		if code == resp.Sw {
			return nil
		}
	}

	return fmt.Errorf("unexpected response: %x", resp.Sw)
}
