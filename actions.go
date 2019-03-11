package keycard

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/status-im/keycard-go/apdu"
	"github.com/status-im/keycard-go/crypto"
	"github.com/status-im/keycard-go/globalplatform"
	"github.com/status-im/keycard-go/types"
)

var (
	ErrAlreadyInitialized                = errors.New("card already initialized")
	ErrWrongApplicationInfoTemplate      = errors.New("wrong application info template")
	ErrApplicationStatusTemplateNotFound = errors.New("application status template not found")
)

func Select(c types.Channel, aid []byte) (*types.ApplicationInfo, error) {
	sel := globalplatform.NewCommandSelect(aid)
	resp, err := c.Send(sel)
	if err != nil {
		return nil, err
	}

	err = checkResponse(resp, globalplatform.SwOK, globalplatform.SwFileNotFound)
	if err != nil {
		return nil, err
	}

	info := &types.ApplicationInfo{}
	if resp.Sw == globalplatform.SwFileNotFound {
		return info, nil
	}

	info.Installed = true
	if resp.Data[0] == TagSelectResponsePreInitialized {
		info.PublicKey = resp.Data[2:]
		return info, nil
	}

	info.Initialized = true

	return parseApplicationInfo(resp.Data, info)
}

func Init(c types.Channel, cardPubKey []byte, secrets *Secrets, aid []byte) error {
	secureChannel, err := NewSecureChannel(c, cardPubKey)
	if err != nil {
		return err
	}

	data, err := secureChannel.OneShotEncrypt(secrets)
	if err != nil {
		return err
	}

	init := NewCommandInit(data)
	resp, err := c.Send(init)

	return checkOKResponse(err, resp)
}

func Pair(c types.Channel, pairingPass string, pin string) (*types.PairingInfo, error) {
	challenge := make([]byte, 32)
	if _, err := rand.Read(challenge); err != nil {
		return nil, err
	}

	cmd := NewCommandPairFirstStep(challenge)
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
	cmd = NewCommandPairFinalStep(h.Sum(nil))
	resp, err = c.Send(cmd)
	if err = checkOKResponse(err, resp); err != nil {
		return nil, err
	}

	h.Reset()
	h.Write(secretHash[:])
	h.Write(resp.Data[1:])

	pairingKey := h.Sum(nil)
	pairingIndex := resp.Data[0]

	return &types.PairingInfo{
		Key:   pairingKey,
		Index: int(pairingIndex),
	}, nil
}

func OpenSecureChannel(c types.Channel, appInfo *types.ApplicationInfo, pairingIndex uint8, pairingKey []byte) (*SecureChannel, error) {
	sc, err := NewSecureChannel(c, appInfo.PublicKey)
	cmd := NewCommandOpenSecureChannel(pairingIndex, sc.RawPublicKey())
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

func mutualAuthenticate(sc *SecureChannel) error {
	data := make([]byte, 32)
	if _, err := rand.Read(data); err != nil {
		return err
	}

	cmd := NewCommandMutuallyAuthenticate(data)
	resp, err := sc.Send(cmd)

	return checkOKResponse(err, resp)
}

func GetStatusApplication(c types.Channel) (*types.ApplicationStatus, error) {
	cmd := NewCommandGetStatusApplication()
	resp, err := c.Send(cmd)
	if err = checkOKResponse(err, resp); err != nil {
		return nil, err
	}

	return parseApplicationStatus(resp.Data)
}

func parseApplicationInfo(data []byte, info *types.ApplicationInfo) (*types.ApplicationInfo, error) {
	if data[0] != TagApplicationInfoTemplate {
		return nil, ErrWrongApplicationInfoTemplate
	}

	instanceUID, err := apdu.FindTag(data, TagApplicationInfoTemplate, uint8(0x8F))
	if err != nil {
		return nil, err
	}

	pubKey, err := apdu.FindTag(data, TagApplicationInfoTemplate, uint8(0x80))
	if err != nil {
		return nil, err
	}

	appVersion, err := apdu.FindTag(data, TagApplicationInfoTemplate, uint8(0x02))
	if err != nil {
		return nil, err
	}

	availableSlots, err := apdu.FindTagN(data, 1, TagApplicationInfoTemplate, uint8(0x02))
	if err != nil {
		return nil, err
	}

	keyUID, err := apdu.FindTagN(data, 0, TagApplicationInfoTemplate, uint8(0x8E))
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

func parseApplicationStatus(data []byte) (*types.ApplicationStatus, error) {
	appStatus := &types.ApplicationStatus{}

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
