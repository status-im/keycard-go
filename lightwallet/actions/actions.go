package actions

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/status-im/smartcard-go/apdu"
	"github.com/status-im/smartcard-go/globalplatform"
	"github.com/status-im/smartcard-go/lightwallet"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/text/unicode/norm"
)

const pairingSalt = "Status Hardware Wallet Lite"

var (
	ErrAlreadyInitialized             = errors.New("card already initialized")
	ErrNotInitialized                 = errors.New("card not initialized")
	ErrUnknownApplicationInfoTemplate = errors.New("unknown application info template")
	ErrInvalidCardCryptogram          = errors.New("invalid card cryptogram")
)

func SelectNotInitialized(c globalplatform.Channel, aid []byte) ([]byte, error) {
	sel := globalplatform.NewCommandSelect(aid)
	resp, err := c.Send(sel)
	if err != nil {
		return nil, err
	}

	if err = checkOKResponse(resp); err != nil {
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
	if err != nil {
		return nil, err
	}

	if err = checkOKResponse(resp); err != nil {
		return nil, err
	}

	if resp.Data[0] == lightwallet.TagSelectResponsePreInitialized {
		return nil, ErrNotInitialized
	}

	return parseApplicationInfo(resp)
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
	if err != nil {
		return err
	}

	return checkOKResponse(resp)
}

func Pair(c globalplatform.Channel, pairingPass string, pin string) (*lightwallet.PairingInfo, error) {
	secretHash := pbkdf2.Key(norm.NFKD.Bytes([]byte(pairingPass)), norm.NFKD.Bytes([]byte(pairingSalt)), 50000, 32, sha256.New)

	challenge := make([]byte, 32)
	if _, err := rand.Read(challenge); err != nil {
		return nil, err
	}

	cmd := lightwallet.NewCommandPairFirstStep(challenge)
	resp, err := c.Send(cmd)
	if err != nil {
		return nil, err
	}

	if err = checkOKResponse(resp); err != nil {
		return nil, err
	}

	h := sha256.New()
	h.Write(secretHash[:])
	h.Write(challenge)

	expectedCryptogram := h.Sum(nil)
	cardCryptogram := resp.Data[:32]
	cardChallenge := resp.Data[32:]

	if !bytes.Equal(expectedCryptogram, cardCryptogram) {
		return nil, ErrInvalidCardCryptogram
	}

	h.Reset()
	h.Write(secretHash[:])
	h.Write(cardChallenge)
	cmd = lightwallet.NewCommandPairFinalStep(h.Sum(nil))
	resp, err = c.Send(cmd)
	if err != nil {
		return nil, err
	}

	if err = checkOKResponse(resp); err != nil {
		return nil, err
	}

	h.Reset()
	h.Write(secretHash[:])
	h.Write(resp.Data[1:])

	pairingKey := h.Sum(nil)
	pairingIndex := resp.Data[0]

	return &lightwallet.PairingInfo{
		PairingKey:   pairingKey,
		PairingIndex: int(pairingIndex),
	}, nil
}

func OpenSecureChannel(c globalplatform.Channel, appInfo *lightwallet.ApplicationInfo, pairingIndex uint8, pairingKey []byte) error {
	sc, err := lightwallet.NewSecureChannel(c, appInfo.PublicKey)

	cmd := lightwallet.NewCommandOpenSecureChannel(pairingIndex, sc.RawPublicKey())
	resp, err := c.Send(cmd)
	if err != nil {
		return err
	}

	if err = checkOKResponse(resp); err != nil {
		return err
	}

	return nil
}

func parseApplicationInfo(resp *apdu.Response) (*lightwallet.ApplicationInfo, error) {
	if resp.Data[0] != lightwallet.TagApplicationInfoTemplate {
		return nil, ErrUnknownApplicationInfoTemplate
	}

	instanceUID, err := apdu.FindTag(resp.Data, lightwallet.TagApplicationInfoTemplate, uint8(0x8F))
	if err != nil {
		return nil, err
	}

	pubKey, err := apdu.FindTag(resp.Data, lightwallet.TagApplicationInfoTemplate, uint8(0x80))
	if err != nil {
		return nil, err
	}

	appVersion, err := apdu.FindTag(resp.Data, lightwallet.TagApplicationInfoTemplate, uint8(0x02))
	if err != nil {
		return nil, err
	}

	availableSlots, err := apdu.FindTagN(resp.Data, 1, lightwallet.TagApplicationInfoTemplate, uint8(0x02))
	if err != nil {
		return nil, err
	}

	keyUID, err := apdu.FindTagN(resp.Data, 0, lightwallet.TagApplicationInfoTemplate, uint8(0x8E))
	if err != nil {
		return nil, err
	}

	return &lightwallet.ApplicationInfo{
		InstanceUID:    instanceUID,
		PublicKey:      pubKey,
		Version:        appVersion,
		AvailableSlots: availableSlots,
		KeyUID:         keyUID,
	}, nil
}

func checkOKResponse(resp *apdu.Response) error {
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
