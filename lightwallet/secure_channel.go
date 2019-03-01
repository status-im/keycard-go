package lightwallet

import (
	"bytes"
	"crypto/ecdsa"
	"errors"

	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/status-im/keycard-go/apdu"
	"github.com/status-im/keycard-go/globalplatform"
	"github.com/status-im/keycard-go/lightwallet/crypto"
)

var ErrInvalidResponseMAC = errors.New("invalid response MAC")

type SecureChannel struct {
	c         globalplatform.Channel
	secret    []byte
	publicKey *ecdsa.PublicKey
	encKey    []byte
	macKey    []byte
	iv        []byte
}

func NewSecureChannel(c globalplatform.Channel, cardKeyData []byte) (*SecureChannel, error) {
	key, err := ethcrypto.GenerateKey()
	if err != nil {
		return nil, err
	}

	cardPubKey, err := ethcrypto.UnmarshalPubkey(cardKeyData)
	if err != nil {
		return nil, err
	}

	secret := crypto.GenerateECDHSharedSecret(key, cardPubKey)

	return &SecureChannel{
		c:         c,
		secret:    secret,
		publicKey: &key.PublicKey,
	}, nil
}

func (sc *SecureChannel) Init(iv, encKey, macKey []byte) {
	sc.iv = iv
	sc.encKey = encKey
	sc.macKey = macKey
}

func (sc *SecureChannel) Secret() []byte {
	return sc.secret
}

func (sc *SecureChannel) PublicKey() *ecdsa.PublicKey {
	return sc.publicKey
}

func (sc *SecureChannel) RawPublicKey() []byte {
	return ethcrypto.FromECDSAPub(sc.publicKey)
}

func (sc *SecureChannel) Send(cmd *apdu.Command) (*apdu.Response, error) {
	encData, err := crypto.EncryptData(cmd.Data, sc.encKey, sc.iv)
	if err != nil {
		return nil, err
	}

	meta := []byte{cmd.Cla, cmd.Ins, cmd.P1, cmd.P2, byte(len(encData) + 16), 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	if err = sc.updateIV(meta, encData); err != nil {
		return nil, err
	}

	newData := append(sc.iv, encData...)
	cmd.Data = newData

	resp, err := sc.c.Send(cmd)
	if err != nil {
		return nil, err
	}

	if resp.Sw != globalplatform.SwOK {
		return nil, apdu.NewErrBadResponse(resp.Sw, "unexpected sw in secure channel")
	}

	rmeta := []byte{byte(len(resp.Data)), 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	rmac := resp.Data[:len(sc.iv)]
	rdata := resp.Data[len(sc.iv):]
	plainData, err := crypto.DecryptData(rdata, sc.encKey, sc.iv)
	if err = sc.updateIV(rmeta, rdata); err != nil {
		return nil, err
	}

	if !bytes.Equal(sc.iv, rmac) {
		return nil, ErrInvalidResponseMAC
	}

	return apdu.ParseResponse(plainData)
}

func (sc *SecureChannel) updateIV(meta, data []byte) error {
	mac, err := crypto.CalculateMac(meta, data, sc.macKey)
	if err != nil {
		return err
	}

	sc.iv = mac

	return nil
}

func (sc *SecureChannel) OneShotEncrypt(secrets *Secrets) ([]byte, error) {
	pubKeyData := ethcrypto.FromECDSAPub(sc.publicKey)
	data := append([]byte(secrets.Pin()), []byte(secrets.Puk())...)
	data = append(data, secrets.PairingToken()...)

	return crypto.OneShotEncrypt(pubKeyData, sc.secret, data)
}
