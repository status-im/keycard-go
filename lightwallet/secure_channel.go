package lightwallet

import (
	"crypto/ecdsa"

	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/status-im/hardware-wallet-go/apdu"
	"github.com/status-im/hardware-wallet-go/globalplatform"
	"github.com/status-im/hardware-wallet-go/lightwallet/crypto"
)

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
	return sc.c.Send(cmd)
}

func (sc *SecureChannel) OneShotEncrypt(secrets *Secrets) ([]byte, error) {
	pubKeyData := ethcrypto.FromECDSAPub(sc.publicKey)
	data := append([]byte(secrets.Pin()), []byte(secrets.Puk())...)
	data = append(data, secrets.PairingToken()...)

	return crypto.OneShotEncrypt(pubKeyData, sc.secret, data)
}
