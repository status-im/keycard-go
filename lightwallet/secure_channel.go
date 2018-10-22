package lightwallet

import (
	"crypto/ecdsa"

	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/status-im/smartcard-go/apdu"
	"github.com/status-im/smartcard-go/globalplatform"
	"github.com/status-im/smartcard-go/lightwallet/crypto"
)

type SecureChannel struct {
	c      globalplatform.Channel
	secret []byte
	pubKey *ecdsa.PublicKey
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
		c:      c,
		secret: secret,
		pubKey: &key.PublicKey,
	}, nil
}

func (sc *SecureChannel) Send(cmd *apdu.Command) (*apdu.Response, error) {
	return sc.c.Send(cmd)
}

func (sc *SecureChannel) OneShotEncrypt(secrets *Secrets) ([]byte, error) {
	pubKeyData := ethcrypto.FromECDSAPub(sc.pubKey)
	data := append([]byte(secrets.Pin()), []byte(secrets.Puk())...)
	data = append(data, secrets.PairingToken()...)

	return crypto.OneShotEncrypt(pubKeyData, sc.secret, data)
}
