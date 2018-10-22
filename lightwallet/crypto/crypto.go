package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/rand"

	"github.com/ethereum/go-ethereum/crypto"
)

func GenerateECDHSharedSecret(priv *ecdsa.PrivateKey, pub *ecdsa.PublicKey) []byte {
	x, _ := crypto.S256().ScalarMult(pub.X, pub.Y, priv.D.Bytes())
	return x.Bytes()
}

func OneShotEncrypt(pubKeyData, secret, data []byte) ([]byte, error) {
	data = appendPadding(16, data)

	iv := make([]byte, 16)
	_, err := rand.Read(iv)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(secret)
	if err != nil {
		return nil, err
	}

	ciphertext := make([]byte, len(data))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, data)

	encrypted := append([]byte{byte(len(pubKeyData))}, pubKeyData...)
	encrypted = append(encrypted, iv...)
	encrypted = append(encrypted, ciphertext...)

	return encrypted, nil
}

func appendPadding(blockSize int, data []byte) []byte {
	paddingSize := blockSize - (len(data)+1)%blockSize
	zeroes := bytes.Repeat([]byte{0x00}, paddingSize)
	padding := append([]byte{0x80}, zeroes...)

	return append(data, padding...)
}
