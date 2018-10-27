package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"errors"

	"github.com/ethereum/go-ethereum/crypto"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/text/unicode/norm"
)

const pairingSalt = "Status Hardware Wallet Lite"

var ErrInvalidCardCryptogram = errors.New("invalid card cryptogram")

func GenerateECDHSharedSecret(priv *ecdsa.PrivateKey, pub *ecdsa.PublicKey) []byte {
	x, _ := crypto.S256().ScalarMult(pub.X, pub.Y, priv.D.Bytes())
	return x.Bytes()
}

func VerifyCryptogram(challenge []byte, pairingPass string, cardCryptogram []byte) ([]byte, error) {
	secretHash := pbkdf2.Key(norm.NFKD.Bytes([]byte(pairingPass)), norm.NFKD.Bytes([]byte(pairingSalt)), 50000, 32, sha256.New)

	h := sha256.New()
	h.Write(secretHash[:])
	h.Write(challenge)
	expectedCryptogram := h.Sum(nil)

	if !bytes.Equal(expectedCryptogram, cardCryptogram) {
		return nil, ErrInvalidCardCryptogram
	}

	return secretHash, nil
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
