package crypto

import (
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/assert"
)

func TestECDH(t *testing.T) {
	pk1, err := crypto.GenerateKey()
	assert.NoError(t, err)
	pk2, err := crypto.GenerateKey()
	assert.NoError(t, err)

	sharedSecret1 := GenerateECDHSharedSecret(pk1, &pk2.PublicKey)
	sharedSecret2 := GenerateECDHSharedSecret(pk2, &pk1.PublicKey)

	assert.Equal(t, sharedSecret1, sharedSecret2)
}
