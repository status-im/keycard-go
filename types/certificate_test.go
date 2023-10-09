package types

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
)

func hexMustDecode(str string) []byte {
	out, _ := hex.DecodeString(str)
	return out
}

func TestVerifyIdentity(t *testing.T) {
	challenge := hexMustDecode("63acd6e02a8b5783551ff2836a9cbdf237c115c3ff018b943f044e6a69b19fe7")
	response := hexMustDecode("a081ab8a620365c18485fe7018e11cb992011426803aa8e843c63aab9657aed7d3ee4b85a62a11188ada267db3312a84e1be27c01c736a89da7a1fe4f7e90ce297e74f00008e2bfdb06058374abfc1c026386d16ead7bbc19bc0645d2e7acf7b953169bbc1ac0130450220364c5ca937b7ca42861978f086d206cc569ef0bb2ea4c7de08929c2fcca7434d022100c87699ce4f977e6a7a4800343db9b6842b91ca873e56dfe3327d19a2d01af14e")
	expectedKey := hexMustDecode("02fc929321aa94fea085b166994aa66590116252cf0235a03accaa2c8ab4595de5")

	pubkey, err := VerifyIdentity(challenge, response)
	assert.NoError(t, err)
	assert.Equal(t, expectedKey, pubkey)
}
