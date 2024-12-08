package crypto

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGeneratePrivateKey(t *testing.T) {
	privKey := GeneratePrivateKey()
	assert.Equal(t, len(privKey.Bytes()), privKeyLen)

	pubKey := privKey.Public()
	assert.Equal(t, len(pubKey.Bytes()), pubKeyLen)
}

func TestPrivateKeySign(t *testing.T) {
	privKey := GeneratePrivateKey()
	pubKey := privKey.Public()
	msg := []byte("foo bar baz")

	sig := privKey.Sign(msg)
	assert.True(t, sig.Verify(pubKey, msg))

	// Test with wrong message
	assert.False(t, sig.Verify(pubKey, []byte("foo")))

	// Test with invalid pubKey
	invalidPrivKey := GeneratePrivateKey()
	invalidPubKey := invalidPrivKey.Public()
	assert.False(t, sig.Verify(invalidPubKey, msg))
}

func TestPublicKeyToAddress(t *testing.T) {
	privKey := GeneratePrivateKey()
	pubKey := privKey.Public()
	address := pubKey.Address()
	t.Log(address.Bytes())
	t.Log(address)
	assert.Equal(t, addressLen, len(address.Bytes()))
}

func TestNewPrivateKeyFromString(t *testing.T) {
	var (
		seed       = "7a6365ff7b56ca93c5587a01987915e0b7c895fbd8b817dd3acd7be6a0bec8bb"
		privKey    = NewPrivateKeyFromString(seed)
		addressStr = "4c9e9cf221202683c9cf7ecd4f3a5b8c601b92f3"
	)
	assert.Equal(t, len(privKey.Bytes()), privKeyLen)
	address := privKey.Public().Address()
	assert.Equal(t, address.String(), addressStr)
}
