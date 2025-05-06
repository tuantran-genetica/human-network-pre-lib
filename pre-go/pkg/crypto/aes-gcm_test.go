package crypto_test

import (
	"crypto/rand"
	"testing"

	"github.com/lifenetwork-ai/proxy-recrypt-sdk/pre-go/pkg/crypto"
	"github.com/stretchr/testify/require"
)

func TestAESGCM(t *testing.T) {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)

	message := []byte("hello, world")
	ciphertext, err := crypto.EncryptAESGCM(message, key, nil)

	require.NoError(t, err)

	plaintext, err := crypto.DecryptAESGCM(ciphertext, key)
	require.NoError(t, err)

	require.Equal(t, message, plaintext)
}

func TestAESGCMErrors(t *testing.T) {
	t.Run("invalid key size", func(t *testing.T) {
		_, err := crypto.EncryptAESGCM([]byte("test"), []byte("invalid"), nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid key size")
	})

	t.Run("decrypt with invalid ciphertext", func(t *testing.T) {
		key := make([]byte, 32)
		_, err := crypto.DecryptAESGCM([]byte("invalid"), key)
		require.Error(t, err)
		require.Contains(t, err.Error(), "ciphertext too short")
	})

	t.Run("decrypt with invalid key", func(t *testing.T) {
		message := []byte("test message")
		key := make([]byte, 32)
		ciphertext, err := crypto.EncryptAESGCM(message, key, nil)
		require.NoError(t, err)

		_, err = crypto.DecryptAESGCM(ciphertext, nil)
		require.Error(t, err)
	})
}
