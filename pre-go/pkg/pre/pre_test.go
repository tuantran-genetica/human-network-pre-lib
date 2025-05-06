package pre_test

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/lifenetwork-ai/proxy-recrypt-sdk/pre-go/pkg/pre"
	"github.com/lifenetwork-ai/proxy-recrypt-sdk/pre-go/pkg/pre/mocks"
	"github.com/lifenetwork-ai/proxy-recrypt-sdk/pre-go/pkg/pre/types"
	"github.com/lifenetwork-ai/proxy-recrypt-sdk/pre-go/pkg/pre/utils"
	"github.com/lifenetwork-ai/proxy-recrypt-sdk/pre-go/pkg/testutils"
	"github.com/stretchr/testify/require"
)

func TestPreFullFlow(t *testing.T) {
	// Generate system parameters
	scheme := pre.NewPreScheme()
	// Test setup
	// Generate key pair for Alice and Bob
	keyPairAlice := testutils.GenerateRandomKeyPair(scheme.Params.G2, scheme.Params.Z)
	keyPairBob := testutils.GenerateRandomKeyPair(scheme.Params.G2, scheme.Params.Z)

	// Alice side
	// Generate re-encryption key for Alice->Bob
	reKey := scheme.Client.GenerateReEncryptionKey(keyPairAlice.SecretKey, keyPairBob.PublicKey)
	// Alice encrypt a message
	message := "Life is full of unexpected moments that shape who we become. Each day brings new opportunities to learn, grow, and discover something amazing about ourselves and the world around us. When we embrace these challenges with an open mind and willing heart, we find strength we never knew we had. Remember that every step forward, no matter how small, is progress toward your dreams today."
	encryptedKey, encryptedMessage, err := scheme.Client.SecondLevelEncryption(keyPairAlice.SecretKey, message, testutils.GenerateRandomScalar())
	require.NoError(t, err)

	// Proxy side
	// Re-encrypt the message for Bob
	firstLevelCipherText := scheme.Proxy.ReEncryption(encryptedKey, reKey)

	// Bob side
	// Decrypt the message
	decryptedMessage := scheme.Client.DecryptFirstLevel(firstLevelCipherText, encryptedMessage, keyPairBob.SecretKey)

	require.Equal(t, message, decryptedMessage)
}

func TestMockPreFullFlow(t *testing.T) {
	scheme := mocks.NewMockPreScheme()
	// Test setup
	// Generate key pair for Alice and Bob
	keyPairAlice := scheme.AliceKeyPair
	keyPairBob := scheme.BobKeyPair

	// Alice side
	// Generate re-encryption key for Alice->Bob
	reKey := scheme.GenerateReEncryptionKey(keyPairAlice.SecretKey, keyPairBob.PublicKey)
	reKeyBytes := reKey.RawBytes()
	require.Equal(t, reKeyBytes, scheme.ReKey.RawBytes())

	encryptedKey, encryptedMessage, err := scheme.SecondLevelEncryption(keyPairAlice.SecretKey, string(scheme.Message), scheme.Scalar)
	require.NoError(t, err)

	// Persist the encrypted key
	SecondLevelEncryptedKeyFirstBytes := encryptedKey.First.RawBytes()
	SecondLevelEncryptedKeySecondBytes := encryptedKey.Second.Bytes()
	err = testutils.WriteAsBase64IfNotExists("../../../testdata/second_encrypted_key_first.txt", SecondLevelEncryptedKeyFirstBytes[:])
	require.NoError(t, err)
	err = testutils.WriteAsBase64IfNotExists("../../../testdata/second_encrypted_key_second.txt", SecondLevelEncryptedKeySecondBytes[:])
	require.NoError(t, err)

	// Proxy side
	// Re-encrypt the message for Bob
	firstLevelEncryptedKey := scheme.ReEncryption(encryptedKey, reKey)
	firstLevelEncryptedKeyFirstBytes := firstLevelEncryptedKey.First.Bytes()
	firstLevelEncryptedKeySecondBytes := firstLevelEncryptedKey.Second.Bytes()

	// Persist the re-encrypted key
	err = testutils.WriteAsBase64IfNotExists("../../../testdata/first_encrypted_key_first.txt", firstLevelEncryptedKeyFirstBytes[:])
	require.NoError(t, err)
	err = testutils.WriteAsBase64IfNotExists("../../../testdata/first_encrypted_key_second.txt", firstLevelEncryptedKeySecondBytes[:])
	require.NoError(t, err)

	// Bob side
	// Decrypt the message
	decryptedMessage := scheme.DecryptFirstLevel(firstLevelEncryptedKey, encryptedMessage, keyPairBob.SecretKey)
	require.Equal(t, string(scheme.Message), decryptedMessage)

	// Alice side
	// Decrypt her own message
	decryptedMessageAlice := scheme.DecryptSecondLevel(encryptedKey, encryptedMessage, keyPairAlice.SecretKey)
	require.Equal(t, string(scheme.Message), decryptedMessageAlice)
}

func TestGenerateKeyPair(t *testing.T) {
	scheme := pre.NewPreScheme()

	sk := &types.SecretKey{
		First:  testutils.GenerateRandomScalar(),
		Second: testutils.GenerateRandomScalar(),
	}

	pk := utils.SecretToPubkey(sk, scheme.Params.G2, scheme.Params.Z)

	// Pk(Z^a1, g2^a2)

	require.Equal(t, pk.First, new(bn254.GT).Exp(*scheme.Params.Z, sk.First))
	require.Equal(t, pk.Second, new(bn254.G2Affine).ScalarMultiplication(scheme.Params.G2, sk.Second))
}

func TestPreSchemeErrors(t *testing.T) {
	scheme := pre.NewPreScheme()

	t.Run("SecondLevelEncryption with invalid scalar", func(t *testing.T) {
		// Use scalar larger than curve order
		invalidScalar := new(big.Int).Add(bn254.ID.ScalarField(), big.NewInt(1))
		_, _, err := scheme.Client.SecondLevelEncryption(nil, "test", invalidScalar)
		require.Error(t, err)
		require.Contains(t, err.Error(), "scalar is out of range")
	})

	t.Run("DecryptFirstLevel with nil inputs", func(t *testing.T) {
		require.Panics(t, func() {
			scheme.Client.DecryptFirstLevel(nil, nil, nil)
		})
	})
}

func TestPreSchemeAdditional(t *testing.T) {
	scheme := pre.NewPreScheme()

	t.Run("DecryptSecondLevel with invalid inputs", func(t *testing.T) {
		message := "test message"
		keyPair := testutils.GenerateRandomKeyPair(scheme.Params.G2, scheme.Params.Z)
		encryptedKey, encryptedMessage, err := scheme.Client.SecondLevelEncryption(
			keyPair.SecretKey,
			message,
			testutils.GenerateRandomScalar(),
		)
		require.NoError(t, err)

		// Try decrypting with wrong secret key
		wrongKeyPair := testutils.GenerateRandomKeyPair(scheme.Params.G2, scheme.Params.Z)
		decrypted := scheme.Client.DecryptSecondLevel(encryptedKey, encryptedMessage, wrongKeyPair.SecretKey)
		require.NotEqual(t, message, decrypted)
	})

	t.Run("ReEncryption with invalid inputs", func(t *testing.T) {
		require.Panics(t, func() {
			scheme.Proxy.ReEncryption(nil, nil)
		})
	})
}
