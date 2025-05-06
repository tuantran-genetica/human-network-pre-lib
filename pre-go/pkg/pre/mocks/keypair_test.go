package mocks_test

import (
	"os"
	"testing"

	"github.com/lifenetwork-ai/proxy-recrypt-sdk/pre-go/pkg/testutils"
	"github.com/stretchr/testify/require"
)

func TestSerializeDeserializeKeyPair(t *testing.T) {
	// Create a temporary file for testing
	tmpFile, err := os.CreateTemp(".", "keypair_test_*.json")
	require.NoError(t, err)
	defer os.Remove(tmpFile.Name()) // Clean up after test

	// Save a keypair to the file
	err = testutils.SaveKeyPairToFile(tmpFile.Name())
	require.NoError(t, err)

	// Load the keypair from the file
	loadedKeyPair, err := testutils.LoadKeyPairFromFile(tmpFile.Name())
	require.NoError(t, err)

	// Verify that the loaded keypair is valid
	require.NotNil(t, loadedKeyPair)
	require.NotNil(t, loadedKeyPair.PublicKey)
	require.NotNil(t, loadedKeyPair.SecretKey)
	require.NotNil(t, loadedKeyPair.PublicKey.First)
	require.NotNil(t, loadedKeyPair.PublicKey.Second)
}
