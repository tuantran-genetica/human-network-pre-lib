package utils_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/lifenetwork-ai/proxy-recrypt-sdk/pre-go/pkg/pre/utils"
	"github.com/lifenetwork-ai/proxy-recrypt-sdk/pre-go/pkg/testutils"
	"github.com/stretchr/testify/require"
)

func TestUtilityFunctions(t *testing.T) {
	t.Run("GenerateRandomString", func(t *testing.T) {
		str1 := testutils.GenerateRandomString(32)
		str2 := testutils.GenerateRandomString(32)
		require.Len(t, str1, 32)
		require.Len(t, str2, 32)
		require.NotEqual(t, str1, str2)
	})

	t.Run("WriteAsBase64IfNotExists with existing file", func(t *testing.T) {
		tmpFile := filepath.Join(t.TempDir(), "test.txt")
		originalData := []byte("original")
		require.NoError(t, os.WriteFile(tmpFile, originalData, 0o600))

		newData := []byte("new")
		err := testutils.WriteAsBase64IfNotExists(tmpFile, newData)
		require.NoError(t, err)

		content, err := os.ReadFile(tmpFile)
		require.NoError(t, err)
		require.Equal(t, originalData, content)
	})
}

func TestDeriveKeyErrors(t *testing.T) {
	t.Run("invalid GT element", func(t *testing.T) {
		_, err := utils.DeriveKeyFromGT(nil, 32)
		require.Error(t, err)
	})

	t.Run("invalid key size", func(t *testing.T) {
		gtElem := testutils.GenerateRandomGTElem()
		_, err := utils.DeriveKeyFromGT(gtElem, 15)
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid key size")
	})
}

func TestSystemParameters(t *testing.T) {
	g1, g2, Z := utils.GenerateSystemParameters()
	require.NotNil(t, g1)
	require.NotNil(t, g2)
	require.NotNil(t, Z)

	// Verify that Z = e(g1, g2)
	computed, err := bn254.Pair([]bn254.G1Affine{*g1}, []bn254.G2Affine{*g2})
	require.NoError(t, err)
	require.Equal(t, *Z, computed)
}
