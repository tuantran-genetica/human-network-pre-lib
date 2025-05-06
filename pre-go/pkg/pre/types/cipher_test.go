package types_test

import (
	"testing"

	"github.com/lifenetwork-ai/proxy-recrypt-sdk/pre-go/pkg/pre/types"
	"github.com/lifenetwork-ai/proxy-recrypt-sdk/pre-go/pkg/testutils"
	"github.com/stretchr/testify/require"
)

func TestToAndFromBytes(t *testing.T) {
	firstLevelSymKey := &types.FirstLevelSymmetricKey{
		First:  testutils.GenerateRandomGTElem(),
		Second: testutils.GenerateRandomGTElem(),
	}

	firstLevelBytes := firstLevelSymKey.ToBytes()
	recoveredFirstLevelSymKey := new(types.FirstLevelSymmetricKey).FromBytes(firstLevelBytes)

	require.Equal(t, firstLevelSymKey, recoveredFirstLevelSymKey)
}

func TestToAndFromBytesSecondLevel(t *testing.T) {
	secondLevelSymKey := &types.SecondLevelSymmetricKey{
		First:  testutils.GenerateRandomG1Elem(),
		Second: testutils.GenerateRandomGTElem(),
	}

	secondLevelBytes := secondLevelSymKey.ToBytes()
	recoveredSecondLevelSymKey := new(types.SecondLevelSymmetricKey).FromBytes(secondLevelBytes)

	require.Equal(t, secondLevelSymKey, recoveredSecondLevelSymKey)
}

func TestCipherErrors(t *testing.T) {
	t.Run("FirstLevelSymmetricKey nil receiver", func(t *testing.T) {
		var key *types.FirstLevelSymmetricKey
		err := key.FromString("invalid")
		require.Error(t, err)
		require.Contains(t, err.Error(), "nil receiver")
	})

	t.Run("FirstLevelSymmetricKey invalid hex", func(t *testing.T) {
		key := &types.FirstLevelSymmetricKey{}
		err := key.FromString("invalid hex")
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to decode hex string")
	})

	t.Run("SecondLevelSymmetricKey nil receiver", func(t *testing.T) {
		var key *types.SecondLevelSymmetricKey
		err := key.FromString("invalid")
		require.Error(t, err)
		require.Contains(t, err.Error(), "nil receiver")
	})

	t.Run("SecondLevelSymmetricKey invalid data length", func(t *testing.T) {
		key := &types.SecondLevelSymmetricKey{}
		err := key.FromString("1234")
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid data length")
	})
}
