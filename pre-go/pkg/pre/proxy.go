package pre

import (
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/lifenetwork-ai/proxy-recrypt-sdk/pre-go/pkg/pre/types"
)

type preProxy struct{}

// NewProxy creates a new proxy
func NewProxy() types.PreProxy {
	return &preProxy{}
}

// ReEncryption performs the re-encryption operation for the PRE scheme.
// It re-encrypts the ciphertext under the re-encryption key.
// It takes the second-level ciphertext and the re-encryption key as input.
// It returns the re-encrypted(first-level) ciphertext.
func (p *preProxy) ReEncryption(encryptedKey *types.SecondLevelSymmetricKey, reKey *bn254.G2Affine) *types.FirstLevelSymmetricKey {
	// compute the re-encryption of the key
	first, err := bn254.Pair([]bn254.G1Affine{*encryptedKey.First}, []bn254.G2Affine{*reKey})
	if err != nil {
		panic("error in re-encryption")
	}

	newEncryptedKey := &types.FirstLevelSymmetricKey{
		First:  &first,
		Second: encryptedKey.Second,
	}

	return newEncryptedKey
}
