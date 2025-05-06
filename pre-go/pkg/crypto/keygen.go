package crypto

import (
	"fmt"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/lifenetwork-ai/proxy-recrypt-sdk/pre-go/pkg/pre/utils"
)

// GenerateRandomSymmetricKeyFromGT creates a new symmetric key of specified size (16, 24, or 32 bytes)
// by first generating a random element in the GT group and then deriving a symmetric key from it.
// The function returns:
//   - The random GT element that can be used to recreate the key
//   - The derived symmetric key of specified size
//   - An error if key generation or derivation fails
//
// Valid key sizes are:
//   - 16 bytes for AES-128
//   - 24 bytes for AES-192
//   - 32 bytes for AES-256
func GenerateRandomSymmetricKeyFromGT(keySize int) (*bn254.GT, []byte, error) {
	// Validate key size
	if keySize != 16 && keySize != 24 && keySize != 32 {
		return nil, nil, fmt.Errorf("invalid key size: must be 16, 24, or 32 bytes")
	}

	// Generate random GT element
	randomGT, err := new(bn254.GT).SetRandom()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate random GT element: %v", err)
	}

	// Derive key from a point in GT
	symmetricKey, err := utils.DeriveKeyFromGT(randomGT, keySize)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to derive key: %v", err)
	}

	return randomGT, symmetricKey, nil
}
