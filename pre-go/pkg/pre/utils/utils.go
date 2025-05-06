package utils

import (
	"crypto/sha256"
	"fmt"
	"io"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/lifenetwork-ai/proxy-recrypt-sdk/pre-go/pkg/pre/types"
	"golang.org/x/crypto/hkdf"
)

// generateSystemParameters returns the system parameters for pairing-based cryptography:
// - g1: Generator point of G1 group (in affine coordinates)
// - g2: Generator point of G2 group (in affine coordinates)
// - Z: Pairing result e(g1,g2) which generates the target group GT
//
// These parameters are foundational for constructing pairing-based cryptographic schemes.
// The generators g1 and g2 are obtained from the BN254 curve's built-in generators,
// and Z is computed as their pairing.
func GenerateSystemParameters() (*bn254.G1Affine, *bn254.G2Affine, *bn254.GT) {
	_, _, g1, g2 := bn254.Generators()

	Z, _ := bn254.Pair([]bn254.G1Affine{g1}, []bn254.G2Affine{g2})

	return &g1, &g2, &Z
}

func SecretToPubkey(secret *types.SecretKey, g *bn254.G2Affine, Z *bn254.GT) *types.PublicKey {
	return &types.PublicKey{
		First:  new(bn254.GT).Exp(*Z, secret.First),
		Second: new(bn254.G2Affine).ScalarMultiplication(g, secret.Second),
	}
}

// DeriveKeyFromGT derives a symmetric key of specified size (16, 24, or 32 bytes) from a bn254.GT element.
// The function returns the derived symmetric key or an error if derivation fails.
func DeriveKeyFromGT(gtElement *bn254.GT, keySize int) ([]byte, error) {
	// Validate inputs
	if gtElement == nil {
		return nil, fmt.Errorf("GT element is nil")
	}
	if keySize != 16 && keySize != 24 && keySize != 32 {
		return nil, fmt.Errorf("invalid key size: must be 16, 24, or 32 bytes")
	}

	// Get bytes from GT element
	gtBytes := gtElement.Bytes()
	if len(gtBytes) == 0 {
		return nil, fmt.Errorf("failed to get bytes from GT element")
	}

	salt := []byte("PRE_derive_key")

	// Use HKDF to derive the key
	hkdf := hkdf.New(sha256.New,
		gtBytes[:],                  // Input keying material
		salt,                        // Salt (optional)
		[]byte("PRE_symmetric_key"), // Info (context)
	)

	// Extract the key
	symmetricKey := make([]byte, keySize)
	if _, err := io.ReadFull(hkdf, symmetricKey); err != nil {
		return nil, fmt.Errorf("failed to derive key: %v", err)
	}

	if len(symmetricKey) != keySize {
		return nil, fmt.Errorf("derived key is not the expected size")
	}

	return symmetricKey, nil
}
