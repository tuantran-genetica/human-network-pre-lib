package testutils

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"math/big"
	"os"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/lifenetwork-ai/proxy-recrypt-sdk/pre-go/pkg/pre/types"
	"github.com/lifenetwork-ai/proxy-recrypt-sdk/pre-go/pkg/pre/utils"
)

// generateSystemParameters returns the system parameters for pairing-based cryptography:
// - g1: Generator point of G1 group (in affine coordinates)
// - g2: Generator point of G2 group (in affine coordinates)
// - Z: Pairing result e(g1,g2) which generates the target group GT
//
// These parameters are foundational for constructing pairing-based cryptographic schemes.
// The generators g1 and g2 are obtained from the BN254 curve's built-in generators,
// and Z is computed as their pairing.
func GenerateSystemParameters() (g1 bn254.G1Affine, g2 bn254.G2Affine, Z bn254.GT) {
	_, _, g1, g2 = bn254.Generators()

	Z, _ = bn254.Pair([]bn254.G1Affine{g1}, []bn254.G2Affine{g2})

	return g1, g2, Z
}

// GenerateRandomKeyPair generates a random key pair for the PRE scheme.
// It returns a random key pair with a random public key and secret key.
// The public key is generated from the secret key using the system parameters g and Z.
func GenerateRandomKeyPair(g *bn254.G2Affine, Z *bn254.GT) *types.KeyPair {
	sk := &types.SecretKey{
		First:  GenerateRandomScalar(),
		Second: GenerateRandomScalar(),
	}

	pk := utils.SecretToPubkey(sk, g, Z)

	return &types.KeyPair{
		PublicKey: pk,
		SecretKey: sk,
	}
}

func GenerateRandomScalar() *big.Int {
	// Get the order of BN254 curve
	order := bn254.ID.ScalarField()
	// Generate random scalar in [0, order-1]
	scalar, _ := rand.Int(rand.Reader, order)
	return scalar
}

func GenerateRandomGTElem() *bn254.GT {
	elem, _ := new(bn254.GT).SetRandom()
	return elem
}

func GenerateRandomG1Elem() *bn254.G1Affine {
	_, _, g1, _ := bn254.Generators()
	randomScalar := GenerateRandomScalar()
	elem := g1.ScalarMultiplicationBase(randomScalar)
	return elem
}

func GenerateRandomG2Elem() *bn254.G2Affine {
	_, _, _, g2 := bn254.Generators()
	randomScalar := GenerateRandomScalar()
	elem := g2.ScalarMultiplicationBase(randomScalar)
	return elem
}

func GenerateMockSecondLevelCipherText(_ int) *types.SecondLevelSymmetricKey {
	return &types.SecondLevelSymmetricKey{
		First:  GenerateRandomG1Elem(),
		Second: GenerateRandomGTElem(),
	}
}

func GenerateMockNonce() []byte {
	return []byte{223, 226, 69, 90, 252, 126, 59, 176, 98, 14, 194, 123}
}

// GenerateRandomString creates a cryptographically secure random string of fixed length
func GenerateRandomString(length int) string {
	// Calculate number of bytes needed for requested length
	// Each byte becomes 2 hex characters
	bytes := make([]byte, (length+1)/2)

	// Generate random bytes using crypto/rand
	if _, err := rand.Read(bytes); err != nil {
		return ""
	}

	// Convert to hex string and trim to exact length
	return hex.EncodeToString(bytes)[:length]
}

func WriteAsBase64IfNotExists(filename string, data []byte) error {
	_, err := os.Stat(filename)
	if os.IsNotExist(err) {
		base64Form := base64.StdEncoding.EncodeToString(data)
		return os.WriteFile(filename, []byte(base64Form), 0o600)
	}
	return nil
}
