package types

import (
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254"
)

// Type aliases for cryptographic primitives
type (
	GT       = bn254.GT
	G1Affine = bn254.G1Affine
	G2Affine = bn254.G2Affine
	Int      = big.Int
)

// KeyPair represents the key pair components for the PRE scheme
type KeyPair struct {
	PublicKey *PublicKey
	SecretKey *SecretKey
}

// PublicKey represents the public key components for the PRE scheme
type PublicKey struct {
	First  *GT
	Second *G2Affine
}

// SecretKey represents the secret key components for the PRE scheme
type SecretKey struct {
	First  *big.Int
	Second *big.Int
}

// FirstLevelCipherText represents the second level encrypted message components
type FirstLevelCipherText struct {
	First            *GT
	Second           *GT
	EncryptedMessage string
}

// SecondLevelCipherText represents the first level encrypted message components
type SecondLevelCipherText struct {
	First            *G1Affine
	Second           *GT
	EncryptedMessage string
}

// PreScheme defines the interface for proxy re-encryption operations
type PreScheme interface {
	GenerateRandomSymmetricKey() *Int
	GenerateReEncryptionKey(secretA *Int, publicB *G2Affine) *bn254.G2Affine
	SecondLevelEncryption(pubkeyA *GT, secretB *Int, message *GT, scalar *Int) *SecondLevelCipherText
}
