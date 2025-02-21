package pre

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/tuantran-genetica/human-network-crypto-lib/pkg/crypto"
	"github.com/tuantran-genetica/human-network-crypto-lib/pkg/pre/types"
	"github.com/tuantran-genetica/human-network-crypto-lib/pkg/pre/utils"
)

// preScheme implements the PreScheme interface
type preScheme struct {
	G1 *bn254.G1Affine
	G2 *bn254.G2Affine
	Z  *bn254.GT
}

// var _ types.PreScheme = (*preScheme)(nil)

// NewPreScheme creates a new instance of preScheme with generated system parameters
func NewPreScheme() *preScheme {
	g1, g2, Z := utils.GenerateSystemParameters()
	return &preScheme{
		G1: &g1,
		G2: &g2,
		Z:  &Z,
	}
}

// GenerateReEncryptionKey generates a re-encryption key indicate A->B relation for the PRE scheme.
// It takes the public key of A and a portion of secret key of B as input.
// The re-encryption key is a point in G1 group.
func (p *preScheme) GenerateReEncryptionKey(secretA *big.Int, publicB *bn254.G2Affine) *bn254.G2Affine {
	return publicB.ScalarMultiplicationBase(secretA)
}

// SecondLevelEncryption performs the second level encryption for the PRE scheme.
// It encrypts a message m ∈ GT under pkA such that it can be decrypted by A and delegatees.
// It takes the public key of A, a portion of secret key of B, the message m and a random scalar as input.
// The scalar is used to randomize the encryption, should not be reused in other sessions.
// It returns the ciphertext in the form of a pair of points in G1 and GT groups.
func (p *preScheme) SecondLevelEncryption(pubkeyA *bn254.GT, secretB *big.Int, message string, scalar *big.Int) *types.SecondLevelCipherText {

	// generate random symmetric key
	keyGT, key, _ := crypto.GenerateRandomSymmetricKeyFromGT(32)
	// encrypt the message
	encryptedMessage, err := crypto.EncryptAESGCM(message, key)

	if err != nil {
		panic("error in encryption")
	}

	first := p.G1.ScalarMultiplicationBase(scalar)
	secondTemp := new(bn254.GT).Exp(*pubkeyA, scalar)
	second := new(bn254.GT).Mul(secondTemp, keyGT)

	encryptedKey := &types.SecondLevelSymmetricKey{
		First:  first,
		Second: second,
	}
	return &types.SecondLevelCipherText{
		EncryptedKey:     encryptedKey,
		EncryptedMessage: encryptedMessage,
	}
}

// ReEncryption performs the re-encryption operation for the PRE scheme.
// It re-encrypts the ciphertext under the re-encryption key.
// It takes the second-level ciphertext and the re-encryption key as input.
// It returns the re-encrypted(first-level) ciphertext.
func (p *preScheme) ReEncryption(ciphertext *types.SecondLevelCipherText, reKey *bn254.G2Affine, pubKeyB bn254.G2Affine) *types.FirstLevelCipherText {
	// compute the re-encryption
	first, err := bn254.Pair([]bn254.G1Affine{*ciphertext.EncryptedKey.First}, []bn254.G2Affine{*reKey})
	if err != nil {
		panic("error in re-encryption")
	}

	newEncryptedKey := &types.FirstLevelSymmetricKey{
		First:  &first,
		Second: ciphertext.EncryptedKey.Second,
	}

	return &types.FirstLevelCipherText{
		EncryptedKey:     newEncryptedKey,
		EncryptedMessage: ciphertext.EncryptedMessage,
	}
}

// Convert the secret key to public key in the PRE scheme.
func (p *preScheme) SecretToPubkey(secret *types.SecretKey) *types.PublicKey {
	return utils.SecretToPubkey(secret, p.G2, p.Z)
}

// Decrypt first-level ciphertext
func (p *preScheme) DecryptFirstLevel(ciphertext *types.FirstLevelCipherText, secretKey *types.SecretKey) string {
	symmetricKey, err := p.decryptFirstLevelKey(ciphertext.EncryptedKey, secretKey)

	if err != nil {
		panic("error in deriving key")
	}

	decryptedMessage, _ := crypto.DecryptAESGCM(ciphertext.EncryptedMessage, symmetricKey)
	return decryptedMessage
}

// Decrypt first-level encrypted symmetric key
func (p *preScheme) decryptFirstLevelKey(encryptedKey *types.FirstLevelSymmetricKey, secretKey *types.SecretKey) ([]byte, error) {
	temp := new(bn254.GT).Exp(*encryptedKey.First, new(big.Int).ModInverse(big.NewInt(1), secretKey.Second))

	symmetricKeyGT := new(bn254.GT).Div(encryptedKey.Second, temp)

	symmetricKey, err := crypto.DeriveKeyFromGT(symmetricKeyGT, 32)

	if err != nil {
		return nil, fmt.Errorf("failed to derive key: %v", err)
	}

	return symmetricKey, nil
}
