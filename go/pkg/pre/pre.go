package pre

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/tuantran-genetica/human-network-crypto-lib/pkg/pre/types"
	"github.com/tuantran-genetica/human-network-crypto-lib/pkg/pre/utils"
)

// preScheme implements the PreScheme interface
type preScheme struct {
	G1 *types.G1Affine
	G2 *types.G2Affine
	Z  *types.GT
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

// GenerateRandomSymmetricKey generates a random symmetric key for the PRE scheme.
// It returns a random scalar value.

func (p *preScheme) GenerateRandomSymmetricKeyFromGT(keySize int) (types.GT, []byte, error) {
	randomGT, _ := new(types.GT).SetRandom()
	randomGTBytes := randomGT.Bytes()
	symmetricKey := randomGTBytes[:keySize]

	return *randomGT, symmetricKey, nil

}

// GenerateReEncryptionKey generates a re-encryption key indicate A->B relation for the PRE scheme.
// It takes the public key of A and a portion of secret key of B as input.
// The re-encryption key is a point in G1 group.
func (p *preScheme) GenerateReEncryptionKey(secretA *types.Int, publicB *types.G2Affine) *bn254.G2Affine {
	return publicB.ScalarMultiplicationBase(secretA)
}

// SecondLevelEncryption performs the second level encryption for the PRE scheme.
// It encrypts a message m ∈ GT under pkA such that it can be decrypted by A and delegatees.
// It takes the public key of A, a portion of secret key of B, the message m and a random scalar as input.
// The scalar is used to randomize the encryption, should not be reused in other sessions.
// It returns the ciphertext in the form of a pair of points in G1 and GT groups.
func (p *preScheme) SecondLevelEncryption(pubkeyA *types.GT, secretB *types.Int, message string, scalar *types.Int) *types.SecondLevelCipherText {

	// generate random symmetric key
	keyGT, key, _ := p.GenerateRandomSymmetricKeyFromGT(32)
	// encrypt the message
	encryptedMessage, _ := utils.SymmetricEncrypt(message, key)

	first := p.G1.ScalarMultiplicationBase(scalar)

	secondTemp := new(bn254.GT).Exp(*pubkeyA, scalar)

	second := new(bn254.GT).Mul(secondTemp, &keyGT)

	return &types.SecondLevelCipherText{
		First:            first,
		Second:           second,
		EncryptedMessage: encryptedMessage,
	}
}

// ReEncryption performs the re-encryption operation for the PRE scheme.
// It re-encrypts the ciphertext under the re-encryption key.
// It takes the second-level ciphertext and the re-encryption key as input.
// It returns the re-encrypted(first-level) ciphertext.
func (p *preScheme) ReEncryption(ciphertext *types.SecondLevelCipherText, reKey *types.G2Affine, pubKeyB types.G2Affine) *types.FirstLevelCipherText {
	// compute the re-encryption
	first, err := bn254.Pair([]bn254.G1Affine{*ciphertext.First}, []bn254.G2Affine{*reKey})
	if err != nil {
		panic("error in re-encryption")
	}
	return &types.FirstLevelCipherText{
		First:            &first,
		Second:           ciphertext.Second,
		EncryptedMessage: ciphertext.EncryptedMessage,
	}
}

// Convert the secret key to public key in the PRE scheme.
func (p *preScheme) SecretToPubkey(secret *types.SecretKey) *types.PublicKey {
	return utils.SecretToPubkey(secret, p.G2, p.Z)
}

// Decrypt first-level ciphertext
func (p *preScheme) DecryptFirstLevel(ciphertext *types.FirstLevelCipherText, secretKey *types.SecretKey) string {
	temp := new(types.GT).Exp(*ciphertext.First, new(big.Int).ModInverse(big.NewInt(1), secretKey.Second))

	symmetricKeyGT := new(types.GT).Div(ciphertext.Second, temp)
	symmetricKeyBytes := symmetricKeyGT.Bytes()

	symmetricKey := symmetricKeyBytes[:32]
	fmt.Println("decrypted symmetric key: ", symmetricKey)
	decryptedMessage, _ := utils.SymmetricDecrypt(ciphertext.EncryptedMessage, symmetricKey)
	return decryptedMessage
}
