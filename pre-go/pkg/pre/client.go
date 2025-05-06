package pre

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/lifenetwork-ai/proxy-recrypt-sdk/pre-go/pkg/crypto"
	"github.com/lifenetwork-ai/proxy-recrypt-sdk/pre-go/pkg/pre/types"
	"github.com/lifenetwork-ai/proxy-recrypt-sdk/pre-go/pkg/pre/utils"
)

// preScheme implements the PreScheme interface
type preClient struct {
	Params types.SystemParams
}

var _ types.PreClient = (*preClient)(nil)

// NewPreScheme creates a new instance of preScheme with generated system parameters
func NewClient(params types.SystemParams) types.PreClient {
	return &preClient{
		Params: params,
	}
}

// GenerateReEncryptionKey generates a re-encryption key indicate A->B relation for the PRE scheme.
// It takes the a portion of secret key of A and a portion of public key of B as input.
// The re-encryption key is a point in G1 group.
func (p *preClient) GenerateReEncryptionKey(secretA *types.SecretKey, publicB *types.PublicKey) *types.ReEncryptionKey {
	return new(bn254.G2Affine).ScalarMultiplication(publicB.Second, secretA.First)
}

// SecondLevelEncryption performs the second level encryption for the PRE scheme.
// It encrypts a message m ∈ GT under pkA such that it can be decrypted by A and delegatees.
// It takes the public key of A, a portion of secret key of B, the message m and a random scalar as input.
// The scalar is used to randomize the encryption, should not be reused in other sessions.
// It returns the ciphertext in the form of a pair of points in G1 and GT groups.
func (p *preClient) SecondLevelEncryption(secretA *types.SecretKey, message string, scalar *types.Scalar) (*types.SecondLevelSymmetricKey, []byte, error) {
	// check if scalar is in the correct range
	if scalar.Cmp(bn254.ID.ScalarField()) >= 0 {
		return nil, nil, fmt.Errorf("scalar is out of range")
	}

	// generate random symmetric key
	keyGT, key, err := crypto.GenerateRandomSymmetricKeyFromGT(32)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate random key: %v", err)
	}

	// encrypt the message
	encryptedMessage, err := crypto.EncryptAESGCM([]byte(message), key, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to encrypt message: %v", err)
	}

	// g1^k
	first := new(bn254.G1Affine).ScalarMultiplication(p.Params.G1, scalar)

	// m*Z^(a1*k)
	secondTemp1 := new(bn254.GT).Exp(*p.Z(), secretA.First)
	secondTemp := new(bn254.GT).Exp(*secondTemp1, scalar)
	second := new(bn254.GT).Mul(keyGT, secondTemp)

	encryptedKey := &types.SecondLevelSymmetricKey{
		First:  first,
		Second: second,
	}

	return encryptedKey, encryptedMessage, nil
}

// Convert the secret key to public key in the PRE scheme.
func (p *preClient) SecretToPubkey(secret *types.SecretKey) *types.PublicKey {
	return utils.SecretToPubkey(secret, p.Params.G2, p.Params.Z)
}

// Decrypt with first-level encrypted key
func (p *preClient) DecryptFirstLevel(encryptedKey *types.FirstLevelSymmetricKey, encryptedMessage []byte, secretKey *types.SecretKey) string {
	symmetricKey, err := p.decryptFirstLevelKey(encryptedKey, secretKey)
	if err != nil {
		panic("error in deriving key")
	}

	decryptedMessage, _ := crypto.DecryptAESGCM(encryptedMessage, symmetricKey)
	return string(decryptedMessage)
}

// Decrypt with second-level encrypted key
func (p *preClient) DecryptSecondLevel(encryptedKey *types.SecondLevelSymmetricKey, encryptedMessage []byte, secretKey *types.SecretKey) string {
	symmetricKey, err := p.decryptSecondLevelKey(encryptedKey, secretKey)
	if err != nil {
		panic("error in deriving key")
	}

	decryptedMessage, _ := crypto.DecryptAESGCM(encryptedMessage, symmetricKey)
	return string(decryptedMessage)
}

// Decrypt first-level encrypted symmetric key
func (p *preClient) decryptFirstLevelKey(encryptedKey *types.FirstLevelSymmetricKey, secretKey *types.SecretKey) ([]byte, error) {
	order := bn254.ID.ScalarField()
	temp := new(bn254.GT).Exp(*encryptedKey.First, new(big.Int).ModInverse(secretKey.Second, order))

	symmetricKeyGT := new(bn254.GT).Div(encryptedKey.Second, temp)

	symmetricKey, err := utils.DeriveKeyFromGT(symmetricKeyGT, 32)
	if err != nil {
		return nil, fmt.Errorf("failed to derive key: %v", err)
	}

	return symmetricKey, nil
}

// Decrypt second-level encrypted symmetric key
// Supposed to run by the original encryptor
func (p *preClient) decryptSecondLevelKey(encryptedKey *types.SecondLevelSymmetricKey, secretKey *types.SecretKey) ([]byte, error) {
	temp, err := bn254.Pair([]bn254.G1Affine{*encryptedKey.First}, []bn254.G2Affine{*p.Params.G2})
	if err != nil {
		return nil, fmt.Errorf("error in pairing")
	}

	symmetricKeyGT := new(bn254.GT).Div(encryptedKey.Second, new(bn254.GT).Exp(temp, secretKey.First))
	symmetricKey, err := utils.DeriveKeyFromGT(symmetricKeyGT, 32)
	if err != nil {
		return nil, fmt.Errorf("failed to derive key: %v", err)
	}

	return symmetricKey, nil
}

// GetG1 returns the G1 group element
func (p *preClient) G1() *bn254.G1Affine {
	return p.Params.G1
}

// GetG2 returns the G2 group element
func (p *preClient) G2() *bn254.G2Affine {
	return p.Params.G2
}

// GetZ returns the GT group element
func (p *preClient) Z() *bn254.GT {
	return p.Params.Z
}
