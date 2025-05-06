package mocks

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/lifenetwork-ai/proxy-recrypt-sdk/pre-go/pkg/crypto"
	"github.com/lifenetwork-ai/proxy-recrypt-sdk/pre-go/pkg/pre"
	"github.com/lifenetwork-ai/proxy-recrypt-sdk/pre-go/pkg/pre/types"
	"github.com/lifenetwork-ai/proxy-recrypt-sdk/pre-go/pkg/pre/utils"
	"github.com/lifenetwork-ai/proxy-recrypt-sdk/pre-go/pkg/testutils"
)

type MockPreScheme struct {
	g1             *bn254.G1Affine
	g2             *bn254.G2Affine
	z              *bn254.GT
	ReKey          *bn254.G2Affine
	Scalar         *big.Int
	AliceKeyPair   *types.KeyPair
	BobKeyPair     *types.KeyPair
	Message        []byte
	SymmetricKeyGT *bn254.GT
	SymmetricKey   []byte
}

func NewMockPreScheme() *MockPreScheme {
	g1, g2, Z := utils.GenerateSystemParameters()
	scheme := pre.NewPreScheme()
	// Generate key pairs for Alice and Bob
	aliceKeypair, bobKeypair := testutils.LoadAliceKeyPair(), testutils.LoadBobKeyPair()
	rekey := testutils.LoadReKey(aliceKeypair, bobKeypair, scheme.Client)

	message := testutils.LoadMessage()

	scalar, err := testutils.LoadMockScalar()
	if err != nil {
		panic(err)
	}

	symmetricKeyGt := testutils.LoadMockSymmetricKeyGt()
	key, _ := utils.DeriveKeyFromGT(symmetricKeyGt, 32)

	return &MockPreScheme{
		g1:             g1,
		g2:             g2,
		z:              Z,
		ReKey:          rekey,
		Scalar:         scalar,
		AliceKeyPair:   aliceKeypair,
		BobKeyPair:     bobKeypair,
		Message:        message,
		SymmetricKeyGT: symmetricKeyGt,
		SymmetricKey:   key,
	}
}

// Interface implementations - using pre-computed values
func (m *MockPreScheme) GenerateReEncryptionKey(_ *types.SecretKey, _ *types.PublicKey) *bn254.G2Affine {
	// Use pre-computed values instead of parameters
	return new(bn254.G2Affine).ScalarMultiplication(m.BobKeyPair.PublicKey.Second, m.AliceKeyPair.SecretKey.First)
}

func (m *MockPreScheme) SecondLevelEncryption(_ *types.SecretKey, _ string, _ *big.Int) (*types.SecondLevelSymmetricKey, []byte, error) {
	// Use pre-computed values instead of parameters
	first := new(bn254.G1Affine).ScalarMultiplication(m.g1, m.Scalar)
	secondTemp1 := new(bn254.GT).Exp(*m.z, m.AliceKeyPair.SecretKey.First)
	secondTemp := new(bn254.GT).Exp(*secondTemp1, m.Scalar)
	second := new(bn254.GT).Mul(m.SymmetricKeyGT, secondTemp)

	keyGTBytes := m.SymmetricKeyGT.Bytes()

	// write to mocks folder if not exists
	err := testutils.WriteAsBase64IfNotExists("../../../testdata/symmetric_key_gt.txt", keyGTBytes[:])
	if err != nil {
		panic(err)
	}

	err = testutils.WriteAsBase64IfNotExists("../../../testdata/symmetric_key.txt", m.SymmetricKey)
	if err != nil {
		panic(err)
	}

	encryptedMessage, _ := crypto.EncryptAESGCM(m.Message, m.SymmetricKey, &crypto.AESGCMOptions{
		Mock: true,
	})
	err = testutils.WriteAsBase64IfNotExists("../../../testdata/encrypted_message.txt", encryptedMessage)
	if err != nil {
		panic(err)
	}
	encryptedKey := &types.SecondLevelSymmetricKey{
		First:  first,
		Second: second,
	}

	return encryptedKey, encryptedMessage, nil
}

func (m *MockPreScheme) ReEncryption(encryptedKey *types.SecondLevelSymmetricKey, reKey *bn254.G2Affine) *types.FirstLevelSymmetricKey {
	first, _ := bn254.Pair([]bn254.G1Affine{*encryptedKey.First}, []bn254.G2Affine{*reKey})

	newEncryptedKey := &types.FirstLevelSymmetricKey{
		First:  &first,
		Second: encryptedKey.Second,
	}

	return newEncryptedKey
}

func (m *MockPreScheme) DecryptFirstLevel(encryptedKey *types.FirstLevelSymmetricKey, encryptedMessage []byte, _ *types.SecretKey) string {
	// Use pre-computed Bob's secret key instead of parameter
	order := bn254.ID.ScalarField()
	fmt.Println("order: ", order)
	fmt.Println("scalar: ", new(big.Int).ModInverse(m.BobKeyPair.SecretKey.Second, order))
	fmt.Println("bob key: ", m.BobKeyPair.SecretKey.Second)
	fmt.Println("encrypted key first: ", encryptedKey.First.Bytes())
	temp := new(bn254.GT).Exp(*encryptedKey.First, new(big.Int).ModInverse(m.BobKeyPair.SecretKey.Second, order))
	fmt.Println("temp", temp.Bytes())
	symmetricKeyGT := new(bn254.GT).Div(encryptedKey.Second, temp)
	// fmt.Println("encrypted key first: ", encryptedKey.First.Bytes())
	symmetricKey, _ := utils.DeriveKeyFromGT(symmetricKeyGT, 32)

	decryptedMessage, _ := crypto.DecryptAESGCM(encryptedMessage, symmetricKey)
	return string(decryptedMessage)
}

func (m *MockPreScheme) DecryptSecondLevel(encryptedKey *types.SecondLevelSymmetricKey, encryptedMessage []byte, _ *types.SecretKey) string {
	// Use pre-computed Bob's secret key instead of parameter
	temp, err := bn254.Pair([]bn254.G1Affine{*encryptedKey.First}, []bn254.G2Affine{*m.G2()})
	if err != nil {
		panic(err)
	}

	symmetricKeyGT := new(bn254.GT).Div(encryptedKey.Second, new(bn254.GT).Exp(temp, m.AliceKeyPair.SecretKey.First))
	symmetricKey, _ := utils.DeriveKeyFromGT(symmetricKeyGT, 32)

	decryptedMessage, _ := crypto.DecryptAESGCM(encryptedMessage, symmetricKey)
	return string(decryptedMessage)
}

func (m *MockPreScheme) SecretToPubkey(secret *types.SecretKey) *types.PublicKey {
	return utils.SecretToPubkey(secret, m.g2, m.z)
}

// Helper methods for testing
func (m *MockPreScheme) GetAliceKeyPair() *types.KeyPair {
	return m.AliceKeyPair
}

func (m *MockPreScheme) GetBobKeyPair() *types.KeyPair {
	return m.BobKeyPair
}

func (m *MockPreScheme) GetTestMessage() []byte {
	return m.Message
}

func (m *MockPreScheme) GetScalar() *big.Int {
	return m.Scalar
}

func (m *MockPreScheme) GetSymmetricKeyGT() *bn254.GT {
	return m.SymmetricKeyGT
}

func (m *MockPreScheme) G1() *bn254.G1Affine {
	return m.g1
}

func (m *MockPreScheme) G2() *bn254.G2Affine {
	return m.g2
}

func (m *MockPreScheme) Z() *bn254.GT {
	return m.z
}
