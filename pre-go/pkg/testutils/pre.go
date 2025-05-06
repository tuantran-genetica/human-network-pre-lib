package testutils

import (
	"encoding/base64"
	"math/big"
	"os"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/lifenetwork-ai/proxy-recrypt-sdk/pre-go/pkg/pre/types"
	"github.com/lifenetwork-ai/proxy-recrypt-sdk/pre-go/pkg/pre/utils"
)

func LoadReKey(aliceKeypair, bobKeypair *types.KeyPair, client types.PreClient) *bn254.G2Affine {
	reKeyBase64FromFile, err := os.ReadFile("../../../testdata/rekey.txt")
	var rekeyBytes []byte
	if err != nil {
		reKey := client.GenerateReEncryptionKey(aliceKeypair.SecretKey, bobKeypair.PublicKey)
		reKeyRawBytes := reKey.RawBytes()
		err = WriteAsBase64IfNotExists("../../../testdata/rekey.txt", reKeyRawBytes[:])
		if err != nil {
			panic(err)
		}
		rekeyBytes = reKeyRawBytes[:]
	} else {
		rekeyBytes, err = base64.StdEncoding.DecodeString(string(reKeyBase64FromFile))
		if err != nil {
			panic(err)
		}
	}

	rekey := new(bn254.G2Affine)
	_, err = rekey.SetBytes(rekeyBytes)
	if err != nil {
		panic(err)
	}

	return rekey
}

func LoadMockScalar() (*big.Int, error) {
	mockData, err := os.ReadFile("../../../testdata/random_scalar.txt")
	if err != nil {
		randomScalar := GenerateRandomScalar()
		randomScalarBytes := randomScalar.Bytes()
		err = WriteAsBase64IfNotExists("../../../testdata/random_scalar.txt", randomScalarBytes)
		if err != nil {
			return nil, err
		}
		return randomScalar, nil
	}
	decodedBytes, err := base64.StdEncoding.DecodeString(string(mockData))
	if err != nil {
		return nil, err
	}
	return new(big.Int).SetBytes(decodedBytes), nil
}

func LoadMockSymmetricKeyGt() *bn254.GT {
	symmetricKeyGtContent, err := os.ReadFile("../../../testdata/symmetric_key_gt.txt")
	var symmetricKeyGtBytes []byte
	if err != nil {
		randomGt := GenerateRandomGTElem()
		randomGtBytes := randomGt.Bytes()
		err = WriteAsBase64IfNotExists("../../../testdata/symmetric_key_gt.txt", randomGtBytes[:])
		if err != nil {
			panic(err)
		}
		symmetricKeyGtBytes = randomGtBytes[:]
	} else {
		symmetricKeyGtBytes, err = base64.StdEncoding.DecodeString(string(symmetricKeyGtContent))
		if err != nil {
			panic(err)
		}
	}

	symmetricKeyGt := new(bn254.GT)
	err = symmetricKeyGt.SetBytes(symmetricKeyGtBytes)
	if err != nil {
		panic(err)
	}

	return symmetricKeyGt
}

func LoadMockSymmetricKey() []byte {
	symmetricKeyGt := LoadMockSymmetricKeyGt()
	key, _ := utils.DeriveKeyFromGT(symmetricKeyGt, 32)

	return key
}
