package testutils

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"os"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/lifenetwork-ai/proxy-recrypt-sdk/pre-go/pkg/pre/types"
	"github.com/lifenetwork-ai/proxy-recrypt-sdk/pre-go/pkg/pre/utils"
)

// SerializableKeyPair represents a serializable version of KeyPair
type SerializableKeyPair struct {
	PublicKey struct {
		First  string // GT element in base64
		Second string // G2Affine point in base64
	}
	SecretKey struct {
		First  string // big.Int in hex
		Second string // big.Int in hex
	}
}

// SaveKeyPairToFile generates a new keypair and saves it to a file
func SaveKeyPairToFile(filename string) error {
	// Generate system parameters
	_, g2, Z := utils.GenerateSystemParameters()

	// Generate a new keypair
	keyPair := GenerateRandomKeyPair(g2, Z)

	// Convert to serializable format
	serializable := SerializableKeyPair{}

	// Serialize public key using base64
	firstBytes := keyPair.PublicKey.First.Bytes()
	secondBytes := keyPair.PublicKey.Second.RawBytes()
	serializable.PublicKey.First = base64.StdEncoding.EncodeToString(firstBytes[:])
	serializable.PublicKey.Second = base64.StdEncoding.EncodeToString(secondBytes[:])

	// Serialize secret key
	serializable.SecretKey.First = keyPair.SecretKey.First.Text(16)   // hex encoding
	serializable.SecretKey.Second = keyPair.SecretKey.Second.Text(16) // hex encoding

	// Convert to JSON
	jsonData, err := json.MarshalIndent(serializable, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal keypair: %v", err)
	}

	// Write to file
	err = os.WriteFile(filename, jsonData, 0o600)
	if err != nil {
		return fmt.Errorf("failed to write keypair to file: %v", err)
	}

	return nil
}

// LoadKeyPairFromFile loads a keypair from a file
func LoadKeyPairFromFile(filename string) (*types.KeyPair, error) {
	// Read file
	jsonData, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read keypair file: %v", err)
	}

	// Parse JSON
	var serializable SerializableKeyPair
	err = json.Unmarshal(jsonData, &serializable)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal keypair: %v", err)
	}

	// Reconstruct KeyPair
	keyPair := &types.KeyPair{
		PublicKey: &types.PublicKey{
			First:  new(bn254.GT),
			Second: new(bn254.G2Affine),
		},
		SecretKey: &types.SecretKey{
			First:  new(big.Int),
			Second: new(big.Int),
		},
	}

	// Deserialize public key from base64
	firstBytes, err := base64.StdEncoding.DecodeString(serializable.PublicKey.First)
	if err != nil {
		return nil, fmt.Errorf("failed to decode GT element from base64: %v", err)
	}
	err = keyPair.PublicKey.First.SetBytes(firstBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize GT element: %v", err)
	}

	secondBytes, err := base64.StdEncoding.DecodeString(serializable.PublicKey.Second)
	if err != nil {
		return nil, fmt.Errorf("failed to decode G2 point from base64: %v", err)
	}
	_, err = keyPair.PublicKey.Second.SetBytes(secondBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize G2 point: %v", err)
	}

	keyPair.SecretKey.First.SetString(serializable.SecretKey.First, 16)   // hex encoding
	keyPair.SecretKey.Second.SetString(serializable.SecretKey.Second, 16) // hex encoding

	return keyPair, nil
}

func LoadAliceKeyPair() *types.KeyPair {
	aliceKeypair, err := LoadKeyPairFromFile("../../../testdata/alice_keypair.json")
	if err != nil {
		err = SaveKeyPairToFile("../../../testdata/alice_keypair.json")
		if err != nil {
			panic(err)
		}
		aliceKeypair, err = LoadKeyPairFromFile("../../../testdata/alice_keypair.json")
		if err != nil {
			panic(err)
		}
	}

	return aliceKeypair
}

func LoadBobKeyPair() *types.KeyPair {
	bobKeypair, err := LoadKeyPairFromFile("../../../testdata/bob_keypair.json")
	if err != nil {
		err = SaveKeyPairToFile("../../../testdata/bob_keypair.json")
		if err != nil {
			panic(err)
		}
		bobKeypair, err = LoadKeyPairFromFile("../../../testdata/bob_keypair.json")
		if err != nil {
			panic(err)
		}
	}

	return bobKeypair
}
