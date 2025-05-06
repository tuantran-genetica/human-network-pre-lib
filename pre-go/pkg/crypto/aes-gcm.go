package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"

	"github.com/lifenetwork-ai/proxy-recrypt-sdk/pre-go/pkg/testutils"
)

type AESGCMOptions struct {
	Mock bool
}

func EncryptAESGCM(message []byte, key []byte, opts *AESGCMOptions) ([]byte, error) {
	if len(key) != 16 && len(key) != 24 && len(key) != 32 {
		return nil, fmt.Errorf("invalid key size: %d", len(key))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("could not create new cipher: %v", err)
	}

	// Generate a random nonce
	nonce := make([]byte, 12)
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("could not generate nonce: %v", err)
	}

	if opts != nil && opts.Mock {
		nonce = testutils.GenerateMockNonce()
	}

	// Create AEAD cipher
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("could not create GCM: %v", err)
	}

	// Encrypt and authenticate
	ciphertext := aead.Seal(nonce, nonce, message, nil)
	return ciphertext, nil
}

func DecryptAESGCM(message []byte, key []byte) ([]byte, error) {
	ciphertext := message

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("could not create new cipher: %v", err)
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("could not create GCM: %v", err)
	}

	if len(ciphertext) < 12 {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce := ciphertext[:12]
	ciphertext = ciphertext[12:]

	// Decrypt and verify
	plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("could not decrypt: %v", err)
	}

	return plaintext, nil
}
