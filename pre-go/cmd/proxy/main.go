package main

import (
	"encoding/base64"
	"net/http"
	"sync"
	"time"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/lifenetwork-ai/proxy-recrypt-sdk/pre-go/pkg/pre"
	"github.com/lifenetwork-ai/proxy-recrypt-sdk/pre-go/pkg/pre/types"
)

// StoredData represents the data stored in memory
type StoredData struct {
	ReencryptionKey *bn254.G2Affine                `json:"reencryption_key"`
	EncryptedKey    *types.SecondLevelSymmetricKey `json:"encrypted_key"`
	EncryptedData   []byte                         `json:"encrypted_data"`
}

// StoreRequest represents the incoming store request
type StoreRequest struct {
	ReencryptionKey string `json:"reencryption_key"` // Base64 encoded
	EncryptedKey    struct {
		First  string `json:"first"`  // Base64 encoded
		Second string `json:"second"` // Base64 encoded
	} `json:"encrypted_key"`
	EncryptedData []byte `json:"encrypted_data"`
	UserID        string `json:"user_id"`
}

// ProxyRequest represents the request structure for re-encryption
type ProxyRequest struct {
	RequestID string `json:"request_id"`
}

// InMemoryStore is a simple thread-safe in-memory storage
type InMemoryStore struct {
	sync.RWMutex
	data map[string]StoredData
}

var (
	store = &InMemoryStore{
		data: make(map[string]StoredData),
	}
	proxyService = pre.NewProxy()
)

func main() {
	r := gin.Default()

	// Update CORS middleware configuration
	r.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"http://localhost:5173"}, // Updated to match your frontend URL
		AllowMethods:     []string{"GET", "POST", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Authorization"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
	}))

	// Endpoint to store re-encryption data
	r.POST("/store", func(c *gin.Context) {
		var req StoreRequest
		if err := c.BindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		// Decode reencryption key
		reKeyBytes, err := base64.StdEncoding.DecodeString(req.ReencryptionKey)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid reencryption key encoding"})
			return
		}
		reKey := new(bn254.G2Affine)
		_, err = reKey.SetBytes(reKeyBytes)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid reencryption key format"})
			return
		}

		// Decode encrypted key components
		firstBytes, err := base64.StdEncoding.DecodeString(req.EncryptedKey.First)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid first key component encoding"})
			return
		}
		first := new(bn254.G1Affine)
		_, err = first.SetBytes(firstBytes)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid first key component format"})
			return
		}

		secondBytes, err := base64.StdEncoding.DecodeString(req.EncryptedKey.Second)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid second key component encoding"})
			return
		}
		second := new(bn254.GT)
		err = second.SetBytes(secondBytes)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid second key component format"})
			return
		}

		encKey := &types.SecondLevelSymmetricKey{
			First:  first,
			Second: second,
		}

		data := StoredData{
			ReencryptionKey: reKey,
			EncryptedKey:    encKey,
			EncryptedData:   req.EncryptedData,
		}

		store.Lock()
		store.data[req.UserID] = data
		store.Unlock()

		c.JSON(http.StatusOK, gin.H{
			"status": "success",
			"id":     req.UserID,
		})
	})

	// Endpoint to request re-encrypted data
	r.POST("/request", func(c *gin.Context) {
		var req ProxyRequest
		if err := c.BindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		store.RLock()
		data, exists := store.data[req.RequestID]
		store.RUnlock()

		if !exists {
			c.JSON(http.StatusNotFound, gin.H{"error": "data not found"})
			return
		}

		// Perform re-encryption using the PRE proxy implementation
		firstLevelKey := proxyService.ReEncryption(data.EncryptedKey, data.ReencryptionKey)

		c.JSON(http.StatusOK, gin.H{
			"first_level_key": firstLevelKey,
			"encrypted_data":  data.EncryptedData,
		})
	})

	err := r.Run(":8080") // Listen and serve on 0.0.0.0:8080
	if err != nil {
		panic(err)
	}
}
