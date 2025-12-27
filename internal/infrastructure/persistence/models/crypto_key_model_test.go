//go:build unit
// +build unit

package models

import (
	"testing"
	"time"

	"github.com/MGTheTrain/crypto-vault/internal/domain/keys"
	"github.com/stretchr/testify/assert"
)

func TestCryptoKeyModel_ToDomain(t *testing.T) {
	// Setup a test CryptoKeyModel instance
	cryptoKeyModel := &CryptoKeyModel{
		ID:              "test-id",
		KeyPairID:       "test-keypair-id",
		Algorithm:       "RSA",
		KeySize:         2048,
		Type:            "private",
		DateTimeCreated: time.Now(),
		UserID:          "user-id",
	}

	// Convert to domain
	cryptoKeyMeta := cryptoKeyModel.ToDomain()

	// Assertions to ensure the conversion is correct
	assert.Equal(t, cryptoKeyModel.ID, cryptoKeyMeta.ID)
	assert.Equal(t, cryptoKeyModel.KeyPairID, cryptoKeyMeta.KeyPairID)
	assert.Equal(t, cryptoKeyModel.Algorithm, cryptoKeyMeta.Algorithm)
	assert.Equal(t, cryptoKeyModel.KeySize, cryptoKeyMeta.KeySize)
	assert.Equal(t, cryptoKeyModel.Type, cryptoKeyMeta.Type)
	assert.Equal(t, cryptoKeyModel.DateTimeCreated, cryptoKeyMeta.DateTimeCreated)
	assert.Equal(t, cryptoKeyModel.UserID, cryptoKeyMeta.UserID)
}

func TestCryptoKeyModel_FromDomain(t *testing.T) {
	// Setup a test CryptoKeyMeta instance (domain entity)
	cryptoKeyMeta := &keys.CryptoKeyMeta{
		ID:              "test-id",
		KeyPairID:       "test-keypair-id",
		Algorithm:       "RSA",
		KeySize:         2048,
		Type:            "private",
		DateTimeCreated: time.Now(),
		UserID:          "user-id",
	}

	// Convert to CryptoKeyModel
	cryptoKeyModel := &CryptoKeyModel{}
	cryptoKeyModel.FromDomain(cryptoKeyMeta)

	// Assertions to ensure the conversion is correct
	assert.Equal(t, cryptoKeyMeta.ID, cryptoKeyModel.ID)
	assert.Equal(t, cryptoKeyMeta.KeyPairID, cryptoKeyModel.KeyPairID)
	assert.Equal(t, cryptoKeyMeta.Algorithm, cryptoKeyModel.Algorithm)
	assert.Equal(t, cryptoKeyMeta.KeySize, cryptoKeyModel.KeySize)
	assert.Equal(t, cryptoKeyMeta.Type, cryptoKeyModel.Type)
	assert.Equal(t, cryptoKeyMeta.DateTimeCreated, cryptoKeyModel.DateTimeCreated)
	assert.Equal(t, cryptoKeyMeta.UserID, cryptoKeyModel.UserID)
}
