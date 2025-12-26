//go:build unit
// +build unit

package keys

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

// TestCryptoKeyValidation tests the Validator method for CryptoKey
func TestCryptoKeyValidation(t *testing.T) {
	// Valid CryptoKey
	validKey := CryptoKeyMeta{
		ID:              uuid.New().String(),
		KeyPairID:       uuid.New().String(),
		Type:            "symmetric",
		KeySize:         256,
		Algorithm:       "AES",
		DateTimeCreated: time.Now(),
		UserID:          uuid.New().String(),
	}

	// Validate the valid CryptoKey
	err := validKey.Validate()
	assert.Nil(t, err, "Expected no validation errors for valid CryptoKey")

	// Invalid CryptoKey (empty ID, invalid Type, expired)
	invalidKey := CryptoKeyMeta{
		ID:              "",            // Invalid empty ID
		Type:            "InvalidType", // Invalid Type
		DateTimeCreated: time.Now(),
		UserID:          "invalid-user-id", // Invalid UserID
	}

	// Validate the invalid CryptoKey
	err = invalidKey.Validate()
	assert.NotNil(t, err, "Expected validation errors for invalid CryptoKey")
	assert.Contains(t, err.Error(), "Field: ID, Tag: required")
	assert.Contains(t, err.Error(), "Field: Type, Tag: oneof")
}

// TestCryptoKeyValidations tests the validation edge cases for CryptoKey
func TestCryptoKeyValidations(t *testing.T) {
	// Test missing UserID (should fail)
	invalidKey := CryptoKeyMeta{
		ID:              uuid.New().String(),
		KeyPairID:       uuid.New().String(), // Valid UUID
		Type:            "symmetric",         // Valid Type
		Algorithm:       "AES",               // Valid Algorithm
		DateTimeCreated: time.Now(),
		UserID:          "", // Invalid empty UserID
	}

	err := invalidKey.Validate()
	assert.NotNil(t, err, "Expected validation error for missing UserID")
	assert.Contains(t, err.Error(), "Field: UserID, Tag: required")
}
