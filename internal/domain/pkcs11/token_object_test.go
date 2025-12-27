//go:build unit
// +build unit

package pkcs11

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TokenObjectValidationTests struct encapsulates the test data and methods for TokenObject validation
type TokenObjectValidationTests struct {
	// TestData for holding valid and invalid TokenObject data
	validTokenObject    TokenObject
	invalidTokenObject  TokenObject
	invalidTokenObject2 TokenObject
}

// NewTokenObjectValidationTests is a constructor to create a new instance of TokenObjectValidationTests
func NewTokenObjectValidationTests() *TokenObjectValidationTests {
	// Create valid and invalid test data for TokenObject
	validTokenObject := TokenObject{
		Label:  "Test TokenObject",
		Type:   "RSA",
		Usage:  "sign",
		Access: "sensitive",
	}

	invalidTokenObject := TokenObject{
		Label:  "", // Invalid empty Label
		Type:   "RSA",
		Usage:  "sign",
		Access: "sensitive",
	}

	invalidTokenObject2 := TokenObject{
		Label:  "Test TokenObject",
		Type:   "", // Invalid empty Type
		Usage:  "sign",
		Access: "sensitive",
	}

	return &TokenObjectValidationTests{
		validTokenObject:    validTokenObject,
		invalidTokenObject:  invalidTokenObject,
		invalidTokenObject2: invalidTokenObject2,
	}
}

// TestTokenObjectValidation tests the Validator method for TokenObject
func (tt *TokenObjectValidationTests) TestTokenObjectValidation(t *testing.T) {
	// Validate the valid TokenObject
	err := tt.validTokenObject.Validate()
	assert.Nil(t, err, "Expected no validation errors for valid TokenObject")

	// Validate the invalid TokenObject (empty Label)
	err = tt.invalidTokenObject.Validate()
	assert.NotNil(t, err, "Expected validation errors for invalid TokenObject")
	assert.Contains(t, err.Error(), "Field: Label, Tag: required")

	// Validate the invalid TokenObject (empty Type)
	err = tt.invalidTokenObject2.Validate()
	assert.NotNil(t, err, "Expected validation errors for invalid TokenObject")
	assert.Contains(t, err.Error(), "Field: Type, Tag: required")
}

// TestTokenValidation is the entry point to run the Token validation tests
func TestTokenValidation(t *testing.T) {
	// Create a new TokenValidationTests instance
	tt := NewTokenValidationTests()

	// Run each test method
	t.Run("TestTokenValidation", tt.TestTokenValidation)
}

// TestTokenObjectValidation is the entry point to run the TokenObject validation tests
func TestTokenObjectValidation(t *testing.T) {
	// Create a new TokenObjectValidationTests instance
	tt := NewTokenObjectValidationTests()

	// Run each test method
	t.Run("TestTokenObjectValidation", tt.TestTokenObjectValidation)
}
