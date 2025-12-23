//go:build unit
// +build unit

package crypto

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TokenValidationTests struct encapsulates the test data and methods for Token validation
type TokenValidationTests struct {
	// TestData for holding valid and invalid Token data
	validToken    Token
	invalidToken  Token
	invalidToken2 Token
}

// NewTokenValidationTests is a constructor to create a new instance of TokenValidationTests
func NewTokenValidationTests() *TokenValidationTests {
	// Create valid and invalid test data for Token
	validToken := Token{
		SlotID:       "slot123",
		Label:        "Test Token",
		Manufacturer: "Test Manufacturer",
		Model:        "Model X",
		SerialNumber: "12345",
	}

	invalidToken := Token{
		SlotID:       "", // Invalid empty SlotID
		Label:        "Test Token",
		Manufacturer: "Test Manufacturer",
		Model:        "Model X",
		SerialNumber: "12345",
	}

	invalidToken2 := Token{
		SlotID:       "slot123",
		Label:        "", // Invalid empty Label
		Manufacturer: "Test Manufacturer",
		Model:        "Model X",
		SerialNumber: "12345",
	}

	return &TokenValidationTests{
		validToken:    validToken,
		invalidToken:  invalidToken,
		invalidToken2: invalidToken2,
	}
}

// TestTokenValidation tests the Validator method for Token
func (tt *TokenValidationTests) TestTokenValidation(t *testing.T) {
	// Validate the valid Token
	err := tt.validToken.Validate()
	assert.Nil(t, err, "Expected no validation errors for valid Token")

	// Validate the invalid Token (empty SlotID)
	err = tt.invalidToken.Validate()
	assert.NotNil(t, err, "Expected validation errors for invalid Token")
	assert.Contains(t, err.Error(), "Field: SlotID, Tag: required")

	// Validate the invalid Token (empty Label)
	err = tt.invalidToken2.Validate()
	assert.NotNil(t, err, "Expected validation errors for invalid Token")
	assert.Contains(t, err.Error(), "Field: Label, Tag: required")
}

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
