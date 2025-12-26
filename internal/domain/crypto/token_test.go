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
