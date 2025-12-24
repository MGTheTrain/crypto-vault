//go:build unit
// +build unit

package validators

import (
	"testing"

	"github.com/go-playground/validator/v10"
	"github.com/stretchr/testify/require"
)

// TestKeyConfig is a mock struct for testing the KeySizeValidation function
type TestKeyConfig struct {
	Algorithm string `validate:"required"`
	KeySize   uint   `validate:"keysize"`
}

func TestKeySizeValidation(t *testing.T) {
	validate := validator.New()

	// Register custom validation
	require.NoError(t, validate.RegisterValidation("keysize", KeySizeValidation))

	tests := []struct {
		name      string
		input     TestKeyConfig
		shouldErr bool
	}{
		// AES cases
		{"AES valid 128", TestKeyConfig{"AES", 128}, false},
		{"AES valid 192", TestKeyConfig{"AES", 192}, false},
		{"AES valid 256", TestKeyConfig{"AES", 256}, false},
		{"AES invalid", TestKeyConfig{"AES", 200}, true},

		// RSA cases
		{"RSA valid 512", TestKeyConfig{"RSA", 512}, false},
		{"RSA valid 2048", TestKeyConfig{"RSA", 2048}, false},
		{"RSA invalid", TestKeyConfig{"RSA", 1234}, true},

		// EC cases
		{"EC valid 256", TestKeyConfig{"ECDSA", 256}, false},
		{"EC valid 521", TestKeyConfig{"ECDSA", 521}, false},
		{"EC invalid", TestKeyConfig{"ECDSA", 300}, true},

		// Unknown algorithm
		{"Unknown algorithm", TestKeyConfig{"Unknown", 256}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validate.Struct(tt.input)
			if tt.shouldErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
