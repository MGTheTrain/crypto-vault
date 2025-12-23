//go:build unit
// +build unit

package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPKCS11SettingsValidation(t *testing.T) {
	tests := []struct {
		name          string
		settings      *PKCS11Settings
		expectedError bool
	}{
		{
			name: "Valid Settings",
			settings: &PKCS11Settings{
				ModulePath: "/path/to/module",
				SOPin:      "1234",
				UserPin:    "5678",
				SlotID:     "1",
			},
			expectedError: false,
		},
		{
			name: "Missing ModulePath",
			settings: &PKCS11Settings{
				SOPin:   "1234",
				UserPin: "5678",
				SlotID:  "1",
			},
			expectedError: true,
		},
		{
			name: "Missing SOPin",
			settings: &PKCS11Settings{
				ModulePath: "/path/to/module",
				UserPin:    "5678",
				SlotID:     "1",
			},
			expectedError: true,
		},
		{
			name: "Missing UserPin",
			settings: &PKCS11Settings{
				ModulePath: "/path/to/module",
				SOPin:      "1234",
				SlotID:     "1",
			},
			expectedError: true,
		},
		{
			name: "Missing SlotID",
			settings: &PKCS11Settings{
				ModulePath: "/path/to/module",
				SOPin:      "1234",
				UserPin:    "5678",
			},
			expectedError: true,
		},
		{
			name:          "All Fields Missing",
			settings:      &PKCS11Settings{},
			expectedError: true,
		},
	}

	// Run each test case
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.settings.Validate()

			if tt.expectedError {
				assert.Errorf(t, err, "expected an error, got nil")
			} else {
				assert.NoError(t, err, "expected no error, got: %v", err)
			}
		})
	}
}
