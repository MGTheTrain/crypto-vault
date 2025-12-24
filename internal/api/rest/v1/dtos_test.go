//go:build unit
// +build unit

package v1

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestUploadKeyRequest_Validate(t *testing.T) {
	tests := []struct {
		name      string
		request   UploadKeyRequest
		shouldErr bool
	}{
		// AES Valid
		{"Valid AES 128", UploadKeyRequest{Algorithm: "AES", KeySize: 128}, false},
		{"Valid AES 256", UploadKeyRequest{Algorithm: "AES", KeySize: 256}, false},
		{"Invalid AES 100", UploadKeyRequest{Algorithm: "AES", KeySize: 100}, true},

		// RSA Valid
		{"Valid RSA 2048", UploadKeyRequest{Algorithm: "RSA", KeySize: 2048}, false},
		{"Invalid RSA 1234", UploadKeyRequest{Algorithm: "RSA", KeySize: 1234}, true},

		// EC Valid
		{"Valid EC 256", UploadKeyRequest{Algorithm: "ECDSA", KeySize: 256}, false},
		{"Invalid EC 999", UploadKeyRequest{Algorithm: "ECDSA", KeySize: 999}, true},

		// Empty (Optional fields)
		{"Empty fields (valid)", UploadKeyRequest{}, false},

		// Invalid algorithm
		{"Invalid algorithm", UploadKeyRequest{Algorithm: "Unknown", KeySize: 256}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.request.Validate()
			if tt.shouldErr {
				require.Error(t, err, "expected validation error")
			} else {
				require.NoError(t, err, "expected no validation error")
			}
		})
	}
}
