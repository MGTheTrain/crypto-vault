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

func TestBlobMetaResponse_Validation(t *testing.T) {
	// Test that response DTOs can be created without errors
	response := BlobMetaResponse{
		ID:              "blob-123",
		Name:            "test.pdf",
		Size:            1024,
		Type:            ".pdf",
		EncryptionKeyID: nil,
		SignKeyID:       nil,
	}

	require.NotEmpty(t, response.ID)
	require.Equal(t, "test.pdf", response.Name)
}

func TestBlobMetaResponse_WithSignature(t *testing.T) {
	signatureBlobID := "sig-blob-456"
	signatureFileName := "test.pdf.sig"

	response := BlobMetaResponse{
		ID:                "blob-123",
		Name:              "test.pdf",
		Size:              1024,
		Type:              ".pdf",
		SignatureBlobID:   &signatureBlobID,
		SignatureFileName: &signatureFileName,
	}

	require.NotNil(t, response.SignatureBlobID)
	require.Equal(t, "sig-blob-456", *response.SignatureBlobID)
	require.Equal(t, "test.pdf.sig", *response.SignatureFileName)
}

func TestErrorResponse_Creation(t *testing.T) {
	errResp := ErrorResponse{
		Message: "Test error",
	}

	require.Equal(t, "Test error", errResp.Message)
}

func TestInfoResponse_Creation(t *testing.T) {
	infoResp := InfoResponse{
		Message: "Operation successful",
	}

	require.Equal(t, "Operation successful", infoResp.Message)
}
