//go:build unit
// +build unit

package v1

import (
	"context"
	"errors"

	"testing"

	"github.com/MGTheTrain/crypto-vault/internal/domain/blobs"

	"github.com/MGTheTrain/crypto-vault/internal/api/grpc/v1/stub"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// TestBlobMetadataServer_GetMetadataByID uses table-driven tests
func TestBlobMetadataServer_GetMetadataByID(t *testing.T) {
	tests := []struct {
		name         string
		blobID       string
		mockReturn   *blobs.BlobMeta
		mockError    error
		wantErr      bool
		errContains  string
		validateResp func(t *testing.T, resp *stub.BlobMetaResponse)
	}{
		{
			name:   "success with all fields populated",
			blobID: "blob-123",
			mockReturn: &blobs.BlobMeta{
				ID:                "blob-123",
				UserID:            "user-1",
				Name:              "test.txt",
				Size:              1024,
				Type:              "text/plain",
				EncryptionKeyID:   stringPtr("enc-key-123"),
				SignKeyID:         stringPtr("sign-key-456"),
				SignatureBlobID:   stringPtr("sig-blob-789"),
				SignatureFileName: stringPtr("test.txt.sig"),
			},
			mockError: nil,
			wantErr:   false,
			validateResp: func(t *testing.T, resp *stub.BlobMetaResponse) {
				assert.Equal(t, "blob-123", resp.Id)
				assert.Equal(t, "test.txt", resp.Name)
				assert.Equal(t, int64(1024), resp.Size)
				assert.Equal(t, "enc-key-123", resp.EncryptionKeyId)
				assert.Equal(t, "sign-key-456", resp.SignKeyId)
				assert.Equal(t, "sig-blob-789", resp.SignatureBlobId)
				assert.Equal(t, "test.txt.sig", resp.SignatureFileName)
			},
		},
		{
			name:   "success with nil encryption and signature fields",
			blobID: "blob-456",
			mockReturn: &blobs.BlobMeta{
				ID:                "blob-456",
				UserID:            "user-2",
				Name:              "plain.pdf",
				Size:              2048,
				Type:              "application/pdf",
				EncryptionKeyID:   nil,
				SignKeyID:         nil,
				SignatureBlobID:   nil,
				SignatureFileName: nil,
			},
			mockError: nil,
			wantErr:   false,
			validateResp: func(t *testing.T, resp *stub.BlobMetaResponse) {
				assert.Equal(t, "blob-456", resp.Id)
				assert.Equal(t, "plain.pdf", resp.Name)
				assert.Equal(t, "", resp.EncryptionKeyId)
				assert.Equal(t, "", resp.SignKeyId)
				assert.Equal(t, "", resp.SignatureBlobId)
				assert.Equal(t, "", resp.SignatureFileName)
			},
		},
		{
			name:        "blob not found error",
			blobID:      "nonexistent-blob",
			mockReturn:  nil,
			mockError:   errors.New("blob not found"),
			wantErr:     true,
			errContains: "failed to get metadata by ID",
		},
		{
			name:   "success with signature but no encryption",
			blobID: "blob-signed-only",
			mockReturn: &blobs.BlobMeta{
				ID:                "blob-signed-only",
				UserID:            "user-3",
				Name:              "signed.doc",
				Size:              512,
				Type:              "application/msword",
				EncryptionKeyID:   nil,
				SignKeyID:         stringPtr("sign-key-999"),
				SignatureBlobID:   stringPtr("sig-blob-111"),
				SignatureFileName: stringPtr("signed.doc.sig"),
			},
			mockError: nil,
			wantErr:   false,
			validateResp: func(t *testing.T, resp *stub.BlobMetaResponse) {
				assert.Equal(t, "blob-signed-only", resp.Id)
				assert.Equal(t, "", resp.EncryptionKeyId)
				assert.Equal(t, "sign-key-999", resp.SignKeyId)
				assert.Equal(t, "sig-blob-111", resp.SignatureBlobId)
				assert.Equal(t, "signed.doc.sig", resp.SignatureFileName)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockService := new(MockBlobMetadataService)
			server, err := NewBlobMetadataServer(mockService)
			require.NoError(t, err)

			mockService.On("GetByID", mock.Anything, tt.blobID).
				Return(tt.mockReturn, tt.mockError)

			req := &stub.IdRequest{Id: tt.blobID}
			resp, err := server.GetMetadataByID(context.Background(), req)

			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, resp)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, resp)
				if tt.validateResp != nil {
					tt.validateResp(t, resp)
				}
			}

			mockService.AssertExpectations(t)
		})
	}
}

// TestBlobMetadataServer_DeleteByID uses table-driven tests
func TestBlobMetadataServer_DeleteByID(t *testing.T) {
	tests := []struct {
		name        string
		blobID      string
		mockError   error
		wantErr     bool
		errContains string
		wantMessage string
	}{
		{
			name:        "successful deletion",
			blobID:      "blob-to-delete",
			mockError:   nil,
			wantErr:     false,
			wantMessage: "blob with id blob-to-delete deleted successfully",
		},
		{
			name:        "deletion fails - blob not found",
			blobID:      "nonexistent-blob",
			mockError:   errors.New("blob not found"),
			wantErr:     true,
			errContains: "failed to delete blob",
		},
		{
			name:        "deletion fails - database error",
			blobID:      "blob-db-error",
			mockError:   errors.New("database connection failed"),
			wantErr:     true,
			errContains: "failed to delete blob",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockService := new(MockBlobMetadataService)
			server, err := NewBlobMetadataServer(mockService)
			require.NoError(t, err)

			mockService.On("DeleteByID", mock.Anything, tt.blobID).
				Return(tt.mockError)

			req := &stub.IdRequest{Id: tt.blobID}
			resp, err := server.DeleteByID(context.Background(), req)

			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, resp)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, resp)
				assert.Contains(t, resp.Message, tt.wantMessage)
			}

			mockService.AssertExpectations(t)
		})
	}
}

// Helper function for creating string pointers
func stringPtr(s string) *string {
	return &s
}
