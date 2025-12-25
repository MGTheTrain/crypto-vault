//go:build unit
// +build unit

package v1

import (
	"context"
	"crypto_vault_service/internal/domain/keys"
	"errors"
	"testing"
	"time"

	pb "proto"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// TestCryptoKeyMetadataServer_GetMetadataByID uses table-driven tests
func TestCryptoKeyMetadataServer_GetMetadataByID(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name         string
		keyID        string
		mockReturn   *keys.CryptoKeyMeta
		mockError    error
		wantErr      bool
		errContains  string
		validateResp func(t *testing.T, resp *pb.CryptoKeyMetaResponse)
	}{
		{
			name:  "success with RSA private key",
			keyID: "rsa-priv-123",
			mockReturn: &keys.CryptoKeyMeta{
				ID:              "rsa-priv-123",
				KeyPairID:       "pair-456",
				UserID:          "user-1",
				Algorithm:       "RSA",
				KeySize:         2048,
				Type:            "private",
				DateTimeCreated: now,
			},
			mockError: nil,
			wantErr:   false,
			validateResp: func(t *testing.T, resp *pb.CryptoKeyMetaResponse) {
				assert.Equal(t, "rsa-priv-123", resp.Id)
				assert.Equal(t, "pair-456", resp.KeyPairId)
				assert.Equal(t, "RSA", resp.Algorithm)
				assert.Equal(t, uint32(2048), resp.KeySize)
				assert.Equal(t, "private", resp.Type)
			},
		},
		{
			name:  "success with ECDSA public key",
			keyID: "ecdsa-pub-789",
			mockReturn: &keys.CryptoKeyMeta{
				ID:              "ecdsa-pub-789",
				KeyPairID:       "pair-abc",
				UserID:          "user-2",
				Algorithm:       "ECDSA",
				KeySize:         256,
				Type:            "public",
				DateTimeCreated: now,
			},
			mockError: nil,
			wantErr:   false,
			validateResp: func(t *testing.T, resp *pb.CryptoKeyMetaResponse) {
				assert.Equal(t, "ecdsa-pub-789", resp.Id)
				assert.Equal(t, "pair-abc", resp.KeyPairId)
				assert.Equal(t, "ECDSA", resp.Algorithm)
				assert.Equal(t, uint32(256), resp.KeySize)
				assert.Equal(t, "public", resp.Type)
			},
		},
		{
			name:  "success with AES symmetric key",
			keyID: "aes-sym-999",
			mockReturn: &keys.CryptoKeyMeta{
				ID:              "aes-sym-999",
				KeyPairID:       "", // No pair for symmetric keys
				UserID:          "user-3",
				Algorithm:       "AES",
				KeySize:         256,
				Type:            "symmetric",
				DateTimeCreated: now,
			},
			mockError: nil,
			wantErr:   false,
			validateResp: func(t *testing.T, resp *pb.CryptoKeyMetaResponse) {
				assert.Equal(t, "aes-sym-999", resp.Id)
				assert.Equal(t, "AES", resp.Algorithm)
				assert.Equal(t, uint32(256), resp.KeySize)
				assert.Equal(t, "symmetric", resp.Type)
			},
		},
		{
			name:        "key not found error",
			keyID:       "nonexistent-key",
			mockReturn:  nil,
			mockError:   errors.New("key not found"),
			wantErr:     true,
			errContains: "failed to get crypto key metadata by ID",
		},
		{
			name:        "database connection error",
			keyID:       "db-error-key",
			mockReturn:  nil,
			mockError:   errors.New("database connection failed"),
			wantErr:     true,
			errContains: "failed to get crypto key metadata by ID",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockService := new(MockCryptoKeyMetadataService)
			server, err := NewCryptoKeyMetadataServer(mockService)
			require.NoError(t, err)

			mockService.On("GetByID", mock.Anything, tt.keyID).
				Return(tt.mockReturn, tt.mockError)

			req := &pb.IdRequest{Id: tt.keyID}
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

// TestCryptoKeyMetadataServer_DeleteByID uses table-driven tests
func TestCryptoKeyMetadataServer_DeleteByID(t *testing.T) {
	tests := []struct {
		name        string
		keyID       string
		mockError   error
		wantErr     bool
		errContains string
		wantMessage string
	}{
		{
			name:        "successful deletion of RSA key",
			keyID:       "rsa-key-delete",
			mockError:   nil,
			wantErr:     false,
			wantMessage: "crypto key with id rsa-key-delete deleted successfully",
		},
		{
			name:        "successful deletion of AES key",
			keyID:       "aes-key-delete",
			mockError:   nil,
			wantErr:     false,
			wantMessage: "crypto key with id aes-key-delete deleted successfully",
		},
		{
			name:        "deletion fails - key not found",
			keyID:       "nonexistent-key",
			mockError:   errors.New("key not found"),
			wantErr:     true,
			errContains: "failed to delete crypto key",
		},
		{
			name:        "deletion fails - key in use",
			keyID:       "key-in-use",
			mockError:   errors.New("key is referenced by blobs"),
			wantErr:     true,
			errContains: "failed to delete crypto key",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockService := new(MockCryptoKeyMetadataService)
			server, err := NewCryptoKeyMetadataServer(mockService)
			require.NoError(t, err)

			mockService.On("DeleteByID", mock.Anything, tt.keyID).
				Return(tt.mockError)

			req := &pb.IdRequest{Id: tt.keyID}
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
