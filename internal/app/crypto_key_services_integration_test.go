//go:build integration
// +build integration

package app

import (
	"context"
	"encoding/pem"
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"crypto_vault_service/internal/domain/crypto"
	"crypto_vault_service/internal/domain/keys"
	"crypto_vault_service/internal/pkg/config"
)

// TestCryptoKeyUploadService_Upload_Success uses table-driven tests for various algorithms
func TestCryptoKeyUploadService_Upload_Success(t *testing.T) {
	tests := []struct {
		name             string
		algorithm        string
		keySize          uint32
		expectedKeyCount int
		wantErr          bool
		errContains      string
	}{
		{
			name:             "ECDSA 224-bit keys",
			algorithm:        crypto.AlgorithmECDSA,
			keySize:          224,
			expectedKeyCount: 2, // private + public
			wantErr:          false,
		},
		{
			name:             "ECDSA 256-bit keys",
			algorithm:        crypto.AlgorithmECDSA,
			keySize:          256,
			expectedKeyCount: 2,
			wantErr:          false,
		},
		{
			name:             "ECDSA 384-bit keys",
			algorithm:        crypto.AlgorithmECDSA,
			keySize:          384,
			expectedKeyCount: 2,
			wantErr:          false,
		},
		{
			name:             "ECDSA 521-bit keys",
			algorithm:        crypto.AlgorithmECDSA,
			keySize:          521,
			expectedKeyCount: 2,
			wantErr:          false,
		},
		{
			name:             "RSA 2048-bit keys",
			algorithm:        crypto.AlgorithmRSA,
			keySize:          2048,
			expectedKeyCount: 2,
			wantErr:          false,
		},
		{
			name:             "RSA 3072-bit keys",
			algorithm:        crypto.AlgorithmRSA,
			keySize:          3072,
			expectedKeyCount: 2,
			wantErr:          false,
		},
		{
			name:             "RSA 4096-bit keys",
			algorithm:        crypto.AlgorithmRSA,
			keySize:          4096,
			expectedKeyCount: 2,
			wantErr:          false,
		},
		{
			name:             "AES 128-bit key",
			algorithm:        crypto.AlgorithmAES,
			keySize:          128,
			expectedKeyCount: 1, // symmetric key only
			wantErr:          false,
		},
		{
			name:             "AES 192-bit key",
			algorithm:        crypto.AlgorithmAES,
			keySize:          192,
			expectedKeyCount: 1,
			wantErr:          false,
		},
		{
			name:             "AES 256-bit key",
			algorithm:        crypto.AlgorithmAES,
			keySize:          256,
			expectedKeyCount: 1,
			wantErr:          false,
		},
		{
			name:        "AES invalid 512-bit",
			algorithm:   crypto.AlgorithmAES,
			keySize:     512,
			wantErr:     true,
			errContains: "not supported for AES",
		},
		{
			name:        "AES invalid 64-bit",
			algorithm:   crypto.AlgorithmAES,
			keySize:     64,
			wantErr:     true,
			errContains: "not supported for AES",
		},
		{
			name:        "ECDSA invalid 512-bit",
			algorithm:   crypto.AlgorithmECDSA,
			keySize:     512,
			wantErr:     true,
			errContains: "not supported",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			services := SetupTestServices(t, config.SqliteDbType)
			userID := uuid.NewString()
			ctx := context.Background()

			cryptoKeyMetas, err := services.CryptoKeyUploadService.Upload(ctx, userID, tt.algorithm, tt.keySize)

			if tt.wantErr {
				require.Error(t, err)
				require.Nil(t, cryptoKeyMetas)
				require.Contains(t, err.Error(), tt.errContains)
			} else {
				require.NoError(t, err)
				require.Len(t, cryptoKeyMetas, tt.expectedKeyCount)

				// Verify all keys have correct metadata
				for _, keyMeta := range cryptoKeyMetas {
					require.NotEmpty(t, keyMeta.ID)
					require.Equal(t, userID, keyMeta.UserID)
					require.Equal(t, tt.algorithm, keyMeta.Algorithm)
					require.Equal(t, tt.keySize, keyMeta.KeySize)

					// Verify key type is set correctly
					if tt.algorithm == crypto.AlgorithmAES {
						require.Equal(t, crypto.KeyTypeSymmetric, keyMeta.Type)
					} else {
						require.Contains(t, []string{crypto.KeyTypePrivate, crypto.KeyTypePublic}, keyMeta.Type)
					}
				}
			}
		})
	}
}

// TestCryptoKeyDownloadService_DownloadByID_ReturnsPEMFormat verifies PEM encoding
func TestCryptoKeyDownloadService_DownloadByID_ReturnsPEMFormat(t *testing.T) {
	tests := []struct {
		name          string
		algorithm     string
		keySize       uint32
		expectedType  string
		pemHeaderType string
	}{
		{
			name:          "RSA private key returns PEM format",
			algorithm:     crypto.AlgorithmRSA,
			keySize:       2048,
			expectedType:  crypto.KeyTypePrivate,
			pemHeaderType: "RSA PRIVATE KEY",
		},
		{
			name:          "RSA public key returns PEM format",
			algorithm:     crypto.AlgorithmRSA,
			keySize:       2048,
			expectedType:  crypto.KeyTypePublic,
			pemHeaderType: "PUBLIC KEY",
		},
		{
			name:          "ECDSA private key returns PEM format",
			algorithm:     crypto.AlgorithmECDSA,
			keySize:       256,
			expectedType:  crypto.KeyTypePrivate,
			pemHeaderType: "EC PRIVATE KEY",
		},
		{
			name:          "ECDSA public key returns PEM format",
			algorithm:     crypto.AlgorithmECDSA,
			keySize:       256,
			expectedType:  crypto.KeyTypePublic,
			pemHeaderType: "PUBLIC KEY",
		},
		{
			name:          "AES key returns PEM format",
			algorithm:     crypto.AlgorithmAES,
			keySize:       256,
			expectedType:  crypto.KeyTypeSymmetric,
			pemHeaderType: "AES KEY",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			services := SetupTestServices(t, config.SqliteDbType)
			ctx := context.Background()
			userID := uuid.NewString()

			// Upload keys
			cryptoKeyMetas, err := services.CryptoKeyUploadService.Upload(ctx, userID, tt.algorithm, tt.keySize)
			require.NoError(t, err)
			require.NotEmpty(t, cryptoKeyMetas)

			// Find the key with expected type
			var targetKeyMeta *keys.CryptoKeyMeta
			for _, keyMeta := range cryptoKeyMetas {
				if keyMeta.Type == tt.expectedType {
					targetKeyMeta = keyMeta
					break
				}
			}
			require.NotNil(t, targetKeyMeta, "expected key type not found")

			// Download key (should be in PEM format)
			pemBytes, err := services.CryptoKeyDownloadService.DownloadByID(ctx, targetKeyMeta.ID)
			require.NoError(t, err)
			require.NotEmpty(t, pemBytes)

			// Verify PEM format
			block, rest := pem.Decode(pemBytes)
			require.NotNil(t, block, "failed to decode PEM block")
			require.Empty(t, rest, "unexpected data after PEM block")
			require.Equal(t, tt.pemHeaderType, block.Type)
			require.NotEmpty(t, block.Bytes)

			// Verify PEM structure
			pemString := string(pemBytes)
			expectedHeader := fmt.Sprintf("-----BEGIN %s-----", tt.pemHeaderType)
			expectedFooter := fmt.Sprintf("-----END %s-----", tt.pemHeaderType)
			require.Contains(t, pemString, expectedHeader)
			require.Contains(t, pemString, expectedFooter)
		})
	}
}

// TestCryptoKeyMetadataService_Operations uses subtests for metadata operations
func TestCryptoKeyMetadataService_Operations(t *testing.T) {
	t.Run("get by ID returns correct metadata", func(t *testing.T) {
		services := SetupTestServices(t, config.SqliteDbType)
		userID := uuid.NewString()
		ctx := context.Background()

		cryptoKeyMetas, err := services.CryptoKeyUploadService.Upload(ctx, userID, crypto.AlgorithmECDSA, 256)
		require.NoError(t, err)

		fetchedCryptoKeyMeta, err := services.CryptoKeyMetadataService.GetByID(ctx, cryptoKeyMetas[0].ID)
		require.NoError(t, err)
		require.NotNil(t, fetchedCryptoKeyMeta)
		require.Equal(t, cryptoKeyMetas[0].ID, fetchedCryptoKeyMeta.ID)
		require.Equal(t, cryptoKeyMetas[0].Algorithm, fetchedCryptoKeyMeta.Algorithm)
		require.Equal(t, cryptoKeyMetas[0].KeySize, fetchedCryptoKeyMeta.KeySize)
	})

	t.Run("delete by ID removes key from database", func(t *testing.T) {
		services := SetupTestServices(t, config.SqliteDbType)
		userID := uuid.NewString()
		ctx := context.Background()

		cryptoKeyMetas, err := services.CryptoKeyUploadService.Upload(ctx, userID, crypto.AlgorithmECDSA, 521)
		require.NoError(t, err)

		err = services.CryptoKeyMetadataService.DeleteByID(ctx, cryptoKeyMetas[0].ID)
		require.NoError(t, err)

		var deletedCryptoKeyMeta keys.CryptoKeyMeta
		err = services.DBContext.DB.First(&deletedCryptoKeyMeta, "id = ?", cryptoKeyMetas[0].ID).Error
		require.Error(t, err)
		require.Equal(t, gorm.ErrRecordNotFound, err)
	})

	t.Run("list returns all uploaded keys", func(t *testing.T) {
		services := SetupTestServices(t, config.SqliteDbType)
		userID := uuid.NewString()
		ctx := context.Background()

		// Create multiple keys
		_, err := services.CryptoKeyUploadService.Upload(ctx, userID, crypto.AlgorithmECDSA, 256)
		require.NoError(t, err)

		_, err = services.CryptoKeyUploadService.Upload(ctx, userID, crypto.AlgorithmRSA, 2048)
		require.NoError(t, err)

		query := &keys.CryptoKeyQuery{}
		cryptoKeys, err := services.CryptoKeyMetadataService.List(ctx, query)
		require.NoError(t, err)
		require.NotNil(t, cryptoKeys)
		require.GreaterOrEqual(t, len(cryptoKeys), 4) // 2 EC keys + 2 RSA keys
	})

	t.Run("download returns non-empty key data", func(t *testing.T) {
		services := SetupTestServices(t, config.SqliteDbType)
		userID := uuid.NewString()
		ctx := context.Background()

		cryptoKeyMetas, err := services.CryptoKeyUploadService.Upload(ctx, userID, crypto.AlgorithmECDSA, 256)
		require.NoError(t, err)

		pemData, err := services.CryptoKeyDownloadService.DownloadByID(ctx, cryptoKeyMetas[0].ID)
		require.NoError(t, err)
		require.NotNil(t, pemData)
		require.NotEmpty(t, pemData)

		// Verify it's valid PEM
		block, _ := pem.Decode(pemData)
		require.NotNil(t, block)
	})

	t.Run("get non-existent key returns error", func(t *testing.T) {
		services := SetupTestServices(t, config.SqliteDbType)
		ctx := context.Background()

		nonExistentID := uuid.NewString()
		_, err := services.CryptoKeyMetadataService.GetByID(ctx, nonExistentID)
		require.Error(t, err)
	})

	t.Run("delete non-existent key returns error", func(t *testing.T) {
		services := SetupTestServices(t, config.SqliteDbType)
		ctx := context.Background()

		nonExistentID := uuid.NewString()
		err := services.CryptoKeyMetadataService.DeleteByID(ctx, nonExistentID)
		require.Error(t, err)
	})
}

// TestCryptoKeyUploadService_KeyPairLinking verifies key pairs are linked correctly
func TestCryptoKeyUploadService_KeyPairLinking(t *testing.T) {
	tests := []struct {
		name      string
		algorithm string
		keySize   uint32
	}{
		{
			name:      "RSA key pair linking",
			algorithm: crypto.AlgorithmRSA,
			keySize:   2048,
		},
		{
			name:      "ECDSA key pair linking",
			algorithm: crypto.AlgorithmECDSA,
			keySize:   256,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			services := SetupTestServices(t, config.SqliteDbType)
			userID := uuid.NewString()
			ctx := context.Background()

			cryptoKeyMetas, err := services.CryptoKeyUploadService.Upload(ctx, userID, tt.algorithm, tt.keySize)
			require.NoError(t, err)
			require.Len(t, cryptoKeyMetas, 2)

			// Verify both keys have the same KeyPairID
			privateKey := cryptoKeyMetas[0]
			publicKey := cryptoKeyMetas[1]

			require.Equal(t, crypto.KeyTypePrivate, privateKey.Type)
			require.Equal(t, crypto.KeyTypePublic, publicKey.Type)
			require.NotEmpty(t, privateKey.KeyPairID)
			require.NotEmpty(t, publicKey.KeyPairID)
			require.Equal(t, privateKey.KeyPairID, publicKey.KeyPairID, "key pair should have matching KeyPairID")
		})
	}
}
