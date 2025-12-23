//go:build integration
// +build integration

package app

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"crypto_vault_service/internal/domain/keys"
	"crypto_vault_service/internal/infrastructure/persistence"
)

func TestCryptoKeyUploadService_Upload_Success(t *testing.T) {
	services := SetupTestServices(t, persistence.SqliteDbType)

	userID := uuid.NewString()
	keyAlgorithm := AlgorithmEC
	var keySize uint32 = 256
	ctx := context.Background()

	cryptoKeyMetas, err := services.CryptoKeyUploadService.Upload(ctx, userID, keyAlgorithm, keySize)
	require.NoError(t, err)
	require.Len(t, cryptoKeyMetas, 2)
	require.NotEmpty(t, cryptoKeyMetas[0].ID)
	require.Equal(t, userID, cryptoKeyMetas[0].UserID)
	require.NotEmpty(t, cryptoKeyMetas[1].ID)
	require.Equal(t, userID, cryptoKeyMetas[1].UserID)
}

func TestCryptoKeyUploadService_Upload_AES_KeySizes(t *testing.T) {
	tests := []struct {
		name    string
		keySize uint32
		wantErr bool
		errMsg  string
	}{
		{"Valid 128-bit", 128, false, ""},
		{"Valid 192-bit", 192, false, ""},
		{"Valid 256-bit", 256, false, ""},
		{"Invalid 512-bit", 512, true, "not supported for AES"},
		{"Invalid 64-bit", 64, true, "not supported for AES"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			services := SetupTestServices(t, persistence.SqliteDbType)
			userID := uuid.NewString()
			ctx := context.Background()

			cryptoKeyMetas, err := services.CryptoKeyUploadService.Upload(ctx, userID, AlgorithmAES, tt.keySize)

			if tt.wantErr {
				require.Error(t, err)
				require.Nil(t, cryptoKeyMetas)
				require.Contains(t, err.Error(), tt.errMsg)
			} else {
				require.NoError(t, err)
				require.Len(t, cryptoKeyMetas, 1)
				require.Equal(t, tt.keySize, cryptoKeyMetas[0].KeySize)
			}
		})
	}
}

func TestCryptoKeyUploadService_Upload_AES_InvalidSize_Fail(t *testing.T) {
	services := SetupTestServices(t, persistence.SqliteDbType)

	userID := uuid.NewString()
	ctx := context.Background()

	cryptoKeyMetas, err := services.CryptoKeyUploadService.Upload(ctx, userID, AlgorithmAES, 512) // Invalid
	require.Error(t, err)
	require.Nil(t, cryptoKeyMetas)
	require.Contains(t, err.Error(), "not supported for AES")
}

func TestCryptoKeyMetadataService_GetByID_Success(t *testing.T) {
	services := SetupTestServices(t, persistence.SqliteDbType)

	userID := uuid.NewString()
	keyAlgorithm := AlgorithmEC
	var keySize uint32 = 256
	ctx := context.Background()

	cryptoKeyMetas, err := services.CryptoKeyUploadService.Upload(ctx, userID, keyAlgorithm, keySize)
	require.NoError(t, err)

	fetchedCryptoKeyMeta, err := services.CryptoKeyMetadataService.GetByID(ctx, cryptoKeyMetas[0].ID)
	require.NoError(t, err)
	require.NotNil(t, fetchedCryptoKeyMeta)
	require.Equal(t, cryptoKeyMetas[0].ID, fetchedCryptoKeyMeta.ID)
}

func TestCryptoKeyMetadataService_DeleteByID_Success(t *testing.T) {
	services := SetupTestServices(t, persistence.SqliteDbType)

	userID := uuid.NewString()
	keyAlgorithm := AlgorithmEC
	var keySize uint32 = 521
	ctx := context.Background()

	cryptoKeyMetas, err := services.CryptoKeyUploadService.Upload(ctx, userID, keyAlgorithm, keySize)
	require.NoError(t, err)

	err = services.CryptoKeyMetadataService.DeleteByID(ctx, cryptoKeyMetas[0].ID)
	require.NoError(t, err)

	var deletedCryptoKeyMeta keys.CryptoKeyMeta
	err = services.DBContext.DB.First(&deletedCryptoKeyMeta, "id = ?", cryptoKeyMetas[0].ID).Error
	require.Error(t, err)
	require.Equal(t, gorm.ErrRecordNotFound, err)
}

func TestCryptoKeyDownloadService_Download_Success(t *testing.T) {
	services := SetupTestServices(t, persistence.SqliteDbType)

	userID := uuid.NewString()
	keyAlgorithm := AlgorithmEC
	var keySize uint32 = 256
	ctx := context.Background()

	cryptoKeyMetas, err := services.CryptoKeyUploadService.Upload(ctx, userID, keyAlgorithm, keySize)
	require.NoError(t, err)

	blobData, err := services.CryptoKeyDownloadService.DownloadByID(ctx, cryptoKeyMetas[0].ID)
	require.NoError(t, err)
	require.NotNil(t, blobData)
	require.NotEmpty(t, blobData)
}
func TestCryptoKeyMetadataService_List_Success(t *testing.T) {
	services := SetupTestServices(t, persistence.SqliteDbType)

	userID := uuid.NewString()
	ctx := context.Background()

	// Create multiple keys
	_, err := services.CryptoKeyUploadService.Upload(ctx, userID, AlgorithmEC, 256)
	require.NoError(t, err)

	_, err = services.CryptoKeyUploadService.Upload(ctx, userID, AlgorithmRSA, 2048)
	require.NoError(t, err)

	query := &keys.CryptoKeyQuery{}
	cryptoKeys, err := services.CryptoKeyMetadataService.List(ctx, query)
	require.NoError(t, err)
	require.NotNil(t, cryptoKeys)
	require.GreaterOrEqual(t, len(cryptoKeys), 4) // 2 EC keys + 2 RSA keys
}
