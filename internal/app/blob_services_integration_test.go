//go:build integration
// +build integration

package app

import (
	"context"
	"crypto_vault_service/internal/domain/blobs"
	"crypto_vault_service/internal/domain/crypto"
	"crypto_vault_service/internal/pkg/config"
	pkgTesting "crypto_vault_service/internal/pkg/testing"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

func TestBlobUploadService_Upload_With_RSA_Encryption_And_Signing_Success(t *testing.T) {
	services := SetupTestServices(t, config.SqliteDbType)

	testFileContent := []byte("This is test file content")
	testFileName := "testfile.txt"
	form, err := pkgTesting.CreateTestFileAndForm(t, testFileName, testFileContent)
	require.NoError(t, err)

	userID := uuid.NewString()
	ctx := context.Background()

	// Generate RSA key pair
	cryptoKeyMetas, err := services.CryptoKeyUploadService.Upload(ctx, userID, crypto.AlgorithmRSA, 2048)
	require.NoError(t, err)
	require.Len(t, cryptoKeyMetas, 2)

	signKeyID := cryptoKeyMetas[0].ID       // private key
	encryptionKeyID := cryptoKeyMetas[1].ID // public key

	blobMetas, err := services.BlobUploadService.Upload(ctx, form, userID, &encryptionKeyID, &signKeyID)
	require.NoError(t, err)
	require.NotNil(t, blobMetas)
	require.NotEmpty(t, blobMetas[0].ID)
	require.Equal(t, userID, blobMetas[0].UserID)
}

func TestBlobUploadService_Upload_With_AES_Encryption_And_ECDSA_Signing_Success(t *testing.T) {
	services := SetupTestServices(t, config.SqliteDbType)

	testFileContent := []byte("This is test file content")
	testFileName := "testfile.txt"
	form, err := pkgTesting.CreateTestFileAndForm(t, testFileName, testFileContent)
	require.NoError(t, err)

	userID := uuid.NewString()
	ctx := context.Background()

	// Generate EC signing key
	ecKeys, err := services.CryptoKeyUploadService.Upload(ctx, userID, crypto.AlgorithmEC, 256)
	require.NoError(t, err)
	require.Len(t, ecKeys, 2)

	// Generate AES encryption key
	aesKeys, err := services.CryptoKeyUploadService.Upload(ctx, userID, crypto.AlgorithmAES, 256)
	require.NoError(t, err)
	require.Len(t, aesKeys, 1)

	signKeyID := ecKeys[0].ID        // private key
	encryptionKeyID := aesKeys[0].ID // symmetric key

	blobMetas, err := services.BlobUploadService.Upload(ctx, form, userID, &encryptionKeyID, &signKeyID)
	require.NoError(t, err)
	require.NotNil(t, blobMetas)
	require.NotEmpty(t, blobMetas[0].ID)
	require.Equal(t, userID, blobMetas[0].UserID)
}

func TestBlobUploadService_Upload_Without_Encryption_And_Signing_Success(t *testing.T) {
	services := SetupTestServices(t, config.SqliteDbType)

	testFileContent := []byte("This is test file content")
	testFileName := "testfile.txt"
	form, err := pkgTesting.CreateTestFileAndForm(t, testFileName, testFileContent)
	require.NoError(t, err)

	userID := uuid.NewString()
	ctx := context.Background()

	blobMetas, err := services.BlobUploadService.Upload(ctx, form, userID, nil, nil)
	require.NoError(t, err)
	require.NotNil(t, blobMetas)
	require.NotEmpty(t, blobMetas[0].ID)
	require.Equal(t, userID, blobMetas[0].UserID)
}

func TestBlobUploadService_Upload_Fail_InvalidEncryptionKey(t *testing.T) {
	services := SetupTestServices(t, config.SqliteDbType)

	testFileContent := []byte("This is test file content")
	testFileName := "testfile.txt"
	form, err := pkgTesting.CreateTestFileAndForm(t, testFileName, testFileContent)
	require.NoError(t, err)

	userID := uuid.NewString()
	invalidEncryptionKeyID := "invalid-encryption-key-id"
	signKeyID := uuid.NewString()
	ctx := context.Background()

	blobMetas, err := services.BlobUploadService.Upload(ctx, form, userID, &invalidEncryptionKeyID, &signKeyID)
	require.Error(t, err)
	require.Nil(t, blobMetas)
}

func TestBlobDownloadService_Download_Success(t *testing.T) {
	services := SetupTestServices(t, config.SqliteDbType)

	testFileContent := []byte("This is test file content")
	testFileName := "testfile.txt"
	form, err := pkgTesting.CreateTestFileAndForm(t, testFileName, testFileContent)
	require.NoError(t, err)

	userID := uuid.NewString()
	ctx := context.Background()

	blobMetas, err := services.BlobUploadService.Upload(ctx, form, userID, nil, nil)
	require.NoError(t, err)
	require.NotNil(t, blobMetas)

	blobData, err := services.BlobDownloadService.DownloadByID(ctx, blobMetas[0].ID, nil)
	require.NoError(t, err)
	require.NotNil(t, blobData)
	require.NotEmpty(t, blobData)
}

func TestBlobDownloadService_Download_Fail_InvalidDecryptionKey(t *testing.T) {
	services := SetupTestServices(t, config.SqliteDbType)

	blobID := uuid.NewString()
	invalidDecryptionKeyID := "invalid-decryption-key-id"
	ctx := context.Background()

	blobData, err := services.BlobDownloadService.DownloadByID(ctx, blobID, &invalidDecryptionKeyID)
	require.Error(t, err)
	require.Nil(t, blobData)
}

func TestBlobDownloadService_Download_With_AES_Decryption_Success(t *testing.T) {
	services := SetupTestServices(t, config.SqliteDbType)

	testFileContent := []byte("This is secret content")
	testFileName := "secret.txt"
	form, err := pkgTesting.CreateTestFileAndForm(t, testFileName, testFileContent)
	require.NoError(t, err)

	userID := uuid.NewString()
	ctx := context.Background()

	// Generate AES encryption key
	aesKeys, err := services.CryptoKeyUploadService.Upload(ctx, userID, crypto.AlgorithmAES, 256)
	require.NoError(t, err)
	require.Len(t, aesKeys, 1)

	encryptionKeyID := aesKeys[0].ID

	// Upload encrypted blob
	blobMetas, err := services.BlobUploadService.Upload(ctx, form, userID, &encryptionKeyID, nil)
	require.NoError(t, err)
	require.NotNil(t, blobMetas)

	// Download with decryption
	decryptedData, err := services.BlobDownloadService.DownloadByID(ctx, blobMetas[0].ID, &encryptionKeyID)
	require.NoError(t, err)
	require.NotNil(t, decryptedData)
	require.Equal(t, testFileContent, decryptedData) // Verify decryption worked
}

func TestBlobDownloadService_Download_With_RSA_Decryption_Success(t *testing.T) {
	services := SetupTestServices(t, config.SqliteDbType)

	testFileContent := []byte("RSA encrypted secret")
	testFileName := "rsa_secret.txt"
	form, err := pkgTesting.CreateTestFileAndForm(t, testFileName, testFileContent)
	require.NoError(t, err)

	userID := uuid.NewString()
	ctx := context.Background()

	// Generate RSA key pair
	rsaKeys, err := services.CryptoKeyUploadService.Upload(ctx, userID, crypto.AlgorithmRSA, 2048)
	require.NoError(t, err)
	require.Len(t, rsaKeys, 2)

	privateKeyID := rsaKeys[0].ID // private key for decryption
	publicKeyID := rsaKeys[1].ID  // public key for encryption

	// Upload encrypted blob
	blobMetas, err := services.BlobUploadService.Upload(ctx, form, userID, &publicKeyID, nil)
	require.NoError(t, err)
	require.NotNil(t, blobMetas)

	// Download with decryption
	decryptedData, err := services.BlobDownloadService.DownloadByID(ctx, blobMetas[0].ID, &privateKeyID)
	require.NoError(t, err)
	require.NotNil(t, decryptedData)
	require.Equal(t, testFileContent, decryptedData)
}

func TestBlobMetadataService_List_Success(t *testing.T) {
	services := SetupTestServices(t, config.SqliteDbType)

	testFileContent := []byte("This is test file content")
	testFileName := "testfile.txt"
	form, err := pkgTesting.CreateTestFileAndForm(t, testFileName, testFileContent)
	require.NoError(t, err)

	userID := uuid.NewString()
	ctx := context.Background()

	blobMetas, err := services.BlobUploadService.Upload(ctx, form, userID, nil, nil)
	require.NoError(t, err)
	require.NotNil(t, blobMetas)

	query := &blobs.BlobMetaQuery{}
	blobMetas, err = services.BlobMetadataService.List(ctx, query)
	require.NoError(t, err)
	require.NotNil(t, blobMetas)
	require.Greater(t, len(blobMetas), 0)
}

func TestBlobMetadataService_GetByID_Success(t *testing.T) {
	services := SetupTestServices(t, config.SqliteDbType)

	testFileContent := []byte("This is test file content")
	testFileName := "testfile.txt"
	form, err := pkgTesting.CreateTestFileAndForm(t, testFileName, testFileContent)
	require.NoError(t, err)

	userID := uuid.NewString()
	ctx := context.Background()

	blobMetas, err := services.BlobUploadService.Upload(ctx, form, userID, nil, nil)
	require.NoError(t, err)
	require.NotNil(t, blobMetas)

	blobMeta, err := services.BlobMetadataService.GetByID(ctx, blobMetas[0].ID)
	require.NoError(t, err)
	require.NotNil(t, blobMeta)
	require.Equal(t, blobMetas[0].ID, blobMeta.ID)
}

func TestBlobMetadataService_DeleteByID_Success(t *testing.T) {
	services := SetupTestServices(t, config.SqliteDbType)

	testFileContent := []byte("This is test file content")
	testFileName := "testfile.txt"
	form, err := pkgTesting.CreateTestFileAndForm(t, testFileName, testFileContent)
	require.NoError(t, err)

	userID := uuid.NewString()
	ctx := context.Background()

	blobMetas, err := services.BlobUploadService.Upload(ctx, form, userID, nil, nil)
	require.NoError(t, err)
	require.NotNil(t, blobMetas)

	err = services.BlobMetadataService.DeleteByID(ctx, blobMetas[0].ID)
	require.NoError(t, err)

	var deletedBlobMeta blobs.BlobMeta
	err = services.DBContext.DB.First(&deletedBlobMeta, "id = ?", blobMetas[0].ID).Error
	require.Error(t, err)
	require.Equal(t, gorm.ErrRecordNotFound, err)
}
