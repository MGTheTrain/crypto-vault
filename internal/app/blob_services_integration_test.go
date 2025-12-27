//go:build integration
// +build integration

package app

import (
	"context"
	"mime/multipart"
	"testing"

	"github.com/MGTheTrain/crypto-vault/internal/domain/blobs"
	"github.com/MGTheTrain/crypto-vault/internal/domain/cryptoalg"
	"github.com/MGTheTrain/crypto-vault/internal/infrastructure/persistence/models"
	"github.com/MGTheTrain/crypto-vault/internal/pkg/config"
	"github.com/MGTheTrain/crypto-vault/internal/pkg/testutil"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

// TestBlobUploadService_Upload_Success uses table-driven tests for success scenarios
func TestBlobUploadService_Upload_Success(t *testing.T) {
	tests := []struct {
		name                string
		fileContent         []byte
		fileName            string
		setupKeys           func(ctx context.Context, services *TestServices, userID string) (encKeyID, signKeyID *string, err error)
		wantEncrypted       bool
		wantSigned          bool
		wantSignatureBlob   bool
		wantSignatureFormat string
	}{
		{
			name:        "plain upload without encryption or signing",
			fileContent: []byte("Plain file content"),
			fileName:    "plain.txt",
			setupKeys: func(ctx context.Context, services *TestServices, userID string) (*string, *string, error) {
				return nil, nil, nil
			},
			wantEncrypted:     false,
			wantSigned:        false,
			wantSignatureBlob: false,
		},
		{
			name:        "RSA encryption and signing",
			fileContent: []byte("RSA encrypted and signed"),
			fileName:    "secure.pdf",
			setupKeys: func(ctx context.Context, services *TestServices, userID string) (*string, *string, error) {
				rsaKeys, err := services.CryptoKeyUploadService.Upload(ctx, userID, cryptoalg.AlgorithmRSA, 2048)
				if err != nil {
					return nil, nil, err
				}
				signKeyID := rsaKeys[0].ID       // private key
				encryptionKeyID := rsaKeys[1].ID // public key
				return &encryptionKeyID, &signKeyID, nil
			},
			wantEncrypted:       true,
			wantSigned:          true,
			wantSignatureBlob:   true,
			wantSignatureFormat: ".pdf.sig",
		},
		{
			name:        "AES encryption with ECDSA signing",
			fileContent: []byte("AES encrypted, ECDSA signed"),
			fileName:    "hybrid.doc",
			setupKeys: func(ctx context.Context, services *TestServices, userID string) (*string, *string, error) {
				ecKeys, err := services.CryptoKeyUploadService.Upload(ctx, userID, cryptoalg.AlgorithmECDSA, 256)
				if err != nil {
					return nil, nil, err
				}
				aesKeys, err := services.CryptoKeyUploadService.Upload(ctx, userID, cryptoalg.AlgorithmAES, 256)
				if err != nil {
					return nil, nil, err
				}
				signKeyID := ecKeys[0].ID
				encKeyID := aesKeys[0].ID
				return &encKeyID, &signKeyID, nil
			},
			wantEncrypted:       true,
			wantSigned:          true,
			wantSignatureBlob:   true,
			wantSignatureFormat: ".doc.sig",
		},
		{
			name:        "RSA signing only",
			fileContent: []byte("RSA signed document"),
			fileName:    "contract.txt",
			setupKeys: func(ctx context.Context, services *TestServices, userID string) (*string, *string, error) {
				rsaKeys, err := services.CryptoKeyUploadService.Upload(ctx, userID, cryptoalg.AlgorithmRSA, 2048)
				if err != nil {
					return nil, nil, err
				}
				signKeyID := rsaKeys[0].ID
				return nil, &signKeyID, nil
			},
			wantEncrypted:       false,
			wantSigned:          true,
			wantSignatureBlob:   true,
			wantSignatureFormat: ".txt.sig",
		},
		{
			name:        "ECDSA signing only",
			fileContent: []byte("ECDSA signed content"),
			fileName:    "message.bin",
			setupKeys: func(ctx context.Context, services *TestServices, userID string) (*string, *string, error) {
				ecKeys, err := services.CryptoKeyUploadService.Upload(ctx, userID, cryptoalg.AlgorithmECDSA, 256)
				if err != nil {
					return nil, nil, err
				}
				signKeyID := ecKeys[0].ID
				return nil, &signKeyID, nil
			},
			wantEncrypted:       false,
			wantSigned:          true,
			wantSignatureBlob:   true,
			wantSignatureFormat: ".bin.sig",
		},
		{
			name:        "AES encryption only",
			fileContent: []byte("AES encrypted only"),
			fileName:    "encrypted.dat",
			setupKeys: func(ctx context.Context, services *TestServices, userID string) (*string, *string, error) {
				aesKeys, err := services.CryptoKeyUploadService.Upload(ctx, userID, cryptoalg.AlgorithmAES, 256)
				if err != nil {
					return nil, nil, err
				}
				encKeyID := aesKeys[0].ID
				return &encKeyID, nil, nil
			},
			wantEncrypted:     true,
			wantSigned:        false,
			wantSignatureBlob: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			services := SetupTestServices(t, config.SqliteDbType)
			ctx := context.Background()
			userID := uuid.NewString()

			// Create test form
			form, err := testutil.CreateTestFileAndForm(t, tt.fileName, tt.fileContent)
			require.NoError(t, err)

			// Setup keys
			encKeyID, signKeyID, err := tt.setupKeys(ctx, services, userID)
			require.NoError(t, err)

			// Upload
			blobMetas, err := services.BlobUploadService.Upload(ctx, form, userID, encKeyID, signKeyID)
			require.NoError(t, err)
			require.Len(t, blobMetas, 1)

			uploadedBlob := blobMetas[0]
			require.NotEmpty(t, uploadedBlob.ID)
			require.Equal(t, userID, uploadedBlob.UserID)
			require.Equal(t, tt.fileName, uploadedBlob.Name)

			// Verify encryption
			if tt.wantEncrypted {
				require.NotNil(t, uploadedBlob.EncryptionKeyID)
			} else {
				require.Nil(t, uploadedBlob.EncryptionKeyID)
			}

			// Verify signing
			if tt.wantSigned {
				require.NotNil(t, uploadedBlob.SignKeyID)
			} else {
				require.Nil(t, uploadedBlob.SignKeyID)
			}

			// Verify signature blob
			if tt.wantSignatureBlob {
				require.NotNil(t, uploadedBlob.SignatureBlobID)
				require.NotNil(t, uploadedBlob.SignatureFileName)
				require.Contains(t, *uploadedBlob.SignatureFileName, tt.wantSignatureFormat)

				// Verify signature blob exists
				sigBlob, err := services.BlobMetadataService.GetByID(ctx, *uploadedBlob.SignatureBlobID)
				require.NoError(t, err)
				require.Greater(t, sigBlob.Size, int64(0))
			} else {
				require.Nil(t, uploadedBlob.SignatureBlobID)
				require.Nil(t, uploadedBlob.SignatureFileName)
			}
		})
	}
}

// TestBlobUploadService_Upload_Errors uses table-driven tests for error scenarios
func TestBlobUploadService_Upload_Errors(t *testing.T) {
	tests := []struct {
		name            string
		fileContent     []byte
		fileName        string
		setupForm       func(t *testing.T, fileName string, content []byte) (*multipart.Form, error)
		setupKeys       func(ctx context.Context, services *TestServices, userID string) (encKeyID, signKeyID *string, err error)
		wantErrContains string
	}{
		{
			name:        "empty form fails",
			fileContent: nil,
			fileName:    "",
			setupForm: func(t *testing.T, fileName string, content []byte) (*multipart.Form, error) {
				return testutil.CreateEmptyForm(), nil
			},
			setupKeys: func(ctx context.Context, services *TestServices, userID string) (*string, *string, error) {
				return nil, nil, nil
			},
			wantErrContains: "no files provided",
		},
		{
			name:        "invalid encryption key ID",
			fileContent: []byte("Test content"),
			fileName:    "test.txt",
			setupForm:   testutil.CreateTestFileAndForm,
			setupKeys: func(ctx context.Context, services *TestServices, userID string) (*string, *string, error) {
				invalidKeyID := "invalid-key-id"
				return &invalidKeyID, nil, nil
			},
			wantErrContains: "failed to get encryption key",
		},
		{
			name:        "invalid signing key ID",
			fileContent: []byte("Test content"),
			fileName:    "test.txt",
			setupForm:   testutil.CreateTestFileAndForm,
			setupKeys: func(ctx context.Context, services *TestServices, userID string) (*string, *string, error) {
				invalidKeyID := "invalid-sign-key"
				return nil, &invalidKeyID, nil
			},
			wantErrContains: "failed to get signing key",
		},
		{
			name:        "AES key used for signing fails",
			fileContent: []byte("Cannot sign with AES"),
			fileName:    "fail.txt",
			setupForm:   testutil.CreateTestFileAndForm,
			setupKeys: func(ctx context.Context, services *TestServices, userID string) (*string, *string, error) {
				aesKeys, err := services.CryptoKeyUploadService.Upload(ctx, userID, cryptoalg.AlgorithmAES, 256)
				if err != nil {
					return nil, nil, err
				}
				aesKeyID := aesKeys[0].ID
				return nil, &aesKeyID, nil
			},
			wantErrContains: "AES does not support signing",
		},
		{
			name:        "ECDSA key used for encryption fails",
			fileContent: []byte("Cannot encrypt with ECDSA"),
			fileName:    "fail2.txt",
			setupForm:   testutil.CreateTestFileAndForm,
			setupKeys: func(ctx context.Context, services *TestServices, userID string) (*string, *string, error) {
				ecKeys, err := services.CryptoKeyUploadService.Upload(ctx, userID, cryptoalg.AlgorithmECDSA, 256)
				if err != nil {
					return nil, nil, err
				}
				ecKeyID := ecKeys[0].ID
				return &ecKeyID, nil, nil
			},
			wantErrContains: "ECDSA does not support encryption",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			services := SetupTestServices(t, config.SqliteDbType)
			ctx := context.Background()
			userID := uuid.NewString()

			// Setup form
			form, err := tt.setupForm(t, tt.fileName, tt.fileContent)
			require.NoError(t, err)

			// Setup keys
			encKeyID, signKeyID, err := tt.setupKeys(ctx, services, userID)
			require.NoError(t, err)

			// Upload should fail
			blobMetas, err := services.BlobUploadService.Upload(ctx, form, userID, encKeyID, signKeyID)
			require.Error(t, err)
			require.Nil(t, blobMetas)
			require.Contains(t, err.Error(), tt.wantErrContains)
		})
	}
}

// TestBlobDownloadService_Download uses table-driven tests
func TestBlobDownloadService_Download(t *testing.T) {
	tests := []struct {
		name            string
		fileContent     []byte
		fileName        string
		setupEncryption func(ctx context.Context, services *TestServices, userID string) (encKeyID, decKeyID *string, err error) // ✅ FIX: Return both keys
		wantContent     []byte
		wantErr         bool
	}{
		{
			name:        "download plain file",
			fileContent: []byte("Plain content"),
			fileName:    "plain.txt",
			setupEncryption: func(ctx context.Context, services *TestServices, userID string) (*string, *string, error) {
				return nil, nil, nil
			},
			wantContent: []byte("Plain content"),
			wantErr:     false,
		},
		{
			name:        "download with AES decryption",
			fileContent: []byte("Secret AES content"),
			fileName:    "secret.txt",
			setupEncryption: func(ctx context.Context, services *TestServices, userID string) (*string, *string, error) {
				aesKeys, err := services.CryptoKeyUploadService.Upload(ctx, userID, cryptoalg.AlgorithmAES, 256)
				if err != nil {
					return nil, nil, err
				}
				encKeyID := aesKeys[0].ID
				return &encKeyID, &encKeyID, nil
			},
			wantContent: []byte("Secret AES content"),
			wantErr:     false,
		},
		{
			name:        "download with RSA decryption",
			fileContent: []byte("Secret RSA content"),
			fileName:    "rsa_secret.txt",
			setupEncryption: func(ctx context.Context, services *TestServices, userID string) (*string, *string, error) {
				rsaKeys, err := services.CryptoKeyUploadService.Upload(ctx, userID, cryptoalg.AlgorithmRSA, 2048)
				if err != nil {
					return nil, nil, err
				}
				privateKeyID := rsaKeys[0].ID           // Private key for decryption
				publicKeyID := rsaKeys[1].ID            // Public key for encryption
				return &publicKeyID, &privateKeyID, nil // Return both keys from same pair
			},
			wantContent: []byte("Secret RSA content"),
			wantErr:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			services := SetupTestServices(t, config.SqliteDbType)
			ctx := context.Background()
			userID := uuid.NewString()

			// Setup encryption key
			encKeyID, decKeyID, err := tt.setupEncryption(ctx, services, userID)
			require.NoError(t, err)

			// Upload file
			form, err := testutil.CreateTestFileAndForm(t, tt.fileName, tt.fileContent)
			require.NoError(t, err)

			blobMetas, err := services.BlobUploadService.Upload(ctx, form, userID, encKeyID, nil)
			require.NoError(t, err)
			require.Len(t, blobMetas, 1)

			// Download file with appropriate decryption key
			downloadedContent, err := services.BlobDownloadService.DownloadByID(ctx, blobMetas[0].ID, decKeyID)

			if tt.wantErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			require.Equal(t, tt.wantContent, downloadedContent)
		})
	}
}

// Keep simple tests for metadata operations
func TestBlobMetadataService_Operations(t *testing.T) {
	t.Run("list blobs", func(t *testing.T) {
		services := SetupTestServices(t, config.SqliteDbType)
		ctx := context.Background()

		form, err := testutil.CreateTestFileAndForm(t, "test.txt", []byte("content"))
		require.NoError(t, err)

		_, err = services.BlobUploadService.Upload(ctx, form, uuid.NewString(), nil, nil)
		require.NoError(t, err)

		blobMetas, err := services.BlobMetadataService.List(ctx, &blobs.BlobMetaQuery{})
		require.NoError(t, err)
		require.Greater(t, len(blobMetas), 0)
	})

	t.Run("get by ID", func(t *testing.T) {
		services := SetupTestServices(t, config.SqliteDbType)
		ctx := context.Background()

		form, err := testutil.CreateTestFileAndForm(t, "test.txt", []byte("content"))
		require.NoError(t, err)

		uploaded, err := services.BlobUploadService.Upload(ctx, form, uuid.NewString(), nil, nil)
		require.NoError(t, err)

		blob, err := services.BlobMetadataService.GetByID(ctx, uploaded[0].ID)
		require.NoError(t, err)
		require.Equal(t, uploaded[0].ID, blob.ID)
	})

	t.Run("delete by ID", func(t *testing.T) {
		services := SetupTestServices(t, config.SqliteDbType)
		ctx := context.Background()

		form, err := testutil.CreateTestFileAndForm(t, "test.txt", []byte("content"))
		require.NoError(t, err)

		uploaded, err := services.BlobUploadService.Upload(ctx, form, uuid.NewString(), nil, nil)
		require.NoError(t, err)

		err = services.BlobMetadataService.DeleteByID(ctx, uploaded[0].ID)
		require.NoError(t, err)

		// Use GORM model with correct table name
		var deletedBlobModel models.BlobModel
		err = services.DBContext.DB.First(&deletedBlobModel, "id = ?", uploaded[0].ID).Error
		require.Equal(t, gorm.ErrRecordNotFound, err)
	})
}
