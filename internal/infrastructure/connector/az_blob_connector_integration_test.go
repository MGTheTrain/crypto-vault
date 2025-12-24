//go:build integration
// +build integration

package connector

import (
	"context"
	"testing"

	"crypto_vault_service/internal/domain/blobs"
	"crypto_vault_service/internal/pkg/config"
	pkgTesting "crypto_vault_service/internal/pkg/testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type AzureBlobConnectorTest struct {
	blobConnector blobs.BlobConnector
}

func NewAzureBlobConnectorTest(t *testing.T, cloudProvider, connectionString, containerName string) *AzureBlobConnectorTest {
	t.Helper()
	logger := pkgTesting.SetupTestLogger(t)

	blobConnectorSettings := &config.BlobConnectorSettings{
		CloudProvider:    cloudProvider,
		ConnectionString: connectionString,
		ContainerName:    containerName,
	}

	ctx := context.Background()
	blobConnector, err := NewAzureBlobConnector(ctx, blobConnectorSettings, logger)
	require.NoError(t, err)

	return &AzureBlobConnectorTest{
		blobConnector: blobConnector,
	}
}

func TestAzureBlobConnector_Upload(t *testing.T) {
	abct := NewAzureBlobConnectorTest(t, TestCloudProvider, TestConnectionString, TestContainerName)

	testFileContent := []byte("This is test file content")
	testFileName := "testfile.txt"
	form, err := pkgTesting.CreateTestFileAndForm(t, testFileName, testFileContent)
	require.NoError(t, err)

	userID := uuid.New().String()
	ctx := context.Background()

	blobs, err := abct.blobConnector.Upload(ctx, form, userID, nil, nil)
	require.NoError(t, err)

	require.Len(t, blobs, 1)
	blob := blobs[0]
	assert.NotEmpty(t, blob.ID)
	assert.Equal(t, testFileName, blob.Name)
	assert.Equal(t, int64(len(testFileContent)), blob.Size)
	assert.Equal(t, ".txt", blob.Type)
	assert.Nil(t, blob.EncryptionKeyID)
	assert.Nil(t, blob.SignKeyID)

	err = abct.blobConnector.Delete(ctx, blob.ID, blob.Name)
	require.NoError(t, err)
}

func TestAzureBlobConnector_Upload_WithEncryptionAndSignKeys(t *testing.T) {
	abct := NewAzureBlobConnectorTest(t, TestCloudProvider, TestConnectionString, TestContainerName)

	testFileContent := []byte("encrypted content")
	testFileName := "encrypted.txt"
	form, err := pkgTesting.CreateTestFileAndForm(t, testFileName, testFileContent)
	require.NoError(t, err)

	userID := uuid.New().String()
	encryptionKeyID := uuid.New().String()
	signKeyID := uuid.New().String()
	ctx := context.Background()

	blobs, err := abct.blobConnector.Upload(ctx, form, userID, &encryptionKeyID, &signKeyID)
	require.NoError(t, err)

	require.Len(t, blobs, 1)
	blob := blobs[0]
	assert.NotNil(t, blob.EncryptionKeyID)
	assert.Equal(t, encryptionKeyID, *blob.EncryptionKeyID)
	assert.NotNil(t, blob.SignKeyID)
	assert.Equal(t, signKeyID, *blob.SignKeyID)

	err = abct.blobConnector.Delete(ctx, blob.ID, blob.Name)
	require.NoError(t, err)
}

func TestAzureBlobConnector_Download(t *testing.T) {
	abct := NewAzureBlobConnectorTest(t, TestCloudProvider, TestConnectionString, TestContainerName)

	testFileContent := []byte("This is test file content")
	testFileName := "testfile.pem"
	form, err := pkgTesting.CreateTestFileAndForm(t, testFileName, testFileContent)
	require.NoError(t, err)

	userID := uuid.New().String()
	ctx := context.Background()

	blobs, err := abct.blobConnector.Upload(ctx, form, userID, nil, nil)
	require.NoError(t, err)

	blob := blobs[0]

	downloadedData, err := abct.blobConnector.Download(ctx, blob.ID, blob.Name)
	require.NoError(t, err)
	assert.Equal(t, testFileContent, downloadedData)

	err = abct.blobConnector.Delete(ctx, blob.ID, blob.Name)
	require.NoError(t, err)
}

func TestAzureBlobConnector_Download_NotFound(t *testing.T) {
	abct := NewAzureBlobConnectorTest(t, TestCloudProvider, TestConnectionString, TestContainerName)

	nonExistentID := uuid.New().String()
	ctx := context.Background()

	_, err := abct.blobConnector.Download(ctx, nonExistentID, "nonexistent.txt")
	assert.Error(t, err)
}

func TestAzureBlobConnector_Delete(t *testing.T) {
	abct := NewAzureBlobConnectorTest(t, TestCloudProvider, TestConnectionString, TestContainerName)

	testFileContent := []byte("This is test file content")
	testFileName := "testfile.pem"
	form, err := pkgTesting.CreateTestFileAndForm(t, testFileName, testFileContent)
	require.NoError(t, err)

	userID := uuid.New().String()
	ctx := context.Background()

	blobs, err := abct.blobConnector.Upload(ctx, form, userID, nil, nil)
	require.NoError(t, err)

	blob := blobs[0]

	err = abct.blobConnector.Delete(ctx, blob.ID, blob.Name)
	require.NoError(t, err)

	_, err = abct.blobConnector.Download(ctx, blob.ID, blob.Name)
	assert.Error(t, err)
}

func TestNewAzureBlobConnector_InvalidSettings(t *testing.T) {
	logger := pkgTesting.SetupTestLogger(t)
	ctx := context.Background()

	invalidSettings := &config.BlobConnectorSettings{
		CloudProvider:    "",
		ConnectionString: "",
		ContainerName:    "",
	}

	_, err := NewAzureBlobConnector(ctx, invalidSettings, logger)
	assert.Error(t, err)
}
