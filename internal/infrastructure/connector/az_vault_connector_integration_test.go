//go:build integration
// +build integration

package connector

import (
	"context"
	"testing"
	"time"

	"crypto_vault_service/internal/domain/keys"
	"crypto_vault_service/internal/pkg/config"
	pkgTesting "crypto_vault_service/internal/pkg/testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type AzureVaultConnectorTest struct {
	vaultConnector keys.VaultConnector
}

func NewAzureVaultConnectorTest(t *testing.T, cloudProvider, connectionString, containerName string) *AzureVaultConnectorTest {
	t.Helper()
	logger := pkgTesting.SetupTestLogger(t)

	keyConnectorSettings := &config.KeyConnectorSettings{
		CloudProvider:    cloudProvider,
		ConnectionString: connectionString,
		ContainerName:    containerName,
	}

	ctx := context.Background()
	vaultConnector, err := NewAzureVaultConnector(ctx, keyConnectorSettings, logger)
	require.NoError(t, err)

	return &AzureVaultConnectorTest{
		vaultConnector: vaultConnector,
	}
}

func TestAzureVaultConnector_Upload(t *testing.T) {
	avct := NewAzureVaultConnectorTest(t, TestCloudProvider, TestConnectionString, TestContainerName)

	testFileContent := []byte("This is a test file content.")
	userID := uuid.New().String()
	keyPairID := uuid.New().String()
	keyAlgorithm := "RSA"
	keyType := "private"
	keySize := uint32(2048)
	ctx := context.Background()

	cryptoKeyMeta, err := avct.vaultConnector.Upload(ctx, testFileContent, userID, keyPairID, keyType, keyAlgorithm, keySize)
	require.NoError(t, err)

	assert.NotEmpty(t, cryptoKeyMeta.ID)
	assert.Equal(t, keyType, cryptoKeyMeta.Type)
	assert.Equal(t, keyAlgorithm, cryptoKeyMeta.Algorithm)
	assert.Equal(t, keySize, cryptoKeyMeta.KeySize)
	assert.Equal(t, userID, cryptoKeyMeta.UserID)
	assert.Equal(t, keyPairID, cryptoKeyMeta.KeyPairID)
	assert.WithinDuration(t, time.Now(), cryptoKeyMeta.DateTimeCreated, time.Second)

	err = avct.vaultConnector.Delete(ctx, cryptoKeyMeta.ID, cryptoKeyMeta.KeyPairID, cryptoKeyMeta.Type)
	require.NoError(t, err)
}

func TestAzureVaultConnector_Download(t *testing.T) {
	avct := NewAzureVaultConnectorTest(t, TestCloudProvider, TestConnectionString, TestContainerName)

	testFileContent := []byte("This is a test file content.")
	userID := uuid.New().String()
	keyPairID := uuid.New().String()
	keyAlgorithm := "RSA"
	keyType := "private"
	keySize := uint32(2048)
	ctx := context.Background()

	cryptoKeyMeta, err := avct.vaultConnector.Upload(ctx, testFileContent, userID, keyPairID, keyType, keyAlgorithm, keySize)
	require.NoError(t, err)

	downloadedData, err := avct.vaultConnector.Download(ctx, cryptoKeyMeta.ID, cryptoKeyMeta.KeyPairID, cryptoKeyMeta.Type)
	require.NoError(t, err)
	assert.Equal(t, testFileContent, downloadedData)

	err = avct.vaultConnector.Delete(ctx, cryptoKeyMeta.ID, cryptoKeyMeta.KeyPairID, cryptoKeyMeta.Type)
	require.NoError(t, err)
}

func TestAzureVaultConnector_Download_NotFound(t *testing.T) {
	avct := NewAzureVaultConnectorTest(t, TestCloudProvider, TestConnectionString, TestContainerName)

	nonExistentID := uuid.New().String()
	keyPairID := uuid.New().String()
	ctx := context.Background()

	_, err := avct.vaultConnector.Download(ctx, nonExistentID, keyPairID, "private")
	assert.Error(t, err)
}

func TestAzureVaultConnector_Delete(t *testing.T) {
	avct := NewAzureVaultConnectorTest(t, TestCloudProvider, TestConnectionString, TestContainerName)

	testFileContent := []byte("This is a test file content.")
	userID := uuid.New().String()
	keyPairID := uuid.New().String()
	keyAlgorithm := "RSA"
	keyType := "private"
	keySize := uint32(2048)
	ctx := context.Background()

	cryptoKeyMeta, err := avct.vaultConnector.Upload(ctx, testFileContent, userID, keyPairID, keyType, keyAlgorithm, keySize)
	require.NoError(t, err)

	err = avct.vaultConnector.Delete(ctx, cryptoKeyMeta.ID, cryptoKeyMeta.KeyPairID, cryptoKeyMeta.Type)
	require.NoError(t, err)

	_, err = avct.vaultConnector.Download(ctx, cryptoKeyMeta.ID, cryptoKeyMeta.KeyPairID, cryptoKeyMeta.Type)
	assert.Error(t, err)
}

func TestNewAzureVaultConnector_InvalidSettings(t *testing.T) {
	logger := pkgTesting.SetupTestLogger(t)
	ctx := context.Background()

	invalidSettings := &config.KeyConnectorSettings{
		CloudProvider:    "",
		ConnectionString: "",
		ContainerName:    "",
	}

	_, err := NewAzureVaultConnector(ctx, invalidSettings, logger)
	assert.Error(t, err)
}
