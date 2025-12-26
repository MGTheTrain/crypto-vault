//go:build integration
// +build integration

package app

import (
	"context"
	"testing"

	"github.com/MGTheTrain/crypto-vault/internal/domain/blobs"
	"github.com/MGTheTrain/crypto-vault/internal/domain/keys"
	"github.com/MGTheTrain/crypto-vault/internal/infrastructure/connector"
	"github.com/MGTheTrain/crypto-vault/internal/infrastructure/cryptography"
	"github.com/MGTheTrain/crypto-vault/internal/infrastructure/persistence"
	"github.com/MGTheTrain/crypto-vault/internal/pkg/config"
	pkgTesting "github.com/MGTheTrain/crypto-vault/internal/pkg/testing"

	"github.com/stretchr/testify/require"
)

// Test constants for Azure Blob Storage (Azurite)
const (
	TestCloudProvider    = "azure"
	TestConnectionString = "DefaultEndpointsProtocol=http;AccountName=devstoreaccount1;AccountKey=Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw==;BlobEndpoint=http://127.0.0.1:10000/devstoreaccount1;"
	TestContainerName    = "testblobs"
)

// TestServices holds all application services and dependencies for testing
type TestServices struct {
	// Blob services
	BlobUploadService   blobs.BlobUploadService
	BlobDownloadService blobs.BlobDownloadService
	BlobMetadataService blobs.BlobMetadataService

	// Crypto key services
	CryptoKeyUploadService   keys.CryptoKeyUploadService
	CryptoKeyMetadataService keys.CryptoKeyMetadataService
	CryptoKeyDownloadService keys.CryptoKeyDownloadService

	// Infrastructure
	DBContext *persistence.TestContext
}

// SetupTestServices initializes all application services for integration tests
func SetupTestServices(t *testing.T, dbType string) *TestServices {
	t.Helper()

	ctx := context.Background()
	logger := pkgTesting.SetupTestLogger(t)

	// Setup database
	dbContext := persistence.SetupTestDB(t, dbType)

	// Setup blob connector
	blobConnectorSettings := &config.BlobConnectorSettings{
		CloudProvider:    TestCloudProvider,
		ConnectionString: TestConnectionString,
		ContainerName:    TestContainerName,
	}
	blobConnector, err := connector.NewAzureBlobConnector(ctx, blobConnectorSettings, logger)
	require.NoError(t, err, "Failed to create blob connector")

	// Setup vault connector
	keyConnectorSettings := &config.KeyConnectorSettings{
		CloudProvider:    TestCloudProvider,
		ConnectionString: TestConnectionString,
		ContainerName:    TestContainerName,
	}
	vaultConnector, err := connector.NewAzureVaultConnector(ctx, keyConnectorSettings, logger)
	require.NoError(t, err, "Failed to create vault connector")

	// Setup cryptographic processors
	aesProcessor, err := cryptography.NewAESProcessor(logger)
	require.NoError(t, err, "Failed to create AES processor")

	ecdsaProcessor, err := cryptography.NewECDSAProcessor(logger)
	require.NoError(t, err, "Failed to create EC processor")

	rsaProcessor, err := cryptography.NewRSAProcessor(logger)
	require.NoError(t, err, "Failed to create RSA processor")

	// Initialize blob services
	blobUploadService, err := NewBlobUploadService(
		blobConnector,
		dbContext.BlobRepo,
		vaultConnector,
		dbContext.CryptoKeyRepo,
		aesProcessor,
		ecdsaProcessor,
		rsaProcessor,
		logger,
	)
	require.NoError(t, err, "Failed to create BlobUploadService")

	blobDownloadService, err := NewBlobDownloadService(
		blobConnector,
		dbContext.BlobRepo,
		vaultConnector,
		dbContext.CryptoKeyRepo,
		aesProcessor,
		rsaProcessor,
		logger,
	)
	require.NoError(t, err, "Failed to create BlobDownloadService")

	blobMetadataService, err := NewBlobMetadataService(
		dbContext.BlobRepo,
		blobConnector,
		logger,
	)
	require.NoError(t, err, "Failed to create BlobMetadataService")

	// Initialize crypto key services
	cryptoKeyUploadService, err := NewCryptoKeyUploadService(
		vaultConnector,
		dbContext.CryptoKeyRepo,
		aesProcessor,
		ecdsaProcessor,
		rsaProcessor,
		logger,
	)
	require.NoError(t, err, "Failed to create CryptoKeyUploadService")

	cryptoKeyMetadataService, err := NewCryptoKeyMetadataService(
		vaultConnector,
		dbContext.CryptoKeyRepo,
		logger,
	)
	require.NoError(t, err, "Failed to create CryptoKeyMetadataService")

	cryptoKeyDownloadService, err := NewCryptoKeyDownloadService(
		vaultConnector,
		dbContext.CryptoKeyRepo,
		logger,
	)
	require.NoError(t, err, "Failed to create CryptoKeyDownloadService")

	return &TestServices{
		BlobUploadService:        blobUploadService,
		BlobDownloadService:      blobDownloadService,
		BlobMetadataService:      blobMetadataService,
		CryptoKeyUploadService:   cryptoKeyUploadService,
		CryptoKeyMetadataService: cryptoKeyMetadataService,
		CryptoKeyDownloadService: cryptoKeyDownloadService,
		DBContext:                dbContext,
	}
}
