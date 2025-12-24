package connector

import (
	"bytes"
	"context"
	"crypto_vault_service/internal/domain/keys"
	"crypto_vault_service/internal/pkg/config"
	"crypto_vault_service/internal/pkg/logger"
	"fmt"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob"
	"github.com/google/uuid"
)

// This is a temporary implementation and may later be replaced with more specialized external key management systems
// like Azure Key Vault or AWS KMS.
type azureVaultConnector struct {
	client        *azblob.Client
	containerName string
	logger        logger.Logger
}

// NewAzureVaultConnector creates a new instance of azureVaultConnector, which connects to Azure Blob Storage.
// This method can be updated in the future to support a more sophisticated key management system like Azure Key Vault.
func NewAzureVaultConnector(ctx context.Context, settings *config.KeyConnectorSettings, logger logger.Logger) (keys.VaultConnector, error) {
	if err := settings.Validate(); err != nil {
		return nil, fmt.Errorf("failed to validate settings: %w", err)
	}

	client, err := azblob.NewClientFromConnectionString(settings.ConnectionString, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create Azure Blob client: %w", err)
	}

	if _, err := client.CreateContainer(ctx, settings.ContainerName, nil); err != nil {
		logger.Warn("container creation failed (may already exist)", "error", err)
	}

	return &azureVaultConnector{
		client:        client,
		containerName: settings.ContainerName,
		logger:        logger,
	}, nil
}

// Upload uploads bytes of a single file to Blob Storage
// and returns the metadata for each uploaded byte stream.
func (vc *azureVaultConnector) Upload(ctx context.Context, bytes []byte, userID, keyPairID, keyType, keyAlgorihm string, keySize uint32) (*keys.CryptoKeyMeta, error) {
	keyID := uuid.New().String()
	fullKeyName := fmt.Sprintf("%s/%s-%s", keyPairID, keyID, keyType)

	cryptoKeyMeta := &keys.CryptoKeyMeta{
		ID:              keyID,
		KeyPairID:       keyPairID,
		Type:            keyType,
		Algorithm:       keyAlgorihm,
		KeySize:         keySize,
		DateTimeCreated: time.Now(),
		UserID:          userID,
	}

	_, err := vc.client.UploadBuffer(ctx, vc.containerName, fullKeyName, bytes, nil)
	if err != nil {
		vc.rollbackUploadedBlobs(ctx, cryptoKeyMeta)
		return nil, fmt.Errorf("failed to upload blob '%s' to storage: %w", fullKeyName, err)
	}

	vc.logger.Info("uploaded blob %s", fullKeyName)
	return cryptoKeyMeta, nil
}

// rollbackUploadedBlobs deletes the blobs that were uploaded successfully before the error occurred
func (vc *azureVaultConnector) rollbackUploadedBlobs(ctx context.Context, cryptoKeyMeta *keys.CryptoKeyMeta) {
	err := vc.Delete(ctx, cryptoKeyMeta.ID, cryptoKeyMeta.KeyPairID, cryptoKeyMeta.Type)
	if err != nil {
		vc.logger.Info("Failed to delete key '%s' during rollback: %v", cryptoKeyMeta.ID, err)
	} else {
		vc.logger.Info("Key '%s' deleted during rollback", cryptoKeyMeta.ID)
	}
}

// Download retrieves a key's content by IDs and Type and returns the data as a byte slice.
func (vc *azureVaultConnector) Download(ctx context.Context, keyID, keyPairID, keyType string) ([]byte, error) {

	fullKeyName := fmt.Sprintf("%s/%s-%s", keyPairID, keyID, keyType)

	get, err := vc.client.DownloadStream(ctx, vc.containerName, fullKeyName, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to download blob '%s': %w", fullKeyName, err)
	}

	downloadedData := bytes.Buffer{}
	_, err = downloadedData.ReadFrom(get.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read data from blob '%s': %w", fullKeyName, err)
	}

	vc.logger.Info("downloaded blob %s", fullKeyName)
	return downloadedData.Bytes(), nil
}

// Delete deletes a key from Azure Blob Storage by IDs and Type.
func (vc *azureVaultConnector) Delete(ctx context.Context, keyID, keyPairID, keyType string) error {
	fullKeyName := fmt.Sprintf("%s/%s-%s", keyPairID, keyID, keyType)

	_, err := vc.client.DeleteBlob(ctx, vc.containerName, fullKeyName, nil)
	if err != nil {
		return fmt.Errorf("failed to delete blob '%s': %w", fullKeyName, err)
	}

	vc.logger.Info("deleted blob %s", fullKeyName)
	return nil
}
