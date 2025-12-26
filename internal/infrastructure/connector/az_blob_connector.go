package connector

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"path/filepath"
	"time"

	"github.com/MGTheTrain/crypto-vault/internal/domain/blobs"
	"github.com/MGTheTrain/crypto-vault/internal/pkg/config"
	"github.com/MGTheTrain/crypto-vault/internal/pkg/logger"

	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob"
	"github.com/google/uuid"
)

// azureBlobConnector is a struct that holds the Azure Blob storage client and implements the BlobConnector interfaces.
type azureBlobConnector struct {
	client        *azblob.Client
	containerName string
	logger        logger.Logger
}

// NewAzureBlobConnector creates a new azureBlobConnector instance using a connection string.
// It returns the connector and any error encountered during the initialization.
func NewAzureBlobConnector(ctx context.Context, settings *config.BlobConnectorSettings, logger logger.Logger) (blobs.BlobConnector, error) {
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

	return &azureBlobConnector{
		client:        client,
		containerName: settings.ContainerName,
		logger:        logger,
	}, nil
}

// Upload uploads files to a Blob Storage
// and returns the metadata for each uploaded byte stream.
func (abc *azureBlobConnector) Upload(ctx context.Context, form *multipart.Form, userID string, encryptionKeyID, signKeyID *string) ([]*blobs.BlobMeta, error) {
	var blobMeta []*blobs.BlobMeta

	fileHeaders := form.File["files"]

	for _, fileHeader := range fileHeaders {

		blobID := uuid.New().String()

		fileExt := filepath.Ext(fileHeader.Filename)

		blob := &blobs.BlobMeta{
			ID:              blobID,
			Name:            fileHeader.Filename,
			Size:            fileHeader.Size,
			Type:            fileExt,
			DateTimeCreated: time.Now(),
			UserID:          userID,
			EncryptionKeyID: nil,
			SignKeyID:       nil,
		}

		if encryptionKeyID != nil {
			blob.EncryptionKeyID = encryptionKeyID
		}

		if signKeyID != nil {
			blob.SignKeyID = signKeyID
		}

		fullBlobName := fmt.Sprintf("%s/%s", blob.ID, blob.Name)
		fullBlobName = filepath.ToSlash(fullBlobName)

		file, err := fileHeader.Open()
		if err != nil {
			err = fmt.Errorf("failed to open file '%s': %w", fullBlobName, err)
			abc.rollbackUploadedBlobs(ctx, blobMeta)
			return nil, err
		}
		defer func() {
			if err := file.Close(); err != nil {
				log.Printf("warning: failed to close file: %v\n", err)
			}
		}()

		buffer := bytes.NewBuffer(make([]byte, 0))
		_, err = io.Copy(buffer, file)

		if err != nil {
			err = fmt.Errorf("failed create new buffer for '%s': %w", fullBlobName, err)
			abc.rollbackUploadedBlobs(ctx, blobMeta)
			return nil, err
		}

		_, err = abc.client.UploadBuffer(ctx, abc.containerName, fullBlobName, buffer.Bytes(), nil)
		if err != nil {
			err = fmt.Errorf("failed to upload blob '%s': %w", fullBlobName, err)
			abc.rollbackUploadedBlobs(ctx, blobMeta)
			return nil, err
		}

		abc.logger.Info("Blob '%s' uploaded successfully", blob.Name)

		blobMeta = append(blobMeta, blob)
	}

	return blobMeta, nil
}

// rollbackUploadedBlobs deletes the blobs that were uploaded successfully before the error occurred
func (abc *azureBlobConnector) rollbackUploadedBlobs(ctx context.Context, blobs []*blobs.BlobMeta) {
	for _, blob := range blobs {
		err := abc.Delete(ctx, blob.ID, blob.Name)
		if err != nil {
			abc.logger.Info("Failed to delete blob '%s' during rollback: %v", blob.Name, err)
		} else {
			abc.logger.Info("Blob '%s' deleted during rollback", blob.Name)
		}
	}
}

// Download retrieves a blob's content by ID and name, and returns the data as a stream.
func (abc *azureBlobConnector) Download(ctx context.Context, blobID, blobName string) ([]byte, error) {
	fullBlobName := fmt.Sprintf("%s/%s", blobID, blobName)

	get, err := abc.client.DownloadStream(ctx, abc.containerName, fullBlobName, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to download blob '%s': %w", fullBlobName, err)
	}

	downloadedData := bytes.Buffer{}

	retryReader := get.NewRetryReader(ctx, &azblob.RetryReaderOptions{})
	_, err = downloadedData.ReadFrom(retryReader)
	if err != nil {
		return nil, fmt.Errorf("failed to read data from blob '%s': %w", fullBlobName, err)
	}

	err = retryReader.Close()
	if err != nil {
		return nil, fmt.Errorf("failed to close retryReader for blob '%s': %w", fullBlobName, err)
	}

	abc.logger.Info("Blob '%s' downloaded successfully", fullBlobName)
	return downloadedData.Bytes(), nil
}

// Delete deletes a blob from Azure Blob Storage by ID and Name, and returns any error encountered.
func (abc *azureBlobConnector) Delete(ctx context.Context, blobID, blobName string) error {
	fullBlobName := fmt.Sprintf("%s/%s", blobID, blobName)

	_, err := abc.client.DeleteBlob(ctx, abc.containerName, fullBlobName, nil)
	if err != nil {
		return fmt.Errorf("failed to delete blob %s: %w", fullBlobName, err)
	}

	abc.logger.Info("Blob '%s' deleted successfully", fullBlobName)
	return nil
}
