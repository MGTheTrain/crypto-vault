//go:build integration
// +build integration

package persistence

import (
	"context"
	"crypto_vault_service/internal/domain/blobs"
	"crypto_vault_service/internal/domain/keys"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestBlobPsqlRepository_Create(t *testing.T) {
	dbType := "postgres"
	ctx := SetupTestDB(t, dbType)
	defer TeardownTestDB(t, ctx, dbType)

	cryptographicKey := keys.CryptoKeyMeta{
		ID:              uuid.New().String(),
		KeyPairID:       uuid.New().String(),
		Type:            "public",
		Algorithm:       "EC",
		KeySize:         521,
		DateTimeCreated: time.Now(),
		UserID:          uuid.New().String(),
	}

	blob := &blobs.BlobMeta{
		ID:              uuid.New().String(),
		DateTimeCreated: time.Now(),
		UserID:          cryptographicKey.UserID,
		Name:            "test-blob",
		Size:            1024,
		Type:            "text",
		EncryptionKey:   cryptographicKey,
		EncryptionKeyID: &cryptographicKey.ID,
		SignKey:         cryptographicKey,
		SignKeyID:       &cryptographicKey.ID,
	}

	err := ctx.BlobRepo.Create(context.Background(), blob)
	assert.NoError(t, err, "Create should not return an error")

	var createdBlob blobs.BlobMeta
	err = ctx.DB.First(&createdBlob, "id = ?", blob.ID).Error
	assert.NoError(t, err, "Failed to find created blob")
	assert.Equal(t, blob.ID, createdBlob.ID, "ID should match")
	assert.Equal(t, blob.Name, createdBlob.Name, "Name should match")
}

func TestBlobPsqlRepository_GetByID(t *testing.T) {
	dbType := "postgres"
	ctx := SetupTestDB(t, dbType)
	defer TeardownTestDB(t, ctx, dbType)

	cryptographicKey := keys.CryptoKeyMeta{
		ID:              uuid.New().String(),
		KeyPairID:       uuid.New().String(),
		Type:            "public",
		Algorithm:       "EC",
		KeySize:         256,
		DateTimeCreated: time.Now(),
		UserID:          uuid.New().String(),
	}
	blob := &blobs.BlobMeta{
		ID:              uuid.New().String(),
		DateTimeCreated: time.Now(),
		UserID:          cryptographicKey.UserID,
		Name:            "test-blob",
		Size:            1024,
		Type:            "text",
		EncryptionKey:   cryptographicKey,
		EncryptionKeyID: &cryptographicKey.ID,
		SignKey:         cryptographicKey,
		SignKeyID:       &cryptographicKey.ID,
	}
	err := ctx.BlobRepo.Create(context.Background(), blob)
	assert.NoError(t, err, "Create should not return an error")
	fetchedBlob, err := ctx.BlobRepo.GetByID(context.Background(), blob.ID)
	assert.NoError(t, err, "GetByID should not return an error")
	assert.NotNil(t, fetchedBlob, "Fetched blob should not be nil")
	assert.Equal(t, blob.ID, fetchedBlob.ID, "ID should match")
}

func TestBlobPsqlRepository_List(t *testing.T) {
	dbType := "postgres"
	ctx := SetupTestDB(t, dbType)
	defer TeardownTestDB(t, ctx, dbType)

	cryptographicKey := keys.CryptoKeyMeta{
		ID:              uuid.New().String(),
		KeyPairID:       uuid.New().String(),
		Type:            "public",
		Algorithm:       "EC",
		KeySize:         256,
		DateTimeCreated: time.Now(),
		UserID:          uuid.New().String(),
	}

	blob1 := &blobs.BlobMeta{
		ID:              uuid.New().String(),
		DateTimeCreated: time.Now(),
		UserID:          cryptographicKey.UserID,
		Name:            "blob-1",
		Size:            1024,
		Type:            "text",
		EncryptionKey:   cryptographicKey,
		EncryptionKeyID: &cryptographicKey.ID,
		SignKey:         cryptographicKey,
		SignKeyID:       &cryptographicKey.ID,
	}

	blob2 := &blobs.BlobMeta{
		ID:              uuid.New().String(),
		DateTimeCreated: time.Now(),
		UserID:          cryptographicKey.UserID,
		Name:            "blob-2",
		Size:            2048,
		Type:            "image",
		EncryptionKey:   cryptographicKey,
		EncryptionKeyID: &cryptographicKey.ID,
		SignKey:         cryptographicKey,
		SignKeyID:       &cryptographicKey.ID,
	}

	// Create blobs
	err := ctx.BlobRepo.Create(context.Background(), blob1)
	assert.NoError(t, err, "Create should not return an error")
	err = ctx.BlobRepo.Create(context.Background(), blob2)
	assert.NoError(t, err, "Create should not return an error")

	// List blobs
	query := &blobs.BlobMetaQuery{}
	blobsList, err := ctx.BlobRepo.List(context.Background(), query)
	assert.NoError(t, err, "List should not return an error")
	assert.Len(t, blobsList, 2, "There should be two blobs in the list")
}

func TestBlobPsqlRepository_UpdateByID(t *testing.T) {
	dbType := "postgres"
	ctx := SetupTestDB(t, dbType)
	defer TeardownTestDB(t, ctx, dbType)

	cryptographicKey := keys.CryptoKeyMeta{
		ID:              uuid.New().String(),
		KeyPairID:       uuid.New().String(),
		Type:            "public",
		Algorithm:       "EC",
		KeySize:         256,
		DateTimeCreated: time.Now(),
		UserID:          uuid.New().String(),
	}
	blob := &blobs.BlobMeta{
		ID:              uuid.New().String(),
		DateTimeCreated: time.Now(),
		UserID:          cryptographicKey.UserID,
		Name:            "test-blob",
		Size:            1024,
		Type:            "text",
		EncryptionKey:   cryptographicKey,
		EncryptionKeyID: &cryptographicKey.ID,
		SignKey:         cryptographicKey,
		SignKeyID:       &cryptographicKey.ID,
	}
	err := ctx.BlobRepo.Create(context.Background(), blob)
	assert.NoError(t, err, "Create should not return an error")

	// Update blob
	blob.Name = "updated-blob"
	err = ctx.BlobRepo.UpdateByID(context.Background(), blob)
	assert.NoError(t, err, "UpdateByID should not return an error")

	// Fetch updated blob
	var updatedBlob blobs.BlobMeta
	err = ctx.DB.First(&updatedBlob, "id = ?", blob.ID).Error
	assert.NoError(t, err, "Failed to find updated blob")
	assert.Equal(t, "updated-blob", updatedBlob.Name, "Name should be updated")
}

func TestBlobPsqlRepository_DeleteByID(t *testing.T) {
	dbType := "postgres"
	ctx := SetupTestDB(t, dbType)
	defer TeardownTestDB(t, ctx, dbType)

	cryptographicKey := keys.CryptoKeyMeta{
		ID:              uuid.New().String(),
		KeyPairID:       uuid.New().String(),
		Type:            "public",
		Algorithm:       "EC",
		KeySize:         256,
		DateTimeCreated: time.Now(),
		UserID:          uuid.New().String(),
	}
	blob := &blobs.BlobMeta{
		ID:              uuid.New().String(),
		DateTimeCreated: time.Now(),
		UserID:          cryptographicKey.UserID,
		Name:            "test-blob",
		Size:            1024,
		Type:            "text",
		EncryptionKey:   cryptographicKey,
		EncryptionKeyID: &cryptographicKey.ID,
		SignKey:         cryptographicKey,
		SignKeyID:       &cryptographicKey.ID,
	}
	err := ctx.BlobRepo.Create(context.Background(), blob)
	assert.NoError(t, err, "Create should not return an error")

	// Delete blob
	err = ctx.BlobRepo.DeleteByID(context.Background(), blob.ID)
	assert.NoError(t, err, "DeleteByID should not return an error")

	// Verify blob is deleted
	var deletedBlob blobs.BlobMeta
	err = ctx.DB.First(&deletedBlob, "id = ?", blob.ID).Error
	assert.Error(t, err, "Blob should be deleted")
}
