//go:build integration
// +build integration

package persistence

import (
	"context"
	"crypto_vault_service/internal/domain/blobs"
	"crypto_vault_service/internal/domain/keys"
	"fmt"

	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestBlobSqliteRepository_Create(t *testing.T) {

	dbType := "sqlite"
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

func TestBlobSqliteRepository_GetByID(t *testing.T) {

	dbType := "sqlite"
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

func TestBlobPsqlRepository_Create_InvalidBlob(t *testing.T) {
	dbType := "sqlite"
	ctx := SetupTestDB(t, dbType)
	defer TeardownTestDB(t, ctx, dbType)

	blob := &blobs.BlobMeta{} // Invalid because required fields are empty

	err := ctx.BlobRepo.Create(context.Background(), blob)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "validation")
}

func TestBlobPsqlRepository_GetByID_NotFound(t *testing.T) {
	dbType := "sqlite"
	ctx := SetupTestDB(t, dbType)
	defer TeardownTestDB(t, ctx, dbType)

	_, err := ctx.BlobRepo.GetByID(context.Background(), "non-existent-id")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestBlobPsqlRepository_List_WithFilters(t *testing.T) {
	dbType := "sqlite"
	ctx := SetupTestDB(t, dbType)
	defer TeardownTestDB(t, ctx, dbType)

	key := keys.CryptoKeyMeta{
		ID:              uuid.NewString(),
		KeyPairID:       uuid.NewString(),
		Type:            "public",
		Algorithm:       "EC",
		KeySize:         256,
		DateTimeCreated: time.Now(),
		UserID:          uuid.NewString(),
	}

	blob := &blobs.BlobMeta{
		ID:              uuid.NewString(),
		DateTimeCreated: time.Now(),
		UserID:          key.UserID,
		Name:            "special-blob",
		Size:            2048,
		Type:            "binary",
		EncryptionKey:   key,
		EncryptionKeyID: &key.ID,
		SignKey:         key,
		SignKeyID:       &key.ID,
	}
	_ = ctx.BlobRepo.Create(context.Background(), blob)

	query := &blobs.BlobMetaQuery{
		Name: "special",
		Type: "binary",
		Size: 2048,
	}
	list, err := ctx.BlobRepo.List(context.Background(), query)
	assert.NoError(t, err)
	assert.Len(t, list, 1)
	assert.Equal(t, "special-blob", list[0].Name)
}

func TestBlobPsqlRepository_List_SortAndPagination(t *testing.T) {
	dbType := "sqlite"
	ctx := SetupTestDB(t, dbType)
	defer TeardownTestDB(t, ctx, dbType)

	key := keys.CryptoKeyMeta{
		ID:              uuid.NewString(),
		KeyPairID:       uuid.NewString(),
		Type:            "public",
		Algorithm:       "EC",
		KeySize:         256,
		DateTimeCreated: time.Now(),
		UserID:          uuid.NewString(),
	}

	// Create two blobs
	for i := 1; i <= 2; i++ {
		_ = ctx.BlobRepo.Create(context.Background(), &blobs.BlobMeta{
			ID:              uuid.NewString(),
			DateTimeCreated: time.Now().Add(time.Duration(i) * time.Second),
			UserID:          key.UserID,
			Name:            fmt.Sprintf("blob-%d", i),
			Size:            1000 + int64(i),
			Type:            "text",
			EncryptionKey:   key,
			EncryptionKeyID: &key.ID,
			SignKey:         key,
			SignKeyID:       &key.ID,
		})
	}

	query := &blobs.BlobMetaQuery{
		SortBy:    "date_time_created",
		SortOrder: "desc",
		Limit:     1,
		Offset:    1,
	}

	list, err := ctx.BlobRepo.List(context.Background(), query)
	assert.NoError(t, err)
	assert.Len(t, list, 1)
}

func TestBlobPsqlRepository_List_InvalidQuery(t *testing.T) {
	dbType := "sqlite"
	ctx := SetupTestDB(t, dbType)
	defer TeardownTestDB(t, ctx, dbType)

	query := &blobs.BlobMetaQuery{
		Limit: -1,
	}
	_, err := ctx.BlobRepo.List(context.Background(), query)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid query parameters")
}
