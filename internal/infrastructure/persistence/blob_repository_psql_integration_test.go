//go:build integration
// +build integration

package persistence

import (
	"context"
	"crypto_vault_service/internal/domain/blobs"
	"crypto_vault_service/internal/pkg/config"
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

func TestBlobPostgresRepository_Create(t *testing.T) {
	ctx := SetupTestDB(t, config.PostgresDbType)

	userID := uuid.NewString()
	key := CreateTestKey(t, userID)
	blob := CreateTestBlob(t, key, "test-blob")

	err := ctx.BlobRepo.Create(context.Background(), blob)
	require.NoError(t, err)

	// Verify by fetching
	fetchedBlob, err := ctx.BlobRepo.GetByID(context.Background(), blob.ID)
	require.NoError(t, err)
	assert.Equal(t, blob.ID, fetchedBlob.ID)
	assert.Equal(t, blob.Name, fetchedBlob.Name)
}

func TestBlobPostgresRepository_GetByID(t *testing.T) {
	ctx := SetupTestDB(t, config.PostgresDbType)

	userID := uuid.NewString()
	key := CreateTestKey(t, userID)
	blob := CreateTestBlob(t, key, "test-blob")

	err := ctx.BlobRepo.Create(context.Background(), blob)
	require.NoError(t, err)

	fetchedBlob, err := ctx.BlobRepo.GetByID(context.Background(), blob.ID)
	require.NoError(t, err)
	assert.NotNil(t, fetchedBlob)
	assert.Equal(t, blob.ID, fetchedBlob.ID)
}

func TestBlobPostgresRepository_List(t *testing.T) {
	ctx := SetupTestDB(t, config.PostgresDbType)

	userID := uuid.NewString()
	key := CreateTestKey(t, userID)

	// Create multiple blobs
	blob1 := CreateTestBlob(t, key, "blob-1")
	blob2 := CreateTestBlobWithOptions(t, key, "blob-2", TestBlobTypeImage, 2048)

	require.NoError(t, ctx.BlobRepo.Create(context.Background(), blob1))
	require.NoError(t, ctx.BlobRepo.Create(context.Background(), blob2))

	// List all blobs
	query := &blobs.BlobMetaQuery{}
	blobsList, err := ctx.BlobRepo.List(context.Background(), query)
	require.NoError(t, err)
	assert.Len(t, blobsList, 2)
}

func TestBlobPostgresRepository_UpdateByID(t *testing.T) {
	ctx := SetupTestDB(t, config.PostgresDbType)

	userID := uuid.NewString()
	key := CreateTestKey(t, userID)
	blob := CreateTestBlob(t, key, "test-blob")

	require.NoError(t, ctx.BlobRepo.Create(context.Background(), blob))

	// Update blob name
	blob.Name = "updated-blob"
	require.NoError(t, ctx.BlobRepo.UpdateByID(context.Background(), blob))

	// Verify update
	var updatedBlob blobs.BlobMeta
	require.NoError(t, ctx.DB.First(&updatedBlob, "id = ?", blob.ID).Error)
	assert.Equal(t, "updated-blob", updatedBlob.Name)
}

func TestBlobPostgresRepository_DeleteByID(t *testing.T) {
	ctx := SetupTestDB(t, config.PostgresDbType)

	userID := uuid.NewString()
	key := CreateTestKey(t, userID)
	blob := CreateTestBlob(t, key, "test-blob")

	require.NoError(t, ctx.BlobRepo.Create(context.Background(), blob))
	require.NoError(t, ctx.BlobRepo.DeleteByID(context.Background(), blob.ID))

	// Verify deletion
	var deletedBlob blobs.BlobMeta
	err := ctx.DB.First(&deletedBlob, "id = ?", blob.ID).Error
	assert.Error(t, err)
	assert.Equal(t, gorm.ErrRecordNotFound, err)
}

func TestBlobPostgresRepository_GetByID_NotFound(t *testing.T) {
	ctx := SetupTestDB(t, config.PostgresDbType)

	_, err := ctx.BlobRepo.GetByID(context.Background(), "non-existent-id")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestBlobPostgresRepository_Create_ValidationError(t *testing.T) {
	ctx := SetupTestDB(t, config.PostgresDbType)

	invalidBlob := &blobs.BlobMeta{} // Missing required fields

	err := ctx.BlobRepo.Create(context.Background(), invalidBlob)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "validation")
}

func TestBlobPostgresRepository_List_WithFilters(t *testing.T) {
	ctx := SetupTestDB(t, config.PostgresDbType)

	userID := uuid.NewString()
	key := CreateTestKey(t, userID)

	// Create blobs with different types
	blob1 := CreateTestBlob(t, key, "text-blob")
	blob2 := CreateTestBlobWithOptions(t, key, "binary-blob", TestBlobTypeBinary, 2048)

	require.NoError(t, ctx.BlobRepo.Create(context.Background(), blob1))
	require.NoError(t, ctx.BlobRepo.Create(context.Background(), blob2))

	// Filter by type
	query := &blobs.BlobMetaQuery{Type: TestBlobTypeBinary}
	blobsList, err := ctx.BlobRepo.List(context.Background(), query)
	require.NoError(t, err)
	assert.Len(t, blobsList, 1)
	assert.Equal(t, "binary-blob", blobsList[0].Name)
}

func TestBlobPostgresRepository_List_WithPagination(t *testing.T) {
	ctx := SetupTestDB(t, config.PostgresDbType)

	userID := uuid.NewString()
	key := CreateTestKey(t, userID)

	// Create multiple blobs
	for i := 1; i <= 3; i++ {
		blob := CreateTestBlob(t, key, fmt.Sprintf("blob-%d", i))
		require.NoError(t, ctx.BlobRepo.Create(context.Background(), blob))
	}

	// Test pagination
	query := &blobs.BlobMetaQuery{
		Limit:  2,
		Offset: 1,
	}
	blobsList, err := ctx.BlobRepo.List(context.Background(), query)
	require.NoError(t, err)
	assert.Len(t, blobsList, 2)
}
