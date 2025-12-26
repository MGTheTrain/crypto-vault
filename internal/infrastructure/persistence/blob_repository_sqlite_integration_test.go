//go:build integration
// +build integration

package persistence

import (
	"context"
	"crypto_vault_service/internal/domain/blobs"
	"crypto_vault_service/internal/infrastructure/persistence/models"
	"crypto_vault_service/internal/pkg/config"
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBlobSqliteRepository_Create(t *testing.T) {
	ctx := SetupTestDB(t, config.SqliteDbType)

	userID := uuid.NewString()
	key := CreateTestKey(t, userID)
	blob := CreateTestBlob(t, key, "test-blob")

	err := ctx.BlobRepo.Create(context.Background(), blob)
	require.NoError(t, err)

	// Verify using GORM model (infrastructure concern)
	var createdBlobModel models.BlobModel
	err = ctx.DB.First(&createdBlobModel, "id = ?", blob.ID).Error
	require.NoError(t, err)
	assert.Equal(t, blob.ID, createdBlobModel.ID)
	assert.Equal(t, blob.Name, createdBlobModel.Name)
}

func TestBlobSqliteRepository_GetByID(t *testing.T) {
	ctx := SetupTestDB(t, config.SqliteDbType)

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

func TestBlobRepository_Create_InvalidBlob(t *testing.T) {
	ctx := SetupTestDB(t, config.SqliteDbType)

	blob := &blobs.BlobMeta{} // Invalid - missing required fields

	err := ctx.BlobRepo.Create(context.Background(), blob)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "validation")
}

func TestBlobRepository_GetByID_NotFound(t *testing.T) {
	ctx := SetupTestDB(t, config.SqliteDbType)

	_, err := ctx.BlobRepo.GetByID(context.Background(), "non-existent-id")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestBlobRepository_List_WithFilters(t *testing.T) {
	ctx := SetupTestDB(t, config.SqliteDbType)

	userID := uuid.NewString()
	key := CreateTestKey(t, userID)
	blob := CreateTestBlobWithOptions(t, key, "special-blob", TestBlobTypeBinary, 2048)

	err := ctx.BlobRepo.Create(context.Background(), blob)
	require.NoError(t, err)

	query := &blobs.BlobMetaQuery{
		Name: "special",
		Type: TestBlobTypeBinary,
		Size: 2048,
	}
	list, err := ctx.BlobRepo.List(context.Background(), query)
	require.NoError(t, err)
	assert.Len(t, list, 1)
	assert.Equal(t, "special-blob", list[0].Name)
}

func TestBlobRepository_List_SortAndPagination(t *testing.T) {
	ctx := SetupTestDB(t, config.SqliteDbType)

	userID := uuid.NewString()
	key := CreateTestKey(t, userID)

	// Create multiple blobs
	for i := 1; i <= 2; i++ {
		blob := CreateTestBlob(t, key, fmt.Sprintf("blob-%d", i))
		_ = ctx.BlobRepo.Create(context.Background(), blob)
	}

	query := &blobs.BlobMetaQuery{
		SortBy:    "date_time_created",
		SortOrder: "desc",
		Limit:     1,
		Offset:    1,
	}

	list, err := ctx.BlobRepo.List(context.Background(), query)
	require.NoError(t, err)
	assert.Len(t, list, 1)
}

func TestBlobRepository_List_InvalidQuery(t *testing.T) {
	ctx := SetupTestDB(t, config.SqliteDbType)

	query := &blobs.BlobMetaQuery{
		Limit: -1,
	}
	_, err := ctx.BlobRepo.List(context.Background(), query)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid query parameters")
}

func TestBlobSqliteRepository_UpdateByID(t *testing.T) {
	ctx := SetupTestDB(t, config.SqliteDbType)

	userID := uuid.NewString()
	key := CreateTestKey(t, userID)
	blob := CreateTestBlob(t, key, "test-blob")

	require.NoError(t, ctx.BlobRepo.Create(context.Background(), blob))

	// Update blob name
	blob.Name = "updated-blob"
	require.NoError(t, ctx.BlobRepo.UpdateByID(context.Background(), blob))

	// Verify update using GORM model
	var updatedBlobModel models.BlobModel
	require.NoError(t, ctx.DB.First(&updatedBlobModel, "id = ?", blob.ID).Error)
	assert.Equal(t, "updated-blob", updatedBlobModel.Name)
}

func TestBlobSqliteRepository_DeleteByID(t *testing.T) {
	ctx := SetupTestDB(t, config.SqliteDbType)

	userID := uuid.NewString()
	key := CreateTestKey(t, userID)
	blob := CreateTestBlob(t, key, "test-blob")

	require.NoError(t, ctx.BlobRepo.Create(context.Background(), blob))
	require.NoError(t, ctx.BlobRepo.DeleteByID(context.Background(), blob.ID))

	// Verify deletion using GORM model
	var deletedBlobModel models.BlobModel
	err := ctx.DB.First(&deletedBlobModel, "id = ?", blob.ID).Error
	assert.Error(t, err)
}
