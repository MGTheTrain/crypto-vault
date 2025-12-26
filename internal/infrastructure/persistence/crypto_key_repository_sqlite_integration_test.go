//go:build integration
// +build integration

package persistence

import (
	"context"
	"testing"
	"time"

	"github.com/MGTheTrain/crypto-vault/internal/domain/keys"
	"github.com/MGTheTrain/crypto-vault/internal/infrastructure/persistence/models"
	"github.com/MGTheTrain/crypto-vault/internal/pkg/config"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

func TestCryptoKeySqliteRepository_Create(t *testing.T) {
	ctx := SetupTestDB(t, config.SqliteDbType)

	userID := uuid.NewString()
	key := CreateTestKeyWithOptions(t, userID, TestKeyTypePublic, TestAlgorithmECDSA, TestKeySize521)

	err := ctx.CryptoKeyRepo.Create(context.Background(), key)
	require.NoError(t, err)

	// Verify using GORM model (infrastructure concern)
	var createdKeyModel models.CryptoKeyModel
	err = ctx.DB.First(&createdKeyModel, "id = ?", key.ID).Error
	require.NoError(t, err)
	assert.Equal(t, key.ID, createdKeyModel.ID)
	assert.Equal(t, key.Type, createdKeyModel.Type)
}

func TestCryptoKeySqliteRepository_GetByID(t *testing.T) {
	ctx := SetupTestDB(t, config.SqliteDbType)

	userID := uuid.NewString()
	key := CreateTestKeyWithOptions(t, userID, TestKeyTypePrivate, TestAlgorithmRSA, TestKeySize2048)

	err := ctx.CryptoKeyRepo.Create(context.Background(), key)
	require.NoError(t, err)

	fetchedKey, err := ctx.CryptoKeyRepo.GetByID(context.Background(), key.ID)
	require.NoError(t, err)
	assert.NotNil(t, fetchedKey)
	assert.Equal(t, key.ID, fetchedKey.ID)
}

func TestCryptoKeySqliteRepository_List(t *testing.T) {
	ctx := SetupTestDB(t, config.SqliteDbType)

	userID := uuid.NewString()
	key1 := CreateTestKeyWithOptions(t, userID, TestKeyTypePrivate, TestAlgorithmRSA, TestKeySize2048)
	key2 := CreateTestKeyWithOptions(t, userID, TestKeyTypePublic, TestAlgorithmECDSA, TestKeySize521)

	require.NoError(t, ctx.CryptoKeyRepo.Create(context.Background(), key1))
	require.NoError(t, ctx.CryptoKeyRepo.Create(context.Background(), key2))

	query := &keys.CryptoKeyQuery{}
	cryptoKeys, err := ctx.CryptoKeyRepo.List(context.Background(), query)
	require.NoError(t, err)
	assert.Len(t, cryptoKeys, 2)
}

func TestCryptoKeySqliteRepository_UpdateByID(t *testing.T) {
	ctx := SetupTestDB(t, config.SqliteDbType)

	userID := uuid.NewString()
	key := CreateTestKey(t, userID)

	require.NoError(t, ctx.CryptoKeyRepo.Create(context.Background(), key))

	key.Type = TestKeyTypePrivate
	require.NoError(t, ctx.CryptoKeyRepo.UpdateByID(context.Background(), key))

	// Verify using GORM model
	var updatedKeyModel models.CryptoKeyModel
	require.NoError(t, ctx.DB.First(&updatedKeyModel, "id = ?", key.ID).Error)
	assert.Equal(t, TestKeyTypePrivate, updatedKeyModel.Type)
}

func TestCryptoKeySqliteRepository_DeleteByID(t *testing.T) {
	ctx := SetupTestDB(t, config.SqliteDbType)

	userID := uuid.NewString()
	key := CreateTestKey(t, userID)

	require.NoError(t, ctx.CryptoKeyRepo.Create(context.Background(), key))
	require.NoError(t, ctx.CryptoKeyRepo.DeleteByID(context.Background(), key.ID))

	// Verify deletion using GORM model
	var deletedKeyModel models.CryptoKeyModel
	err := ctx.DB.First(&deletedKeyModel, "id = ?", key.ID).Error
	assert.Error(t, err)
	assert.Equal(t, gorm.ErrRecordNotFound, err)
}

func TestCryptoKeyRepository_GetByID_NotFound(t *testing.T) {
	ctx := SetupTestDB(t, config.SqliteDbType)

	key, err := ctx.CryptoKeyRepo.GetByID(context.Background(), uuid.NewString())
	assert.Nil(t, key)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestCryptoKeyRepository_Create_ValidationError(t *testing.T) {
	ctx := SetupTestDB(t, config.SqliteDbType)

	invalidKey := &keys.CryptoKeyMeta{} // Missing required fields

	err := ctx.CryptoKeyRepo.Create(context.Background(), invalidKey)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "validation")
}

func TestCryptoKeySqliteRepository_List_WithFiltersAndSorting(t *testing.T) {
	ctx := SetupTestDB(t, config.SqliteDbType)

	userID := uuid.NewString()
	key1 := CreateTestKeyWithOptions(t, userID, TestKeyTypePrivate, TestAlgorithmRSA, TestKeySize2048)
	key1.DateTimeCreated = time.Now().Add(-2 * time.Hour)

	key2 := CreateTestKeyWithOptions(t, userID, TestKeyTypePublic, TestAlgorithmECDSA, TestKeySize521)
	key2.DateTimeCreated = time.Now().Add(-1 * time.Hour)

	require.NoError(t, ctx.CryptoKeyRepo.Create(context.Background(), key1))
	require.NoError(t, ctx.CryptoKeyRepo.Create(context.Background(), key2))

	// Test filtering by Algorithm
	query := &keys.CryptoKeyQuery{Algorithm: TestAlgorithmRSA}
	keysRSA, err := ctx.CryptoKeyRepo.List(context.Background(), query)
	require.NoError(t, err)
	assert.Len(t, keysRSA, 1)
	assert.Equal(t, TestAlgorithmRSA, keysRSA[0].Algorithm)

	// Test sorting
	query = &keys.CryptoKeyQuery{
		SortBy:    "date_time_created",
		SortOrder: "desc",
	}
	sortedKeys, err := ctx.CryptoKeyRepo.List(context.Background(), query)
	require.NoError(t, err)
	assert.Len(t, sortedKeys, 2)
	assert.True(t, sortedKeys[0].DateTimeCreated.After(sortedKeys[1].DateTimeCreated))

	// Test pagination
	query = &keys.CryptoKeyQuery{Limit: 1, Offset: 1}
	pagedKeys, err := ctx.CryptoKeyRepo.List(context.Background(), query)
	require.NoError(t, err)
	assert.Len(t, pagedKeys, 1)
}
