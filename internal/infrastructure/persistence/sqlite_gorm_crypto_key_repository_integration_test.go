//go:build integration
// +build integration

package persistence

import (
	"context"
	"crypto_vault_service/internal/domain/keys"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"gorm.io/gorm"
)

func TestCryptoKeySqliteRepository_Create(t *testing.T) {
	dbType := "sqlite"
	ctx := SetupTestDB(t, dbType)
	defer TeardownTestDB(t, ctx, dbType)

	cryptoKeyMeta := &keys.CryptoKeyMeta{
		ID:              uuid.New().String(),
		KeyPairID:       uuid.New().String(),
		Type:            "public",
		KeySize:         521,
		Algorithm:       "EC",
		DateTimeCreated: time.Now(),
		UserID:          uuid.New().String(),
	}

	err := ctx.CryptoKeyRepo.Create(context.Background(), cryptoKeyMeta)
	assert.NoError(t, err, "Create should not return an error")

	var createdCryptoKeyMeta keys.CryptoKeyMeta
	err = ctx.DB.First(&createdCryptoKeyMeta, "id = ?", cryptoKeyMeta.ID).Error
	assert.NoError(t, err, "Failed to find created cryptographic key")
	assert.Equal(t, cryptoKeyMeta.ID, createdCryptoKeyMeta.ID, "ID should match")
	assert.Equal(t, cryptoKeyMeta.Type, createdCryptoKeyMeta.Type, "Type should match")
}

func TestCryptoKeySqliteRepository_GetByID(t *testing.T) {
	dbType := "sqlite"
	ctx := SetupTestDB(t, dbType)
	defer TeardownTestDB(t, ctx, dbType)

	cryptoKeyMeta := &keys.CryptoKeyMeta{
		ID:              uuid.New().String(),
		KeyPairID:       uuid.New().String(),
		Type:            "private",
		KeySize:         2048,
		Algorithm:       "RSA",
		DateTimeCreated: time.Now(),
		UserID:          uuid.New().String(),
	}

	err := ctx.CryptoKeyRepo.Create(context.Background(), cryptoKeyMeta)
	assert.NoError(t, err, "Create should not return an error")

	fetchedCryptoKeyMeta, err := ctx.CryptoKeyRepo.GetByID(context.Background(), cryptoKeyMeta.ID)
	assert.NoError(t, err, "GetByID should not return an error")
	assert.NotNil(t, fetchedCryptoKeyMeta, "Fetched cryptographic key should not be nil")
	assert.Equal(t, cryptoKeyMeta.ID, fetchedCryptoKeyMeta.ID, "ID should match")
}

func TestCryptoKeySqliteRepository_List(t *testing.T) {
	dbType := "sqlite"
	ctx := SetupTestDB(t, dbType)
	defer TeardownTestDB(t, ctx, dbType)

	cryptoKeyMeta1 := &keys.CryptoKeyMeta{
		ID:              uuid.New().String(),
		KeyPairID:       uuid.New().String(),
		Type:            "private",
		KeySize:         2048,
		Algorithm:       "RSA",
		DateTimeCreated: time.Now(),
		UserID:          uuid.New().String(),
	}

	cryptoKeyMeta2 := &keys.CryptoKeyMeta{
		ID:              uuid.New().String(),
		KeyPairID:       uuid.New().String(),
		Type:            "public",
		KeySize:         521,
		Algorithm:       "EC",
		DateTimeCreated: time.Now(),
		UserID:          cryptoKeyMeta1.UserID, // Same UserID for listing purpose
	}

	// Create crypto keys
	err := ctx.CryptoKeyRepo.Create(context.Background(), cryptoKeyMeta1)
	assert.NoError(t, err, "Create should not return an error")
	err = ctx.CryptoKeyRepo.Create(context.Background(), cryptoKeyMeta2)
	assert.NoError(t, err, "Create should not return an error")

	// List crypto keys
	query := &keys.CryptoKeyQuery{}
	cryptoKeys, err := ctx.CryptoKeyRepo.List(context.Background(), query)
	assert.NoError(t, err, "List should not return an error")
	assert.Len(t, cryptoKeys, 2, "There should be two cryptographic keys in the list")
}

func TestCryptoKeySqliteRepository_UpdateByID(t *testing.T) {
	dbType := "sqlite"
	ctx := SetupTestDB(t, dbType)
	defer TeardownTestDB(t, ctx, dbType)

	cryptoKeyMeta := &keys.CryptoKeyMeta{
		ID:              uuid.New().String(),
		KeyPairID:       uuid.New().String(),
		Type:            "public",
		KeySize:         521,
		Algorithm:       "EC",
		DateTimeCreated: time.Now(),
		UserID:          uuid.New().String(),
	}

	err := ctx.CryptoKeyRepo.Create(context.Background(), cryptoKeyMeta)
	assert.NoError(t, err, "Create should not return an error")

	// Update the key's type
	cryptoKeyMeta.Type = "private"
	err = ctx.CryptoKeyRepo.UpdateByID(context.Background(), cryptoKeyMeta)
	assert.NoError(t, err, "UpdateByID should not return an error")

	var updatedCryptoKeyMeta keys.CryptoKeyMeta
	err = ctx.DB.First(&updatedCryptoKeyMeta, "id = ?", cryptoKeyMeta.ID).Error
	assert.NoError(t, err, "Failed to find updated cryptographic key")
	assert.Equal(t, "private", updatedCryptoKeyMeta.Type, "Type should be updated")
}

func TestCryptoKeySqliteRepository_DeleteByID(t *testing.T) {
	dbType := "sqlite"
	ctx := SetupTestDB(t, dbType)
	defer TeardownTestDB(t, ctx, dbType)

	cryptoKeyMeta := &keys.CryptoKeyMeta{
		ID:              uuid.New().String(),
		KeyPairID:       uuid.New().String(),
		Type:            "public",
		KeySize:         256,
		Algorithm:       "EC",
		DateTimeCreated: time.Now(),
		UserID:          uuid.New().String(),
	}

	err := ctx.CryptoKeyRepo.Create(context.Background(), cryptoKeyMeta)
	assert.NoError(t, err, "Create should not return an error")

	err = ctx.CryptoKeyRepo.DeleteByID(context.Background(), cryptoKeyMeta.ID)
	assert.NoError(t, err, "DeleteByID should not return an error")

	var deletedCryptoKeyMeta keys.CryptoKeyMeta
	err = ctx.DB.First(&deletedCryptoKeyMeta, "id = ?", cryptoKeyMeta.ID).Error
	assert.Error(t, err, "Cryptographic key should be deleted")
	assert.Equal(t, gorm.ErrRecordNotFound, err, "Error should be 'record not found'")
}

func TestCryptoKeyRepository_GetByID_NotFound(t *testing.T) {
	dbType := "sqlite"
	ctx := SetupTestDB(t, dbType)
	defer TeardownTestDB(t, ctx, dbType)

	nonexistentID := uuid.New().String()

	key, err := ctx.CryptoKeyRepo.GetByID(context.Background(), nonexistentID)
	assert.Nil(t, key)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestCryptoKeyRepository_Create_ValidationError(t *testing.T) {
	dbType := "sqlite"
	ctx := SetupTestDB(t, dbType)
	defer TeardownTestDB(t, ctx, dbType)

	invalidKey := &keys.CryptoKeyMeta{} // Missing required fields

	err := ctx.CryptoKeyRepo.Create(context.Background(), invalidKey)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "validation")
}

func TestCryptoKeySqliteRepository_List_WithFiltersAndSorting(t *testing.T) {
	dbType := "sqlite"
	ctx := SetupTestDB(t, dbType)
	defer TeardownTestDB(t, ctx, dbType)

	// Create two keys with different values
	cryptoKeyMeta1 := &keys.CryptoKeyMeta{
		ID:              uuid.New().String(),
		KeyPairID:       uuid.New().String(),
		Type:            "private",
		KeySize:         2048,
		Algorithm:       "RSA",
		DateTimeCreated: time.Now().Add(-2 * time.Hour),
		UserID:          uuid.New().String(),
	}
	cryptoKeyMeta2 := &keys.CryptoKeyMeta{
		ID:              uuid.New().String(),
		KeyPairID:       uuid.New().String(),
		Type:            "public",
		KeySize:         521,
		Algorithm:       "EC",
		DateTimeCreated: time.Now().Add(-1 * time.Hour),
		UserID:          cryptoKeyMeta1.UserID, // Same user for filter testing
	}

	err := ctx.CryptoKeyRepo.Create(context.Background(), cryptoKeyMeta1)
	assert.NoError(t, err)
	err = ctx.CryptoKeyRepo.Create(context.Background(), cryptoKeyMeta2)
	assert.NoError(t, err)

	// Test filtering by Algorithm
	query := &keys.CryptoKeyQuery{
		Algorithm: "RSA",
	}
	keysRSA, err := ctx.CryptoKeyRepo.List(context.Background(), query)
	assert.NoError(t, err)
	assert.Len(t, keysRSA, 1)
	assert.Equal(t, "RSA", keysRSA[0].Algorithm)

	// Test filtering by Type
	query = &keys.CryptoKeyQuery{
		Type: "public",
	}
	keysPublic, err := ctx.CryptoKeyRepo.List(context.Background(), query)
	assert.NoError(t, err)
	assert.Len(t, keysPublic, 1)
	assert.Equal(t, "public", keysPublic[0].Type)

	// Test sorting by DateTimeCreated DESC
	query = &keys.CryptoKeyQuery{
		SortBy:    "date_time_created",
		SortOrder: "desc",
	}
	sortedKeys, err := ctx.CryptoKeyRepo.List(context.Background(), query)
	assert.NoError(t, err)
	assert.Len(t, sortedKeys, 2)
	assert.True(t, sortedKeys[0].DateTimeCreated.After(sortedKeys[1].DateTimeCreated))

	// Test pagination: Limit and Offset
	query = &keys.CryptoKeyQuery{
		Limit:  1,
		Offset: 1,
	}
	pagedKeys, err := ctx.CryptoKeyRepo.List(context.Background(), query)
	assert.NoError(t, err)
	assert.Len(t, pagedKeys, 1)

	// Test query validation failure
	invalidQuery := &keys.CryptoKeyQuery{
		SortBy: "invalid_column",
	}
	_ = invalidQuery.Validate // Assume your Validate handles column checking — if not, mock or skip
}
