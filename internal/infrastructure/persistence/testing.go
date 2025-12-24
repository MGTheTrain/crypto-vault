//go:build integration
// +build integration

package persistence

import (
	"crypto_vault_service/internal/domain/blobs"
	"crypto_vault_service/internal/domain/keys"
	"crypto_vault_service/internal/pkg/config"
	pkgTesting "crypto_vault_service/internal/pkg/testing"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

// Test constants
const (
	TestKeySize256  = 256
	TestKeySize521  = 521
	TestKeySize2048 = 2048

	TestKeyTypePublic  = "public"
	TestKeyTypePrivate = "private"

	TestAlgorithmEC  = "EC"
	TestAlgorithmRSA = "RSA"

	TestBlobTypeText   = "text"
	TestBlobTypeBinary = "binary"
	TestBlobTypeImage  = "image"
)

// TestContext holds test database and repositories
type TestContext struct {
	DB            *gorm.DB
	BlobRepo      blobs.BlobRepository
	CryptoKeyRepo keys.CryptoKeyRepository
}

// SetupTestDB initializes test database with automatic cleanup
func SetupTestDB(t *testing.T, dbType string) *TestContext {
	t.Helper()

	var settings config.DatabaseSettings
	var cleanupFunc func()

	switch dbType {
	case config.SqliteDbType:
		settings = config.DatabaseSettings{
			Type: config.SqliteDbType,
			DSN:  ":memory:",
		}
		cleanupFunc = func() {
			// SQLite in-memory cleanup is automatic
		}

	case config.PostgresDbType:
		uniqueDBName := "test_" + strings.ReplaceAll(uuid.NewString(), "-", "")[:16]
		settings = config.DatabaseSettings{
			Type:   config.PostgresDbType,
			DSN:    "user=postgres password=postgres host=localhost port=5432 sslmode=disable",
			DBName: uniqueDBName,
		}
		cleanupFunc = func() {
			adminDSN := "user=postgres password=postgres host=localhost port=5432 dbname=postgres sslmode=disable"
			_ = DropDatabase(adminDSN, uniqueDBName)
		}

	default:
		t.Fatalf("Unsupported database type: %s", dbType)
	}

	// Create connection
	db, err := NewDBConnection(settings)
	require.NoError(t, err, "Failed to create database connection")

	// Register cleanup
	t.Cleanup(func() {
		CloseDB(db)
		cleanupFunc()
	})

	// Migrate schema
	err = db.AutoMigrate(&blobs.BlobMeta{}, &keys.CryptoKeyMeta{})
	require.NoError(t, err, "Failed to migrate schema")

	// Create repositories
	logger := pkgTesting.SetupTestLogger(t)

	blobRepo, err := NewGormBlobRepository(db, logger)
	require.NoError(t, err, "Failed to create blob repository")

	cryptoKeyRepo, err := NewGormCryptoKeyRepository(db, logger)
	require.NoError(t, err, "Failed to create crypto key repository")

	return &TestContext{
		DB:            db,
		BlobRepo:      blobRepo,
		CryptoKeyRepo: cryptoKeyRepo,
	}
}

// TeardownTestDB is deprecated - use t.Cleanup in SetupTestDB
// Kept for backward compatibility
func TeardownTestDB(t *testing.T, ctx *TestContext, dbType string) {
	t.Helper()
	// Cleanup now handled automatically by t.Cleanup in SetupTestDB
}

// CreateTestKey creates a test crypto key with default values
func CreateTestKey(t *testing.T, userID string) *keys.CryptoKeyMeta {
	t.Helper()

	return &keys.CryptoKeyMeta{
		ID:              uuid.NewString(),
		KeyPairID:       uuid.NewString(),
		Type:            TestKeyTypePublic,
		Algorithm:       TestAlgorithmEC,
		KeySize:         TestKeySize256,
		DateTimeCreated: time.Now(),
		UserID:          userID,
	}
}

// CreateTestKeyWithOptions creates a test key with custom options
func CreateTestKeyWithOptions(t *testing.T, userID, keyType, algorithm string, keySize int) *keys.CryptoKeyMeta {
	t.Helper()

	return &keys.CryptoKeyMeta{
		ID:              uuid.NewString(),
		KeyPairID:       uuid.NewString(),
		Type:            keyType,
		Algorithm:       algorithm,
		KeySize:         uint32(keySize),
		DateTimeCreated: time.Now(),
		UserID:          userID,
	}
}

// CreateTestBlob creates a test blob with default values
func CreateTestBlob(t *testing.T, key *keys.CryptoKeyMeta, name string) *blobs.BlobMeta {
	t.Helper()

	if name == "" {
		name = "test-blob"
	}

	return &blobs.BlobMeta{
		ID:              uuid.NewString(),
		DateTimeCreated: time.Now(),
		UserID:          key.UserID,
		Name:            name,
		Size:            1024,
		Type:            TestBlobTypeText,
		EncryptionKey:   *key,
		EncryptionKeyID: &key.ID,
		SignKey:         *key,
		SignKeyID:       &key.ID,
	}
}

// CreateTestBlobWithOptions creates a test blob with custom options
func CreateTestBlobWithOptions(t *testing.T, key *keys.CryptoKeyMeta, name, blobType string, size int64) *blobs.BlobMeta {
	t.Helper()

	return &blobs.BlobMeta{
		ID:              uuid.NewString(),
		DateTimeCreated: time.Now(),
		UserID:          key.UserID,
		Name:            name,
		Size:            size,
		Type:            blobType,
		EncryptionKey:   *key,
		EncryptionKeyID: &key.ID,
		SignKey:         *key,
		SignKeyID:       &key.ID,
	}
}
