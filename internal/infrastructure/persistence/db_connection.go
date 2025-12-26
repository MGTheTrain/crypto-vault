package persistence

import (
	"fmt"
	"log"

	"github.com/MGTheTrain/crypto-vault/internal/pkg/config"

	"gorm.io/driver/postgres"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// NewDBConnection creates a database connection based on settings
// Supports both production and test environments
func NewDBConnection(settings config.DatabaseSettings) (*gorm.DB, error) {
	var db *gorm.DB
	var err error

	switch settings.Type {
	case config.PostgresDbType:
		db, err = connectPostgres(settings)
	case config.SqliteDbType:
		db, err = connectSQLite(settings)
	default:
		return nil, fmt.Errorf("unsupported database type: %s", settings.Type)
	}

	if err != nil {
		return nil, err
	}

	return db, nil
}

// connectPostgres establishes PostgreSQL connection with optional database creation
func connectPostgres(settings config.DatabaseSettings) (*gorm.DB, error) {
	// Connect to postgres database first
	db, err := gorm.Open(postgres.Open(settings.DSN), &gorm.Config{})
	if err != nil {
		return nil, fmt.Errorf("failed to connect to PostgreSQL: %w", err)
	}

	// If Name is specified, ensure it exists
	if settings.Name != "" {
		sqlDB, err := db.DB()
		if err != nil {
			return nil, fmt.Errorf("failed to get raw DB connection: %w", err)
		}

		// Try to create database (idempotent - ignore if exists)
		_, _ = sqlDB.Exec(fmt.Sprintf("CREATE DATABASE %s", settings.Name))

		// Close initial connection
		if err := sqlDB.Close(); err != nil {
			return nil, fmt.Errorf("failed to close initial DB connection: %w", err)
		}

		// Reconnect to the specific database
		dsn := fmt.Sprintf("%s dbname=%s", settings.DSN, settings.Name)
		db, err = gorm.Open(postgres.Open(dsn), &gorm.Config{})
		if err != nil {
			return nil, fmt.Errorf("failed to connect to database '%s': %w", settings.Name, err)
		}
	}

	return db, nil
}

// connectSQLite establishes SQLite connection
func connectSQLite(settings config.DatabaseSettings) (*gorm.DB, error) {
	// Use DSN if provided, otherwise default to in-memory
	dsn := settings.DSN
	if dsn == "" {
		dsn = ":memory:"
	}

	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	if err != nil {
		return nil, fmt.Errorf("failed to connect to SQLite: %w", err)
	}

	return db, nil
}

// CloseDB closes the database connection
func CloseDB(db *gorm.DB) error {
	sqlDB, err := db.DB()
	if err != nil {
		return fmt.Errorf("failed to get database instance: %w", err)
	}

	if err := sqlDB.Close(); err != nil {
		return fmt.Errorf("failed to close database connection: %w", err)
	}
	return nil
}

// DropDatabase drops a PostgreSQL database (test cleanup utility)
func DropDatabase(adminDSN, dbName string) error {
	db, err := gorm.Open(postgres.Open(adminDSN), &gorm.Config{})
	if err != nil {
		return fmt.Errorf("failed to connect to PostgreSQL: %w", err)
	}
	defer func() {
		if err := CloseDB(db); err != nil {
			// Log error but don't fail since this is cleanup
			log.Printf("Warning: failed to close database connection: %v", err)
		}
	}()

	err = db.Exec(fmt.Sprintf("DROP DATABASE IF EXISTS %s", dbName)).Error
	if err != nil {
		return fmt.Errorf("failed to drop database '%s': %w", dbName, err)
	}

	return nil
}
