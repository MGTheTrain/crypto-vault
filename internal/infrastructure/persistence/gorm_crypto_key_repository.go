package persistence

import (
	"context"
	"crypto_vault_service/internal/domain/keys"
	"crypto_vault_service/internal/infrastructure/persistence/models"
	"crypto_vault_service/internal/pkg/logger"
	"errors"
	"fmt"

	"gorm.io/gorm"
)

type gormCryptoKeyRepository struct {
	db     *gorm.DB
	logger logger.Logger
}

// NewGormCryptoKeyRepository creates a new GORM-based CryptoKeyRepository implementation
func NewGormCryptoKeyRepository(db *gorm.DB, logger logger.Logger) (keys.CryptoKeyRepository, error) {
	return &gormCryptoKeyRepository{
		db:     db,
		logger: logger,
	}, nil
}

func (r *gormCryptoKeyRepository) Create(ctx context.Context, key *keys.CryptoKeyMeta) error {
	if err := key.Validate(); err != nil {
		return fmt.Errorf("validation error: %w", err)
	}

	model := &models.CryptoKeyModel{}
	model.FromDomain(key)

	if err := r.db.WithContext(ctx).Create(model).Error; err != nil {
		return fmt.Errorf("failed to create cryptographic key: %w", err)
	}

	r.logger.Info("Created key metadata with id ", key.ID)
	return nil
}

func (r *gormCryptoKeyRepository) List(ctx context.Context, query *keys.CryptoKeyQuery) ([]*keys.CryptoKeyMeta, error) {
	if err := query.Validate(); err != nil {
		return nil, fmt.Errorf("invalid query parameters: %w", err)
	}

	var modelList []*models.CryptoKeyModel
	dbQuery := r.db.WithContext(ctx).Model(&models.CryptoKeyModel{})

	if query.Algorithm != "" {
		dbQuery = dbQuery.Where("algorithm = ?", query.Algorithm)
	}
	if query.Type != "" {
		dbQuery = dbQuery.Where("type = ?", query.Type)
	}
	if !query.DateTimeCreated.IsZero() {
		dbQuery = dbQuery.Where("date_time_created >= ?", query.DateTimeCreated)
	}

	if query.SortBy != "" {
		order := query.SortOrder
		if order == "" {
			order = "asc"
		}
		dbQuery = dbQuery.Order(fmt.Sprintf("%s %s", query.SortBy, order))
	}

	if query.Limit > 0 {
		dbQuery = dbQuery.Limit(query.Limit)
	}
	if query.Offset > 0 {
		dbQuery = dbQuery.Offset(query.Offset)
	}

	if err := dbQuery.Find(&modelList).Error; err != nil {
		return nil, fmt.Errorf("failed to fetch crypto key metadata: %w", err)
	}

	domainList := make([]*keys.CryptoKeyMeta, len(modelList))
	for i, model := range modelList {
		domainList[i] = model.ToDomain()
	}

	return domainList, nil
}

func (r *gormCryptoKeyRepository) GetByID(ctx context.Context, keyID string) (*keys.CryptoKeyMeta, error) {
	var model models.CryptoKeyModel
	if err := r.db.WithContext(ctx).Where("id = ?", keyID).First(&model).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("cryptographic key with ID %s not found", keyID)
		}
		return nil, fmt.Errorf("failed to fetch cryptographic key: %w", err)
	}
	return model.ToDomain(), nil
}

func (r *gormCryptoKeyRepository) UpdateByID(ctx context.Context, key *keys.CryptoKeyMeta) error {
	if err := key.Validate(); err != nil {
		return fmt.Errorf("validation error: %w", err)
	}

	model := &models.CryptoKeyModel{}
	model.FromDomain(key)

	if err := r.db.WithContext(ctx).Save(model).Error; err != nil {
		return fmt.Errorf("failed to update cryptographic key: %w", err)
	}

	r.logger.Info("Updated key metadata with id ", key.ID)
	return nil
}

func (r *gormCryptoKeyRepository) DeleteByID(ctx context.Context, keyID string) error {
	if err := r.db.WithContext(ctx).Where("id = ?", keyID).Delete(&models.CryptoKeyModel{}).Error; err != nil {
		return fmt.Errorf("failed to delete cryptographic key: %w", err)
	}

	r.logger.Info("Deleted key metadata with id ", keyID)
	return nil
}
