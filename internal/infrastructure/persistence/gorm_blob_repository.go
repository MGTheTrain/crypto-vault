package persistence

import (
	"context"
	"errors"
	"fmt"

	"github.com/MGTheTrain/crypto-vault/internal/domain/blobs"
	"github.com/MGTheTrain/crypto-vault/internal/infrastructure/persistence/models"
	"github.com/MGTheTrain/crypto-vault/internal/pkg/logger"

	"gorm.io/gorm"
)

type gormBlobRepository struct {
	db     *gorm.DB
	logger logger.Logger
}

// NewGormBlobRepository creates a new GORM-based BlobRepository implementation
func NewGormBlobRepository(db *gorm.DB, logger logger.Logger) (blobs.BlobRepository, error) {
	return &gormBlobRepository{
		db:     db,
		logger: logger,
	}, nil
}

func (r *gormBlobRepository) Create(ctx context.Context, blob *blobs.BlobMeta) error {
	// Validate domain entity (business rules)
	if err := blob.Validate(); err != nil {
		return fmt.Errorf("validation error: %w", err)
	}

	// Convert to GORM model
	model := &models.BlobModel{}
	model.FromDomain(blob)

	// Persist to database
	if err := r.db.WithContext(ctx).Create(model).Error; err != nil {
		return fmt.Errorf("failed to create blob: %w", err)
	}

	r.logger.Info("Created blob metadata with id ", blob.ID)
	return nil
}

func (r *gormBlobRepository) List(ctx context.Context, query *blobs.BlobMetaQuery) ([]*blobs.BlobMeta, error) {
	if err := query.Validate(); err != nil {
		return nil, fmt.Errorf("invalid query parameters: %w", err)
	}

	var modelList []*models.BlobModel
	dbQuery := r.db.WithContext(ctx).Model(&models.BlobModel{})

	// Apply filters
	if query.Name != "" {
		dbQuery = dbQuery.Where("name LIKE ?", "%"+query.Name+"%")
	}
	if query.Size > 0 {
		dbQuery = dbQuery.Where("size = ?", query.Size)
	}
	if query.Type != "" {
		dbQuery = dbQuery.Where("type = ?", query.Type)
	}
	if !query.DateTimeCreated.IsZero() {
		dbQuery = dbQuery.Where("date_time_created >= ?", query.DateTimeCreated)
	}

	// Sorting
	if query.SortBy != "" {
		order := query.SortOrder
		if order == "" {
			order = "asc"
		}
		dbQuery = dbQuery.Order(fmt.Sprintf("%s %s", query.SortBy, order))
	}

	// Pagination
	if query.Limit > 0 {
		dbQuery = dbQuery.Limit(query.Limit)
	}
	if query.Offset > 0 {
		dbQuery = dbQuery.Offset(query.Offset)
	}

	if err := dbQuery.Find(&modelList).Error; err != nil {
		return nil, fmt.Errorf("failed to fetch blobs: %w", err)
	}

	// Convert to domain models
	domainList := make([]*blobs.BlobMeta, len(modelList))
	for i, model := range modelList {
		domainList[i] = model.ToDomain()
	}

	return domainList, nil
}

func (r *gormBlobRepository) GetByID(ctx context.Context, blobID string) (*blobs.BlobMeta, error) {
	var model models.BlobModel
	if err := r.db.WithContext(ctx).Where("id = ?", blobID).First(&model).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("blob with ID %s not found", blobID)
		}
		return nil, fmt.Errorf("failed to fetch blob: %w", err)
	}
	return model.ToDomain(), nil
}

func (r *gormBlobRepository) UpdateByID(ctx context.Context, blob *blobs.BlobMeta) error {
	if err := blob.Validate(); err != nil {
		return fmt.Errorf("validation error: %w", err)
	}

	model := &models.BlobModel{}
	model.FromDomain(blob)

	if err := r.db.WithContext(ctx).Save(model).Error; err != nil {
		return fmt.Errorf("failed to update blob: %w", err)
	}

	r.logger.Info("Updated blob metadata with id ", blob.ID)
	return nil
}

func (r *gormBlobRepository) DeleteByID(ctx context.Context, blobID string) error {
	if err := r.db.WithContext(ctx).Where("id = ?", blobID).Delete(&models.BlobModel{}).Error; err != nil {
		return fmt.Errorf("failed to delete blob: %w", err)
	}

	r.logger.Info("Deleted blob metadata with id ", blobID)
	return nil
}
