package persistence

import (
	"context"
	"crypto_vault_service/internal/domain/blobs"
	"crypto_vault_service/internal/pkg/logger"
	"errors"
	"fmt"

	"gorm.io/gorm"
)

// gormBlobRepository is the implementation of the BlobRepository interface
type gormBlobRepository struct {
	db     *gorm.DB
	logger logger.Logger
}

// NewGormBlobRepository creates a new gormBlobRepository instance
func NewGormBlobRepository(db *gorm.DB, logger logger.Logger) (blobs.BlobRepository, error) {

	return &gormBlobRepository{
		db:     db,
		logger: logger,
	}, nil
}

// Create adds a new Blob to the database
func (r *gormBlobRepository) Create(ctx context.Context, blob *blobs.BlobMeta) error {
	// Validate the Blob before saving
	if err := blob.Validate(); err != nil {
		return fmt.Errorf("validation error: %w", err)
	}

	if err := r.db.WithContext(ctx).Create(&blob).Error; err != nil {
		return fmt.Errorf("failed to create blob: %w", err)
	}
	r.logger.Info(fmt.Sprintf("Created blob metadata with id %s", blob.ID))
	return nil
}

func (r *gormBlobRepository) List(ctx context.Context, query *blobs.BlobMetaQuery) ([]*blobs.BlobMeta, error) {
	// Validate the query parameters before using them
	if err := query.Validate(); err != nil {
		return nil, fmt.Errorf("invalid query parameters: %w", err)
	}

	// Start building the query
	var blobMetas []*blobs.BlobMeta
	dbQuery := r.db.WithContext(ctx).Model(&blobs.BlobMeta{})

	// Apply filters based on the query
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
		order := query.SortOrder // Default to ascending if not specified
		if query.SortOrder == "" {
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

	// Execute the query
	if err := dbQuery.Find(&blobMetas).Error; err != nil {
		return nil, fmt.Errorf("failed to fetch blobs: %w", err)
	}

	// Return the list of blob metadata
	return blobMetas, nil
}

// GetByID retrieves a Blob by its ID from the database
func (r *gormBlobRepository) GetByID(ctx context.Context, blobID string) (*blobs.BlobMeta, error) {
	var blob blobs.BlobMeta
	if err := r.db.WithContext(ctx).Where("id = ?", blobID).First(&blob).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("blob with ID %s not found", blobID)
		}

		return nil, fmt.Errorf("failed to fetch blob: %w", err)
	}
	return &blob, nil
}

// UpdateByID updates an existing Blob in the database
func (r *gormBlobRepository) UpdateByID(ctx context.Context, blob *blobs.BlobMeta) error {
	// Validate the Blob before updating
	if err := blob.Validate(); err != nil {
		return fmt.Errorf("validation error: %w", err)
	}

	if err := r.db.WithContext(ctx).Save(&blob).Error; err != nil {
		return fmt.Errorf("failed to update blob: %w", err)
	}
	r.logger.Info(fmt.Sprintf("Updated blob metadata with id %s", blob.ID))
	return nil
}

// DeleteByID removes a Blob from the database by its ID
func (r *gormBlobRepository) DeleteByID(ctx context.Context, blobID string) error {
	if err := r.db.WithContext(ctx).Where("id = ?", blobID).Delete(&blobs.BlobMeta{}).Error; err != nil {
		return fmt.Errorf("failed to delete blob: %w", err)
	}
	r.logger.Info(fmt.Sprintf("Deleted blob metadata with id %s", blobID))
	return nil
}
