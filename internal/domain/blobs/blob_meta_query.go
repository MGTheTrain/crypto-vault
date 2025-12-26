package blobs

import (
	"errors"
	"fmt"
	"time"

	"github.com/go-playground/validator/v10"
)

// BlobMetaQuery represents metadata on the actual blob being stored.
type BlobMetaQuery struct {
	DateTimeCreated time.Time `validate:"omitempty"`               // DateTimeCreated is optional
	Name            string    `validate:"omitempty,min=1,max=255"` // Name is optional and length must be between 1 and 255 characters
	Size            int64     `validate:"omitempty,min=1"`         // Size is optional and if set must be greater than 0
	Type            string    `validate:"omitempty,min=1,max=50"`  // Type is optional, and length must be between 1 and 50 characters

	// Pagination properties
	Limit  int `validate:"omitempty,min=1"` // Limit is optional but if provided, should be at least 1
	Offset int `validate:"omitempty,min=0"` // Offset is optional but should be 0 or greater for pagination

	// Sorting properties
	SortBy    string `validate:"omitempty,oneof=ID type date_time_created"` // SortBy is optional but can be one of the fields to sort by
	SortOrder string `validate:"omitempty,oneof=asc desc"`                  // SortOrder is optional, default is ascending ('asc'), can also be 'desc'
}

// NewBlobMetaQuery creates a BlobMetaQuery with default values.
func NewBlobMetaQuery() *BlobMetaQuery {
	return &BlobMetaQuery{
		Limit:     10,                  // Default limit to 10 results per page
		Offset:    0,                   // Default offset to 0 for pagination
		SortBy:    "date_time_created", // Default sort by DateTimeCreated
		SortOrder: "asc",               // Default sort order ascending
	}
}

// Validate validates the BlobMetaQuery struct based on the defined rules.
func (b *BlobMetaQuery) Validate() error {
	validate := validator.New()

	err := validate.Struct(b)
	if err != nil {
		var validationErrors validator.ValidationErrors
		if errors.As(err, &validationErrors) {
			var messages []string
			for _, fieldErr := range validationErrors {
				messages = append(messages, fmt.Sprintf("Field: %s, Tag: %s", fieldErr.Field(), fieldErr.Tag()))
			}
			return fmt.Errorf("validation failed: %v", messages)
		}
		return fmt.Errorf("validation error: %w", err)
	}

	return nil
}
