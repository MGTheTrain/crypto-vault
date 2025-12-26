package keys

import (
	"errors"
	"fmt"
	"time"

	"github.com/go-playground/validator/v10"
)

// CryptoKeyQuery represents the parameters used to query encryption keys.
type CryptoKeyQuery struct {
	Algorithm       string    `validate:"omitempty,oneof=AES RSA ECDSA"`            // Type is optional but if provided, must be one of the listed types (AES, RSA, ECDSA)
	Type            string    `validate:"omitempty,oneof=private public symmetric"` // Type is optional but if provided, must be one of the listed types (private-key, public-key, symmetric-key)
	DateTimeCreated time.Time `validate:"omitempty,gtefield=date_time_created"`     // DateTimeCreated is optional, but can be used for filtering

	// Pagination properties
	Limit  int `validate:"omitempty,min=1"` // Limit is optional but if provided, should be at least 1
	Offset int `validate:"omitempty,min=0"` // Offset is optional but should be 0 or greater for pagination

	// Sorting properties
	SortBy    string `validate:"omitempty,oneof=ID type date_time_created"` // SortBy is optional but can be one of the fields to sort by
	SortOrder string `validate:"omitempty,oneof=asc desc"`                  // SortOrder is optional, default is ascending ('asc'), can also be 'desc'
}

// NewCryptoKeyQuery creates a CryptoKeyQuery with default values
func NewCryptoKeyQuery() *CryptoKeyQuery {
	return &CryptoKeyQuery{
		Limit:     10,                  // Default limit to 10 results per page
		Offset:    0,                   // Default offset to 0 for pagination
		SortBy:    "date_time_created", // Default sort by DateTimeCreated
		SortOrder: "asc",               // Default sort order ascending
	}
}

// Validate validates the CryptoKeyQuery struct based on the defined rules.
func (k *CryptoKeyQuery) Validate() error {
	validate := validator.New()
	err := validate.Struct(k)
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
