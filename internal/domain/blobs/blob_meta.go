package blobs

import (
	"crypto_vault_service/internal/pkg/validators"
	"errors"
	"fmt"
	"time"

	"github.com/go-playground/validator/v10"
)

// BlobMeta entity
type BlobMeta struct {
	ID                string    `validate:"required,uuid4"`
	DateTimeCreated   time.Time `validate:"required"`
	UserID            string    `validate:"required,uuid4"`
	Name              string    `validate:"required,min=1,max=255"`
	Size              int64     `validate:"required,min=1"`
	Type              string    `validate:"required,min=1,max=50"`
	EncryptionKeyID   *string   `validate:"omitempty,uuid4"`
	SignKeyID         *string   `validate:"omitempty,uuid4"`
	SignatureBlobID   *string   `validate:"omitempty,uuid4"`
	SignatureFileName *string   `validate:"omitempty,min=1,max=255"`
}

// Validate for validating BlobMeta struct
func (b *BlobMeta) Validate() error {
	validate := validator.New()

	if err := validate.RegisterValidation("keySizeValidation", validators.KeySizeValidation); err != nil {
		return fmt.Errorf("failed to register custom validator: %w", err)
	}

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
