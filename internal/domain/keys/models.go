package keys

import (
	"crypto_vault_service/internal/pkg/validators"
	"errors"
	"fmt"
	"time"

	"github.com/go-playground/validator/v10"
)

// CryptoKeyMeta entity
type CryptoKeyMeta struct {
	ID              string    `gorm:"primaryKey" validate:"required,uuid4"`
	KeyPairID       string    `gorm:"index" validate:"required,uuid4"`
	Algorithm       string    `validate:"omitempty,oneof=AES RSA EC"`
	KeySize         uint32    `json:"key_size" validate:"omitempty,keySizeValidation"`
	Type            string    `validate:"omitempty,oneof=private public symmetric"`
	DateTimeCreated time.Time `validate:"required"`
	UserID          string    `gorm:"index" validate:"required,uuid4"`
}

// Validate method for CryptoKeyMeta struct
func (k *CryptoKeyMeta) Validate() error {
	validate := validator.New()

	if err := validate.RegisterValidation("keySizeValidation", validators.KeySizeValidation); err != nil {
		return fmt.Errorf("failed to register custom validator: %w", err)
	}

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
