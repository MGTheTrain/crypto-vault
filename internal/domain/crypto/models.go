package crypto

import (
	"errors"
	"fmt"

	"github.com/go-playground/validator/v10"
)

// Token represents a PKCS#11 token with label and other metadata
type Token struct {
	SlotID       string `mapstructure:"slot_id" validate:"required"`
	Label        string `mapstructure:"label" validate:"required"`
	Manufacturer string `mapstructure:"manufacturer" validate:"required"`
	Model        string `mapstructure:"model" validate:"required"`
	SerialNumber string `mapstructure:"serial_number" validate:"required"`
}

// Validate for validating Token struct
func (t *Token) Validate() error {
	validate := validator.New()

	err := validate.Struct(t)
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

// TokenObject represents a PKCS#11 object (e.g. public or private key) with metadata.
type TokenObject struct {
	Label  string `mapstructure:"label" validate:"required"`
	Type   string `mapstructure:"type" validate:"required"`
	Usage  string `mapstructure:"usage" validate:"required"`
	Access string `mapstructure:"access" validate:"required"`
}

// Validate for validating TokenObject struct
func (t *TokenObject) Validate() error {
	validate := validator.New()

	err := validate.Struct(t)
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
