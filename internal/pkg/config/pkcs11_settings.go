package config

import (
	"fmt"

	"github.com/go-playground/validator/v10"
)

// PKCS11Settings holds the configuration settings required to interact with a PKCS#11 module
type PKCS11Settings struct {
	ModulePath string `mapstructure:"module_path" validate:"required"`
	SOPin      string `mapstructure:"so_pin" validate:"required"`
	UserPin    string `mapstructure:"user_pin" validate:"required"`
	SlotID     string `mapstructure:"slot_id" validate:"required"`
}

// Validate checks that all fields in PKCS11Settings are valid (non-empty in this case)
func (settings *PKCS11Settings) Validate() error {
	validate := validator.New()

	err := validate.Struct(settings)
	if err != nil {
		return fmt.Errorf("validation failed: %w", err)
	}
	return nil
}
