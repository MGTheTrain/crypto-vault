package config

import (
	"fmt"

	"github.com/go-playground/validator/v10"
)

// DatabaseSettings holds configuration settings for connecting to a database, including type, DSN and name
type DatabaseSettings struct {
	Type   string `mapstructure:"type" validate:"required,oneof=postgres sqlite"`
	DSN    string `mapstructure:"dsn" validate:"required"`
	DBName string `mapstructure:"db_name" validate:"required"`
}

// Validate checks that all fields in DatabaseSettings are valid (non-empty in this case)
func (settings *DatabaseSettings) Validate() error {
	validate := validator.New()

	err := validate.Struct(settings)
	if err != nil {
		return fmt.Errorf("validation failed: %w", err)
	}
	return nil
}
