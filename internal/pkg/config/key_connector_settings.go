package config

import (
	"fmt"

	"github.com/go-playground/validator/v10"
)

// KeyConnectorSettings holds configuration settings for connecting to a key storage service
type KeyConnectorSettings struct {
	CloudProvider    string `mapstructure:"cloud_provider" validate:"required"`
	ConnectionString string `mapstructure:"connection_string" validate:"required"`
	ContainerName    string `mapstructure:"container_name" validate:"required"`
}

// Validate checks that all fields in KeyConnectorSettings are valid (non-empty in this case)
func (settings *KeyConnectorSettings) Validate() error {
	validate := validator.New()

	err := validate.Struct(settings)
	if err != nil {
		return fmt.Errorf("validation failed: %w", err)
	}
	return nil
}
