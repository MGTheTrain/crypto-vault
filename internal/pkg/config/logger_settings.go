package config

import (
	"fmt"

	"github.com/go-playground/validator/v10"
)

// Log level constants
const (
	LogLevelInfo     = "info"
	LogLevelDebug    = "debug"
	LogLevelError    = "error"
	LogLevelWarning  = "warning"
	LogLevelCritical = "critical"
)

// Log type constants
const (
	LogTypeConsole = "console"
	LogTypeFile    = "file"
)

// LoggerSettings holds configuration settings for logging, including log level, type and file path
type LoggerSettings struct {
	LogLevel   string `mapstructure:"log_level" validate:"required,oneof=info debug error warning critical"`
	LogType    string `mapstructure:"log_type" validate:"required,oneof=console file"`
	FilePath   string `mapstructure:"file_path"`
	MaxSize    int    `mapstructure:"max_size"`
	MaxBackups int    `mapstructure:"max_backups"`
	MaxAge     int    `mapstructure:"max_age"`
}

// Validate checks that all fields in LoggerSettings are valid
func (s *LoggerSettings) Validate() error {
	validate := validator.New()

	if err := validate.Struct(s); err != nil {
		return fmt.Errorf("validation failed for LoggerSettings: %w", err)
	}

	// Additional validation for file logger
	if s.LogType == LogTypeFile {
		if s.FilePath == "" {
			return fmt.Errorf("file path is required for file logger")
		}
		if s.MaxSize < 1 || s.MaxSize > 100 {
			return fmt.Errorf("max size must be between 1 and 100 MB")
		}
		if s.MaxBackups < 1 || s.MaxBackups > 10 {
			return fmt.Errorf("max backups must be between 1 and 10")
		}
		if s.MaxAge < 1 || s.MaxAge > 365 {
			return fmt.Errorf("max age must be between 1 and 365 days")
		}
	}

	return nil
}
