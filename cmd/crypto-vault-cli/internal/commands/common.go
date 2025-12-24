package commands

import (
	"crypto_vault_service/internal/pkg/config"
	"crypto_vault_service/internal/pkg/logger"
	"fmt"
)

// In commands/common.go
func setupLogger() (logger.Logger, error) {
	settings := &config.LoggerSettings{
		LogLevel: "info",
		LogType:  "console",
		FilePath: "",
	}

	if err := logger.InitLogger(settings); err != nil {
		return nil, fmt.Errorf("failed to initialize logger: %w", err)
	}

	loggerInstance, err := logger.GetLogger()
	if err != nil {
		return nil, fmt.Errorf("failed to get logger instance: %w", err)
	}

	return loggerInstance, nil
}
