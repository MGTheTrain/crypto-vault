package commands

import (
	"fmt"

	"github.com/MGTheTrain/crypto-vault/internal/pkg/config"
	"github.com/MGTheTrain/crypto-vault/internal/pkg/logger"
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
