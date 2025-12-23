package logger

import (
	"crypto_vault_service/internal/infrastructure/settings"
	"fmt"
	"log/slog"
	"sync"
)

var (
	loggerInstance Logger
	loggerErr      error
	loggerOnce     sync.Once
)

// InitLogger initializes the singleton logger.
func InitLogger(settings *settings.LoggerSettings) error {
	loggerOnce.Do(func() {
		loggerInstance, loggerErr = newLogger(settings)
	})
	return loggerErr
}

// GetLogger returns the initialized logger instance.
func GetLogger() (Logger, error) {
	if loggerInstance == nil {
		return nil, fmt.Errorf("logger not initialized: call InitLogger first")
	}
	return loggerInstance, nil
}

func newLogger(config *settings.LoggerSettings) (Logger, error) {
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	switch config.LogType {
	case settings.LogTypeConsole:
		return NewConsoleLogger(config.LogLevel), nil
	case settings.LogTypeFile:
		if config.FilePath == "" {
			return nil, fmt.Errorf("file path required for file logger")
		}
		return NewFileLogger(config.LogLevel, config.FilePath, config.MaxSize, config.MaxBackups, config.MaxAge), nil
	default:
		return nil, fmt.Errorf("unsupported log type: %s", config.LogType)
	}
}

// Helper functions
func parseLevel(level string) slog.Level {
	switch level {
	case settings.LogLevelDebug:
		return slog.LevelDebug
	case settings.LogLevelInfo:
		return slog.LevelInfo
	case settings.LogLevelWarning:
		return slog.LevelWarn
	case settings.LogLevelError:
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

func formatArgs(args ...interface{}) string {
	if len(args) == 0 {
		return ""
	}
	return fmt.Sprint(args...)
}
