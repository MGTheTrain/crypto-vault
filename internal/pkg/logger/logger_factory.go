package logger

import (
	"crypto_vault_service/internal/pkg/config"
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
func InitLogger(settings *config.LoggerSettings) error {
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

func newLogger(c *config.LoggerSettings) (Logger, error) {
	if err := c.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	switch c.LogType {
	case config.LogTypeConsole:
		return NewConsoleLogger(c.LogLevel), nil
	case config.LogTypeFile:
		if c.FilePath == "" {
			return nil, fmt.Errorf("file path required for file logger")
		}
		return NewFileLogger(c.LogLevel, c.FilePath, c.MaxSize, c.MaxBackups, c.MaxAge), nil
	default:
		return nil, fmt.Errorf("unsupported log type: %s", c.LogType)
	}
}

// Helper functions
func parseLevel(level string) slog.Level {
	switch level {
	case config.LogLevelDebug:
		return slog.LevelDebug
	case config.LogLevelInfo:
		return slog.LevelInfo
	case config.LogLevelWarning:
		return slog.LevelWarn
	case config.LogLevelError:
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
