//go:build unit
// +build unit

package logger

import (
	"bytes"
	"crypto_vault_service/internal/pkg/config"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConsoleLogger_LogsToOutput(t *testing.T) {
	var buf bytes.Buffer

	// Create logger with custom output for testing
	opts := &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}
	handler := slog.NewTextHandler(&buf, opts)
	logger := &ConsoleLogger{logger: slog.New(handler)}

	// Log messages at different levels
	logger.Info("info message")
	logger.Warn("warn message")
	logger.Error("error message")

	// Verify output contains all messages
	output := buf.String()
	assert.Contains(t, output, "info message")
	assert.Contains(t, output, "warn message")
	assert.Contains(t, output, "error message")
}

func TestNewConsoleLogger(t *testing.T) {
	logger := NewConsoleLogger(config.LogLevelInfo)
	require.NotNil(t, logger)

	// Verify it satisfies the Logger interface and doesn't panic
	require.NotPanics(t, func() {
		logger.Info("test")
		logger.Warn("test")
		logger.Error("test")
	})
}
