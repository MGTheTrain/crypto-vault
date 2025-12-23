//go:build unit
// +build unit

package logger

import (
	"crypto_vault_service/internal/infrastructure/settings"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewFileLogger(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "test.log")

	logger := NewFileLogger(settings.LogLevelInfo, logPath, 10, 3, 28)
	require.NotNil(t, logger)

	logger.Info("info message")
	logger.Warn("warn message")
	logger.Error("error message")

	// Verify file exists
	_, err := os.Stat(logPath)
	assert.NoError(t, err)

	// Verify log content
	content, err := os.ReadFile(logPath)
	require.NoError(t, err)

	logOutput := string(content)
	assert.Contains(t, logOutput, "info message")
	assert.Contains(t, logOutput, "warn message")
	assert.Contains(t, logOutput, "error message")
	assert.Contains(t, logOutput, "INFO")
	assert.Contains(t, logOutput, "WARN")
	assert.Contains(t, logOutput, "ERROR")
}
