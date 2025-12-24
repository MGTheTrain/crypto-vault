//go:build unit
// +build unit

package logger

import (
	"crypto_vault_service/internal/pkg/config"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func resetLoggerSingleton() {
	loggerInstance = nil
	loggerErr = nil
	loggerOnce = sync.Once{}
}

func TestInitLogger(t *testing.T) {
	tests := []struct {
		name      string
		settings  *config.LoggerSettings
		wantErr   bool
		setupTest func(*testing.T) string
	}{
		{
			name: "console logger",
			settings: &config.LoggerSettings{
				LogLevel: config.LogLevelInfo,
				LogType:  config.LogTypeConsole,
			},
			wantErr: false,
		},
		{
			name: "file logger with rotation",
			settings: &config.LoggerSettings{
				LogLevel:   config.LogLevelInfo,
				LogType:    config.LogTypeFile,
				FilePath:   "",
				MaxSize:    10,
				MaxBackups: 3,
				MaxAge:     28,
			},
			wantErr: false,
			setupTest: func(t *testing.T) string {
				tmpDir := t.TempDir()
				return filepath.Join(tmpDir, "app.log")
			},
		},
		{
			name: "invalid log level",
			settings: &config.LoggerSettings{
				LogLevel: "invalid",
				LogType:  config.LogTypeConsole,
			},
			wantErr: true,
		},
		{
			name: "unsupported log type",
			settings: &config.LoggerSettings{
				LogLevel: config.LogLevelInfo,
				LogType:  "unknown",
			},
			wantErr: true,
		},
		{
			name: "file logger missing rotation settings",
			settings: &config.LoggerSettings{
				LogLevel: config.LogLevelInfo,
				LogType:  config.LogTypeFile,
				FilePath: "/tmp/test.log",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Cleanup(resetLoggerSingleton)

			if tt.setupTest != nil {
				tt.settings.FilePath = tt.setupTest(t)
			}

			err := InitLogger(tt.settings)

			if tt.wantErr {
				assert.Error(t, err, "expected error for test: %s", tt.name)

				logger, getErr := GetLogger()
				assert.Error(t, getErr)
				assert.Nil(t, logger)
			} else {
				require.NoError(t, err, "unexpected error for test: %s", tt.name)

				logger, err := GetLogger()
				require.NoError(t, err)
				require.NotNil(t, logger)

				if tt.settings.LogType == config.LogTypeFile {
					logger.Info("test message")
					_, err := os.Stat(tt.settings.FilePath)
					assert.NoError(t, err)
				}
			}
		})
	}
}

func TestGetLogger_BeforeInit(t *testing.T) {
	t.Cleanup(resetLoggerSingleton)

	logger, err := GetLogger()
	assert.Error(t, err)
	assert.Nil(t, logger)
	assert.Contains(t, err.Error(), "not initialized")
}

func TestInitLogger_Singleton(t *testing.T) {
	t.Cleanup(resetLoggerSingleton)

	err := InitLogger(&config.LoggerSettings{
		LogLevel: config.LogLevelInfo,
		LogType:  config.LogTypeConsole,
	})
	require.NoError(t, err)

	logger1, err := GetLogger()
	require.NoError(t, err)

	logger2, err := GetLogger()
	require.NoError(t, err)

	assert.Same(t, logger1, logger2)
}

func TestInitLogger_Idempotent(t *testing.T) {
	t.Cleanup(resetLoggerSingleton)

	err1 := InitLogger(&config.LoggerSettings{
		LogLevel: config.LogLevelInfo,
		LogType:  config.LogTypeConsole,
	})
	require.NoError(t, err1)

	err2 := InitLogger(&config.LoggerSettings{
		LogLevel: config.LogLevelDebug,
		LogType:  config.LogTypeConsole,
	})
	assert.NoError(t, err2)

	logger1, _ := GetLogger()
	logger2, _ := GetLogger()
	assert.Same(t, logger1, logger2)
}

func TestParseLevel(t *testing.T) {
	tests := []struct {
		level    string
		expected slog.Level
	}{
		{config.LogLevelDebug, slog.LevelDebug},
		{config.LogLevelInfo, slog.LevelInfo},
		{config.LogLevelWarning, slog.LevelWarn},
		{config.LogLevelError, slog.LevelError},
		{"unknown", slog.LevelInfo}, // default case
	}

	for _, tt := range tests {
		t.Run(tt.level, func(t *testing.T) {
			result := parseLevel(tt.level)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestFormatArgs(t *testing.T) {
	tests := []struct {
		name     string
		args     []interface{}
		expected string
	}{
		{"empty", []interface{}{}, ""},
		{"single", []interface{}{"test"}, "test"},
		{"multiple", []interface{}{"hello", "world"}, "helloworld"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := formatArgs(tt.args...)
			assert.Equal(t, tt.expected, result)
		})
	}
}
