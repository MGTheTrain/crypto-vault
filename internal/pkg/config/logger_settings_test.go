//go:build unit
// +build unit

package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLoggerSettingsValidation(t *testing.T) {
	tests := []struct {
		name          string
		settings      *LoggerSettings
		expectedError bool
	}{
		{
			name: "valid console logger",
			settings: &LoggerSettings{
				LogLevel: LogLevelInfo,
				LogType:  LogTypeConsole,
			},
			expectedError: false,
		},
		{
			name: "valid file logger with rotation",
			settings: &LoggerSettings{
				LogLevel:   LogLevelInfo,
				LogType:    LogTypeFile,
				FilePath:   "/path/to/log/file",
				MaxSize:    10,
				MaxBackups: 3,
				MaxAge:     28,
			},
			expectedError: false,
		},
		{
			name: "missing log level",
			settings: &LoggerSettings{
				LogType: LogTypeConsole,
			},
			expectedError: true,
		},
		{
			name: "missing log type",
			settings: &LoggerSettings{
				LogLevel: LogLevelInfo,
			},
			expectedError: true,
		},
		{
			name: "invalid log type",
			settings: &LoggerSettings{
				LogLevel: LogLevelInfo,
				LogType:  "invalid",
			},
			expectedError: true,
		},
		{
			name: "file logger missing file path",
			settings: &LoggerSettings{
				LogLevel:   LogLevelInfo,
				LogType:    LogTypeFile,
				MaxSize:    10,
				MaxBackups: 3,
				MaxAge:     28,
			},
			expectedError: true,
		},
		{
			name: "file logger missing rotation settings",
			settings: &LoggerSettings{
				LogLevel: LogLevelInfo,
				LogType:  LogTypeFile,
				FilePath: "/path/to/log/file",
			},
			expectedError: true,
		},
		{
			name: "file logger invalid max size (too small)",
			settings: &LoggerSettings{
				LogLevel:   LogLevelInfo,
				LogType:    LogTypeFile,
				FilePath:   "/path/to/log/file",
				MaxSize:    0,
				MaxBackups: 3,
				MaxAge:     28,
			},
			expectedError: true,
		},
		{
			name: "file logger invalid max size (too large)",
			settings: &LoggerSettings{
				LogLevel:   LogLevelInfo,
				LogType:    LogTypeFile,
				FilePath:   "/path/to/log/file",
				MaxSize:    101,
				MaxBackups: 3,
				MaxAge:     28,
			},
			expectedError: true,
		},
		{
			name: "console logger ignores rotation settings",
			settings: &LoggerSettings{
				LogLevel:   LogLevelInfo,
				LogType:    LogTypeConsole,
				FilePath:   "/path/to/log/file",
				MaxSize:    10,
				MaxBackups: 3,
				MaxAge:     28,
			},
			expectedError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.settings.Validate()

			if tt.expectedError {
				assert.Error(t, err, "expected an error")
			} else {
				assert.NoError(t, err, "expected no error")
			}
		})
	}
}
