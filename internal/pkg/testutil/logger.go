package testutil

import (
	"testing"

	"github.com/MGTheTrain/crypto-vault/internal/pkg/config"
	"github.com/MGTheTrain/crypto-vault/internal/pkg/logger"
	"github.com/stretchr/testify/require"
)

// SetupTestLogger sets up a logger for testing purposes.
func SetupTestLogger(t *testing.T) logger.Logger {
	t.Helper()

	settings := &config.LoggerSettings{
		LogLevel: config.LogLevelInfo,
		LogType:  config.LogTypeConsole,
	}

	err := logger.InitLogger(settings)
	require.NoError(t, err)

	log, err := logger.GetLogger()
	require.NoError(t, err)

	return log
}
