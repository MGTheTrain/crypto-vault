package testing

import (
	"bytes"
	"crypto_vault_service/internal/pkg/config"
	"crypto_vault_service/internal/pkg/logger"
	"crypto_vault_service/internal/pkg/utils"
	"fmt"
	"mime/multipart"
	"os"
	"testing"

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

// CreateTestFile create a test files
func CreateTestFile(fileName string, content []byte) error {
	err := os.WriteFile(fileName, content, 0600)
	if err != nil {
		return fmt.Errorf("failed to create test file: %w", err)
	}
	return nil
}

// CreateTestFileAndForm creates a test file and form
func CreateTestFileAndForm(t *testing.T, fileName string, fileContent []byte) (*multipart.Form, error) {
	err := CreateTestFile(fileName, fileContent)
	require.NoError(t, err)

	t.Cleanup(func() {
		if err := os.Remove(fileName); err != nil {
			t.Logf("failed to remove temporary file %s: %v", fileName, err)
		}
	})

	form, err := utils.CreateForm(fileContent, fileName)
	require.NoError(t, err)

	return form, nil
}

// CreateEmptyForm creates an empty multipart form for testing
func CreateEmptyForm() *multipart.Form {
	return &multipart.Form{
		File: make(map[string][]*multipart.FileHeader),
	}
}

// CreateMultipleTestFilesForm creates a multipart form with multiple test files
func CreateMultipleTestFilesForm(t *testing.T, files map[string][]byte) (*multipart.Form, error) {
	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)

	for filename, content := range files {
		part, err := writer.CreateFormFile("files", filename)
		require.NoError(t, err)

		_, err = part.Write(content)
		require.NoError(t, err)
	}

	err := writer.Close()
	require.NoError(t, err)

	reader := multipart.NewReader(&buf, writer.Boundary())
	form, err := reader.ReadForm(32 << 20) // 32 MB
	require.NoError(t, err)

	// Set FileHeader.Size manually (same fix as utils.CreateMultipleFilesForm)
	if fileHeaders, ok := form.File["files"]; ok {
		i := 0
		for _, content := range files {
			if i < len(fileHeaders) {
				fileHeaders[i].Size = int64(len(content))
				i++
			}
		}
	}

	return form, nil
}
