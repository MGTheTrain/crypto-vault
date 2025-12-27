package testutil

import (
	"bytes"
	"mime/multipart"
	"os"
	"testing"

	"github.com/MGTheTrain/crypto-vault/internal/pkg/httputil"
	"github.com/stretchr/testify/require"
)

// CreateTestFileAndForm creates a test file and form
func CreateTestFileAndForm(t *testing.T, fileName string, fileContent []byte) (*multipart.Form, error) {
	err := CreateTestFile(fileName, fileContent)
	require.NoError(t, err)

	t.Cleanup(func() {
		if err := os.Remove(fileName); err != nil {
			t.Logf("failed to remove temporary file %s: %v", fileName, err)
		}
	})

	form, err := httputil.CreateForm(fileContent, fileName)
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
