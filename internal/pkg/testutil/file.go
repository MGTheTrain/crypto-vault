package testutil

import (
	"fmt"
	"os"
)

// CreateTestFile create a test files
func CreateTestFile(fileName string, content []byte) error {
	err := os.WriteFile(fileName, content, 0600)
	if err != nil {
		return fmt.Errorf("failed to create test file: %w", err)
	}
	return nil
}
