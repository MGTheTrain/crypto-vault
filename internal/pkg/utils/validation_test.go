//go:build unit
// +build unit

package utils

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestCheckNonEmptyStrings tests the CheckNonEmptyStrings function
func TestCheckNonEmptyStrings(t *testing.T) {
	// Test with all non-empty strings
	err := CheckNonEmptyStrings("test", "hello", "world")
	assert.NoError(t, err, "Expected no error for non-empty strings")

	// Test with one empty string
	err = CheckNonEmptyStrings("test", "", "world")
	assert.Error(t, err, "Expected error for empty string")
	assert.Equal(t, err.Error(), "one of the input strings is empty", "Error message should match")

	// Test with all empty strings
	err = CheckNonEmptyStrings("", "", "")
	assert.Error(t, err, "Expected error for all empty strings")
	assert.Equal(t, err.Error(), "one of the input strings is empty", "Error message should match")
}

// TestCheckFilesExist tests the CheckFilesExist function
func TestCheckFilesExist(t *testing.T) {
	// Prepare a test file path for a file that will be created during the test
	existingFilePath := "testfile.txt"
	nonExistentFilePath := "non_existent_file.txt"

	// Create the test file to ensure it exists
	err := os.WriteFile(existingFilePath, []byte("This is a test file."), 0600)
	assert.NoError(t, err, "Expected no error when creating test file")

	// Test with existing file
	err = CheckFilesExist(existingFilePath)
	assert.NoError(t, err, "Expected no error for existing file")

	// Test with non-existent file
	err = CheckFilesExist(nonExistentFilePath)
	assert.Error(t, err, "Expected error for non-existent file")
	assert.Equal(t, err.Error(), "file does not exist: non_existent_file.txt", "Error message should match")

	// Clean up the test file
	err = os.Remove(existingFilePath)
	assert.NoError(t, err, "Error cleaning up the test file")
}
