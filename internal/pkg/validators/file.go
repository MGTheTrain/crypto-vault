package validators

import (
	"fmt"
	"os"
)

// CheckNonEmptyStrings checks if any of the input strings are empty
func CheckNonEmptyStrings(args ...string) error {
	for _, arg := range args {
		if arg == "" {
			return fmt.Errorf("one of the input strings is empty")
		}
	}
	return nil
}

// CheckFilesExist checks if the input files exist
func CheckFilesExist(filePaths ...string) error {
	for _, filePath := range filePaths {
		if _, err := os.Stat(filePath); os.IsNotExist(err) {
			return fmt.Errorf("file does not exist: %s", filePath)
		}
	}
	return nil
}
