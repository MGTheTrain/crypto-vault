package utils

import (
	"bytes"
	"fmt"
	"log"
	"mime/multipart"
)

// CreateForm creates a multipart form with a single file and its associated content
func CreateForm(content []byte, fileName string) (*multipart.Form, error) {
	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)

	fileWriter, err := writer.CreateFormFile("files", fileName)
	if err != nil {
		return nil, fmt.Errorf("failed to create form file for '%s': %w", fileName, err)
	}

	_, err = fileWriter.Write(content)
	if err != nil {
		return nil, fmt.Errorf("failed to write content to form file '%s': %w", fileName, err)
	}

	err = writer.Close()
	if err != nil {
		log.Printf("Error closing writer: %v", err)
	}

	mr := multipart.NewReader(&buf, writer.Boundary())
	form, err := mr.ReadForm(10 << 20)
	if err != nil {
		return nil, fmt.Errorf("failed to read form with max size %d: %w", 10<<20, err)
	}

	return form, nil
}

// CreateMultipleFilesForm creates a multipart form with multiple files and their associated contents.
func CreateMultipleFilesForm(contents [][]byte, fileNames []string) (*multipart.Form, error) {
	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)

	// Ensure the number of contents and file names match
	if len(contents) != len(fileNames) {
		return nil, fmt.Errorf("number of contents and file names must match")
	}

	// Loop over the contents and write each one to the multipart form
	for i, content := range contents {
		fileWriter, err := writer.CreateFormFile("files", fileNames[i])
		if err != nil {
			return nil, fmt.Errorf("failed to create form file for '%s': %w", fileNames[i], err)
		}

		_, err = fileWriter.Write(content)
		if err != nil {
			return nil, fmt.Errorf("failed to write content to file: %w", err)
		}
	}

	err := writer.Close()
	if err != nil {
		log.Printf("Error closing writer: %v", err)
	}

	// Read the form from the buffer
	mr := multipart.NewReader(&buf, writer.Boundary())
	form, err := mr.ReadForm(10 << 20)
	if err != nil {
		return nil, fmt.Errorf("failed to read form data: %w", err)
	}

	return form, nil
}
