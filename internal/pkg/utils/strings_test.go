package utils

import (
	"log"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCreateForm(t *testing.T) {
	content := []byte("hello world")
	fileName := "test.txt"

	form, err := CreateForm(content, fileName)
	assert.NoError(t, err)
	assert.NotNil(t, form)

	files := form.File["files"]
	assert.Len(t, files, 1)
	assert.Equal(t, fileName, files[0].Filename)

	// Check file content
	file, err := files[0].Open()
	assert.NoError(t, err)
	defer func() {
		if err := file.Close(); err != nil {
			log.Printf("warning: failed to close file: %v\n", err)
		}
	}()

	buf := make([]byte, len(content))
	_, err = file.Read(buf)
	assert.NoError(t, err)
	assert.Equal(t, content, buf)
}

func TestCreateMultipleFilesForm(t *testing.T) {
	contents := [][]byte{
		[]byte("file one content"),
		[]byte("file two content"),
	}
	fileNames := []string{
		"file1.txt",
		"file2.txt",
	}

	form, err := CreateMultipleFilesForm(contents, fileNames)
	assert.NoError(t, err)
	assert.NotNil(t, form)

	files := form.File["files"]
	assert.Len(t, files, 2)

	for i, fh := range files {
		assert.Equal(t, fileNames[i], fh.Filename)

		file, err := fh.Open()
		assert.NoError(t, err)

		buf := make([]byte, len(contents[i]))
		_, err = file.Read(buf)
		assert.NoError(t, err)
		assert.Equal(t, contents[i], buf)
		defer func() {
			if err := file.Close(); err != nil {
				log.Printf("warning: failed to close file: %v\n", err)
			}
		}()
	}
}

func TestCreateMultipleFilesForm_MismatchedInputs(t *testing.T) {
	contents := [][]byte{
		[]byte("file one content"),
	}
	fileNames := []string{
		"file1.txt",
		"extra.txt",
	}

	form, err := CreateMultipleFilesForm(contents, fileNames)
	assert.Nil(t, form)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "number of contents and file names must match")
}
