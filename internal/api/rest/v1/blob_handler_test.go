//go:build unit
// +build unit

package v1

import (
	"bytes"
	"errors"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/MGTheTrain/crypto-vault/internal/domain/blobs"
	"github.com/MGTheTrain/crypto-vault/internal/pkg/testutil"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestBlobHandler_Upload_Success(t *testing.T) {
	mockUploadService := new(MockBlobUploadService)
	mockDownloadService := new(MockBlobDownloadService)
	mockMetadataService := new(MockBlobMetadataService)
	mockCryptoKeyUploadService := new(MockCryptoKeyUploadService)

	handler := NewBlobHandler(mockUploadService, mockDownloadService, mockMetadataService, mockCryptoKeyUploadService)

	blobMeta := blobs.BlobMeta{ID: "123"}

	mockUploadService.On("Upload", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return([]*blobs.BlobMeta{&blobMeta}, nil)

	fileName := "testfile.txt"
	fileContent := []byte("This is a test file content")
	form, err := testutil.CreateTestFileAndForm(t, fileName, fileContent)
	require.NoError(t, err)

	var b bytes.Buffer
	writer := multipart.NewWriter(&b)
	fileWriter, err := writer.CreateFormFile("file", fileName)
	require.NoError(t, err)

	_, err = fileWriter.Write(fileContent)
	require.NoError(t, err)
	writer.Close()

	req, err := http.NewRequest("POST", "/blobs", &b)
	require.NoError(t, err)
	req.Header.Set("Content-Type", writer.FormDataContentType())

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = req
	c.Request.MultipartForm = form

	handler.Upload(c)

	assert.Equal(t, http.StatusCreated, w.Code)
	assert.Contains(t, w.Body.String(), "123")
	mockUploadService.AssertExpectations(t)
}

func TestBlobHandler_Upload_InvalidData_Error(t *testing.T) {
	mockBlobUploadService := new(MockBlobUploadService)
	mockBlobMetadataService := new(MockBlobMetadataService)
	mockBlobDownloadService := new(MockBlobDownloadService)
	mockCryptoKeyUploadService := new(MockCryptoKeyUploadService)

	handler := NewBlobHandler(mockBlobUploadService, mockBlobDownloadService, mockBlobMetadataService, mockCryptoKeyUploadService)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/upload", nil)

	c, _ := gin.CreateTestContext(w)
	c.Request = req

	handler.Upload(c)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "invalid form data")
}

func TestBlobHandler_ListMetadata_Success(t *testing.T) {
	mockUploadService := new(MockBlobUploadService)
	mockDownloadService := new(MockBlobDownloadService)
	mockMetadataService := new(MockBlobMetadataService)
	mockCryptoKeyUploadService := new(MockCryptoKeyUploadService)

	handler := NewBlobHandler(mockUploadService, mockDownloadService, mockMetadataService, mockCryptoKeyUploadService)

	blobMeta := blobs.BlobMeta{ID: "123"}

	mockMetadataService.On("List", mock.Anything, mock.Anything).Return([]*blobs.BlobMeta{&blobMeta}, nil)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/blobs", nil)

	c, _ := gin.CreateTestContext(w)
	c.Request = req

	handler.ListMetadata(c)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "123")
	mockMetadataService.AssertExpectations(t)
}

func TestBlobHandler_GetMetadataByID_Success(t *testing.T) {
	mockUploadService := new(MockBlobUploadService)
	mockDownloadService := new(MockBlobDownloadService)
	mockMetadataService := new(MockBlobMetadataService)
	mockCryptoKeyUploadService := new(MockCryptoKeyUploadService)

	handler := NewBlobHandler(mockUploadService, mockDownloadService, mockMetadataService, mockCryptoKeyUploadService)

	blobMeta := blobs.BlobMeta{ID: "123"}

	mockMetadataService.On("GetByID", mock.Anything, "123").Return(&blobMeta, nil)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/blobs/123", nil)

	c, _ := gin.CreateTestContext(w)
	c.Request = req
	c.Params = gin.Params{gin.Param{Key: "id", Value: "123"}}

	handler.GetMetadataByID(c)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "123")
	mockMetadataService.AssertExpectations(t)
}

func TestBlobHandler_GetMetadataByID_Error(t *testing.T) {
	mockUploadService := new(MockBlobUploadService)
	mockDownloadService := new(MockBlobDownloadService)
	mockMetadataService := new(MockBlobMetadataService)
	mockCryptoKeyUploadService := new(MockCryptoKeyUploadService)

	handler := NewBlobHandler(mockUploadService, mockDownloadService, mockMetadataService, mockCryptoKeyUploadService)

	mockMetadataService.On("GetByID", mock.Anything, "123").Return(&blobs.BlobMeta{}, errors.New("not found"))

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/blobs/123", nil)

	c, _ := gin.CreateTestContext(w)
	c.Request = req
	c.Params = gin.Params{gin.Param{Key: "id", Value: "123"}}

	handler.GetMetadataByID(c)

	assert.Equal(t, http.StatusNotFound, w.Code)
	assert.Contains(t, w.Body.String(), "not found")
	mockMetadataService.AssertExpectations(t)
}

func TestBlobHandler_DownloadByID_Success(t *testing.T) {
	mockUploadService := new(MockBlobUploadService)
	mockDownloadService := new(MockBlobDownloadService)
	mockMetadataService := new(MockBlobMetadataService)
	mockCryptoKeyUploadService := new(MockCryptoKeyUploadService)

	handler := NewBlobHandler(mockUploadService, mockDownloadService, mockMetadataService, mockCryptoKeyUploadService)

	blobID := "123"
	blobContent := []byte("file content")
	blobMeta := &blobs.BlobMeta{
		ID:   blobID,
		Name: "testfile.txt",
	}

	mockDownloadService.On("DownloadByID", mock.Anything, blobID, (*string)(nil)).Return(blobContent, nil)
	mockMetadataService.On("GetByID", mock.Anything, blobID).Return(blobMeta, nil)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/blobs/123/file", nil)

	c, _ := gin.CreateTestContext(w)
	c.Request = req
	c.Params = gin.Params{gin.Param{Key: "id", Value: blobID}}

	handler.DownloadByID(c)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "application/octet-stream; charset=utf-8", w.Header().Get("Content-Type"))
	assert.Equal(t, "attachment; filename="+blobMeta.Name, w.Header().Get("Content-Disposition"))
	assert.Equal(t, string(blobContent), w.Body.String())

	mockDownloadService.AssertExpectations(t)
	mockMetadataService.AssertExpectations(t)
}

func TestBlobHandler_DeleteByID_Success(t *testing.T) {
	mockUploadService := new(MockBlobUploadService)
	mockDownloadService := new(MockBlobDownloadService)
	mockMetadataService := new(MockBlobMetadataService)
	mockCryptoKeyUploadService := new(MockCryptoKeyUploadService)

	handler := NewBlobHandler(mockUploadService, mockDownloadService, mockMetadataService, mockCryptoKeyUploadService)

	mockMetadataService.On("DeleteByID", mock.Anything, "123").Return(nil)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("DELETE", "/blobs/123", nil)

	c, _ := gin.CreateTestContext(w)
	c.Request = req
	c.Params = gin.Params{gin.Param{Key: "id", Value: "123"}}

	handler.DeleteByID(c)

	assert.Equal(t, http.StatusNoContent, w.Code)
	mockMetadataService.AssertExpectations(t)
}

func TestBlobHandler_ListMetadata_ValidationError(t *testing.T) {
	mockUploadService := new(MockBlobUploadService)
	mockDownloadService := new(MockBlobDownloadService)
	mockMetadataService := new(MockBlobMetadataService)
	mockCryptoKeyUploadService := new(MockCryptoKeyUploadService)

	handler := NewBlobHandler(mockUploadService, mockDownloadService, mockMetadataService, mockCryptoKeyUploadService)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/blobs?sortOrder=invalid", nil)

	c, _ := gin.CreateTestContext(w)
	c.Request = req

	handler.ListMetadata(c)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestBlobHandler_DownloadByID_DownloadError(t *testing.T) {
	mockUploadService := new(MockBlobUploadService)
	mockDownloadService := new(MockBlobDownloadService)
	mockMetadataService := new(MockBlobMetadataService)
	mockCryptoKeyUploadService := new(MockCryptoKeyUploadService)

	handler := NewBlobHandler(mockUploadService, mockDownloadService, mockMetadataService, mockCryptoKeyUploadService)

	mockDownloadService.On("DownloadByID", mock.Anything, "123", (*string)(nil)).
		Return(nil, errors.New("download failed"))

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/blobs/123/file", nil)

	c, _ := gin.CreateTestContext(w)
	c.Request = req
	c.Params = gin.Params{gin.Param{Key: "id", Value: "123"}}

	handler.DownloadByID(c)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	mockDownloadService.AssertExpectations(t)
}

func TestBlobHandler_DeleteByID_Error(t *testing.T) {
	mockUploadService := new(MockBlobUploadService)
	mockDownloadService := new(MockBlobDownloadService)
	mockMetadataService := new(MockBlobMetadataService)
	mockCryptoKeyUploadService := new(MockCryptoKeyUploadService)

	handler := NewBlobHandler(mockUploadService, mockDownloadService, mockMetadataService, mockCryptoKeyUploadService)

	mockMetadataService.On("DeleteByID", mock.Anything, "123").Return(errors.New("delete failed"))

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("DELETE", "/blobs/123", nil)

	c, _ := gin.CreateTestContext(w)
	c.Request = req
	c.Params = gin.Params{gin.Param{Key: "id", Value: "123"}}

	handler.DeleteByID(c)

	assert.Equal(t, http.StatusNotFound, w.Code)
	mockMetadataService.AssertExpectations(t)
}
