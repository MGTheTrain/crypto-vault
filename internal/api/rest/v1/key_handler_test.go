//go:build unit
// +build unit

package v1

import (
	"bytes"
	"crypto_vault_service/internal/domain/keys"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestKeyHandler_UploadKeys_Success(t *testing.T) {
	mockUploadService := new(MockCryptoKeyUploadService)
	mockDownloadService := new(MockCryptoKeyDownloadService)
	mockMetadataService := new(MockCryptoKeyMetadataService)

	handler := NewKeyHandler(mockUploadService, mockDownloadService, mockMetadataService)

	keyMeta := &keys.CryptoKeyMeta{
		ID:              "abc-123",
		KeyPairID:       "pair-123",
		Algorithm:       "RSA",
		KeySize:         2048,
		Type:            "private",
		DateTimeCreated: time.Now(),
		UserID:          "user-1",
	}

	requestBody := `{"algorithm": "RSA", "key_size": 2048}`

	mockUploadService.
		On("Upload", mock.Anything, mock.AnythingOfType("string"), "RSA", uint32(2048)).
		Return([]*keys.CryptoKeyMeta{keyMeta}, nil)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/keys", bytes.NewBufferString(requestBody))
	req.Header.Set("Content-Type", "application/json")

	c, _ := gin.CreateTestContext(w)
	c.Request = req

	handler.UploadKeys(c)

	assert.Equal(t, http.StatusCreated, w.Code)
	assert.Contains(t, w.Body.String(), "abc-123")
	mockUploadService.AssertExpectations(t)
}

func TestKeyHandler_ListMetadata_Success(t *testing.T) {
	mockUploadService := new(MockCryptoKeyUploadService)
	mockDownloadService := new(MockCryptoKeyDownloadService)
	mockMetadataService := new(MockCryptoKeyMetadataService)

	handler := NewKeyHandler(mockUploadService, mockDownloadService, mockMetadataService)

	keyMeta := &keys.CryptoKeyMeta{
		ID:              "abc-123",
		KeyPairID:       "pair-123",
		Algorithm:       "RSA",
		KeySize:         2048,
		Type:            "private",
		DateTimeCreated: time.Now(),
		UserID:          "user-1",
	}

	mockMetadataService.
		On("List", mock.Anything, mock.Anything).
		Return([]*keys.CryptoKeyMeta{keyMeta}, nil)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/keys", nil)

	c, _ := gin.CreateTestContext(w)
	c.Request = req

	handler.ListMetadata(c)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "abc-123")
	mockMetadataService.AssertExpectations(t)
}

func TestKeyHandler_GetMetadataByID_Success(t *testing.T) {
	mockUploadService := new(MockCryptoKeyUploadService)
	mockDownloadService := new(MockCryptoKeyDownloadService)
	mockMetadataService := new(MockCryptoKeyMetadataService)

	handler := NewKeyHandler(mockUploadService, mockDownloadService, mockMetadataService)

	keyMeta := &keys.CryptoKeyMeta{
		ID:              "abc-123",
		KeyPairID:       "pair-123",
		Algorithm:       "RSA",
		KeySize:         2048,
		Type:            "private",
		DateTimeCreated: time.Now(),
		UserID:          "user-1",
	}

	mockMetadataService.
		On("GetByID", mock.Anything, "abc-123").
		Return(keyMeta, nil)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/keys/abc-123", nil)

	c, _ := gin.CreateTestContext(w)
	c.Request = req
	c.Params = gin.Params{gin.Param{Key: "id", Value: "abc-123"}}

	handler.GetMetadataByID(c)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "abc-123")
	mockMetadataService.AssertExpectations(t)
}

func TestKeyHandler_DownloadByID_Success(t *testing.T) {
	mockUploadService := new(MockCryptoKeyUploadService)
	mockDownloadService := new(MockCryptoKeyDownloadService)
	mockMetadataService := new(MockCryptoKeyMetadataService)

	handler := NewKeyHandler(mockUploadService, mockDownloadService, mockMetadataService)

	keyID := "abc-123"
	keyContent := []byte("secret key content")

	mockDownloadService.
		On("DownloadByID", mock.Anything, keyID).
		Return(keyContent, nil)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/keys/abc-123/file", nil)

	c, _ := gin.CreateTestContext(w)
	c.Request = req
	c.Params = gin.Params{gin.Param{Key: "id", Value: keyID}}

	handler.DownloadByID(c)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "application/octet-stream; charset=utf-8", w.Header().Get("Content-Type"))
	assert.Equal(t, "attachment; filename="+keyID, w.Header().Get("Content-Disposition"))
	assert.Equal(t, string(keyContent), w.Body.String())

	mockDownloadService.AssertExpectations(t)
}

func TestKeyHandler_DeleteByID_Success(t *testing.T) {
	mockUploadService := new(MockCryptoKeyUploadService)
	mockDownloadService := new(MockCryptoKeyDownloadService)
	mockMetadataService := new(MockCryptoKeyMetadataService)

	handler := NewKeyHandler(mockUploadService, mockDownloadService, mockMetadataService)

	keyID := "abc-123"

	mockMetadataService.
		On("DeleteByID", mock.Anything, keyID).
		Return(nil)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("DELETE", "/keys/abc-123", nil)

	c, _ := gin.CreateTestContext(w)
	c.Request = req
	c.Params = gin.Params{gin.Param{Key: "id", Value: keyID}}

	handler.DeleteByID(c)

	assert.Equal(t, http.StatusNoContent, w.Code)
	mockMetadataService.AssertExpectations(t)
}

func TestKeyHandler_ListMetadata_ValidationError(t *testing.T) {
	mockUploadService := new(MockCryptoKeyUploadService)
	mockDownloadService := new(MockCryptoKeyDownloadService)
	mockMetadataService := new(MockCryptoKeyMetadataService)

	handler := NewKeyHandler(mockUploadService, mockDownloadService, mockMetadataService)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/keys?sortOrder=invalid", nil)

	c, _ := gin.CreateTestContext(w)
	c.Request = req

	handler.ListMetadata(c)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestKeyHandler_GetMetadataByID_Error(t *testing.T) {
	mockUploadService := new(MockCryptoKeyUploadService)
	mockDownloadService := new(MockCryptoKeyDownloadService)
	mockMetadataService := new(MockCryptoKeyMetadataService)

	handler := NewKeyHandler(mockUploadService, mockDownloadService, mockMetadataService)

	mockMetadataService.On("GetByID", mock.Anything, "abc-123").
		Return(nil, errors.New("not found"))

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/keys/abc-123", nil)

	c, _ := gin.CreateTestContext(w)
	c.Request = req
	c.Params = gin.Params{gin.Param{Key: "id", Value: "abc-123"}}

	handler.GetMetadataByID(c)

	assert.Equal(t, http.StatusNotFound, w.Code)
	mockMetadataService.AssertExpectations(t)
}

func TestKeyHandler_DownloadByID_Error(t *testing.T) {
	mockUploadService := new(MockCryptoKeyUploadService)
	mockDownloadService := new(MockCryptoKeyDownloadService)
	mockMetadataService := new(MockCryptoKeyMetadataService)

	handler := NewKeyHandler(mockUploadService, mockDownloadService, mockMetadataService)

	mockDownloadService.On("DownloadByID", mock.Anything, "abc-123").
		Return(nil, errors.New("download failed"))

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/keys/abc-123/file", nil)

	c, _ := gin.CreateTestContext(w)
	c.Request = req
	c.Params = gin.Params{gin.Param{Key: "id", Value: "abc-123"}}

	handler.DownloadByID(c)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	mockDownloadService.AssertExpectations(t)
}

func TestKeyHandler_DeleteByID_Error(t *testing.T) {
	mockUploadService := new(MockCryptoKeyUploadService)
	mockDownloadService := new(MockCryptoKeyDownloadService)
	mockMetadataService := new(MockCryptoKeyMetadataService)

	handler := NewKeyHandler(mockUploadService, mockDownloadService, mockMetadataService)

	mockMetadataService.On("DeleteByID", mock.Anything, "abc-123").
		Return(errors.New("delete failed"))

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("DELETE", "/keys/abc-123", nil)

	c, _ := gin.CreateTestContext(w)
	c.Request = req
	c.Params = gin.Params{gin.Param{Key: "id", Value: "abc-123"}}

	handler.DeleteByID(c)

	assert.Equal(t, http.StatusNotFound, w.Code)
	mockMetadataService.AssertExpectations(t)
}
