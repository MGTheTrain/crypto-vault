//go:build unit
// +build unit

package v1

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// TestSetupRoutes_RoutesRegistered verifies that routes are properly registered
func TestSetupRoutes_RoutesRegistered(t *testing.T) {
	mockBlobUploadService := new(MockBlobUploadService)
	mockBlobDownloadService := new(MockBlobDownloadService)
	mockBlobMetadataService := new(MockBlobMetadataService)
	mockCryptoKeyUploadService := new(MockCryptoKeyUploadService)
	mockCryptoKeyDownloadService := new(MockCryptoKeyDownloadService)
	mockCryptoKeyMetadataService := new(MockCryptoKeyMetadataService)

	r := gin.Default()

	// Setup mocks to return nil
	mockBlobUploadService.On("Upload", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(nil, nil)
	mockBlobMetadataService.On("List", mock.Anything, mock.Anything).Return(nil, nil)
	mockBlobMetadataService.On("GetByID", mock.Anything, mock.Anything).Return(nil, nil)
	mockBlobMetadataService.On("DeleteByID", mock.Anything, mock.Anything).Return(nil)
	mockBlobDownloadService.On("DownloadByID", mock.Anything, mock.Anything, mock.Anything).Return(nil, nil)

	mockCryptoKeyUploadService.On("Upload", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(nil, nil)
	mockCryptoKeyMetadataService.On("List", mock.Anything, mock.Anything).Return(nil, nil)
	mockCryptoKeyMetadataService.On("GetByID", mock.Anything, mock.Anything).Return(nil, nil)
	mockCryptoKeyDownloadService.On("DownloadByID", mock.Anything, mock.Anything).Return(nil, nil)
	mockCryptoKeyMetadataService.On("DeleteByID", mock.Anything, mock.Anything).Return(nil)

	SetupRoutes(r, mockBlobUploadService, mockBlobDownloadService, mockBlobMetadataService, mockCryptoKeyUploadService, mockCryptoKeyDownloadService, mockCryptoKeyMetadataService)

	// Verify routes are registered by testing they respond (even with errors)
	tests := []struct {
		method string
		url    string
	}{
		{"POST", "/api/v1/cvs/blobs"},
		{"POST", "/api/v1/cvs/keys"},
	}

	for _, tt := range tests {
		t.Run(tt.method+" "+tt.url, func(t *testing.T) {
			req, _ := http.NewRequest(tt.method, tt.url, nil)
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)

			// Just verify route exists (status != 404)
			assert.NotEqual(t, http.StatusNotFound, w.Code, "Route should be registered")
		})
	}
}
