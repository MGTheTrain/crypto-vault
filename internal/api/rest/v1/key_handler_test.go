//go:build unit
// +build unit

package v1

import (
	"bytes"
	"crypto_vault_service/internal/domain/blobs"
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

// TestKeyHandler_UploadKeys uses table-driven tests
func TestKeyHandler_UploadKeys(t *testing.T) {
	tests := []struct {
		name         string
		requestBody  string
		mockSetup    func(*MockCryptoKeyUploadService)
		wantStatus   int
		wantContains string
	}{
		{
			name:        "successful RSA key upload",
			requestBody: `{"algorithm": "RSA", "key_size": 2048}`,
			mockSetup: func(m *MockCryptoKeyUploadService) {
				keyMeta := &keys.CryptoKeyMeta{
					ID:              "rsa-key-123",
					KeyPairID:       "pair-123",
					Algorithm:       "RSA",
					KeySize:         2048,
					Type:            "private",
					DateTimeCreated: time.Now(),
					UserID:          "user-1",
				}
				m.On("Upload", mock.Anything, mock.AnythingOfType("string"), "RSA", uint32(2048)).
					Return([]*keys.CryptoKeyMeta{keyMeta}, nil)
			},
			wantStatus:   http.StatusCreated,
			wantContains: "rsa-key-123",
		},
		{
			name:        "successful AES key upload",
			requestBody: `{"algorithm": "AES", "key_size": 256}`,
			mockSetup: func(m *MockCryptoKeyUploadService) {
				keyMeta := &keys.CryptoKeyMeta{
					ID:              "aes-key-456",
					Algorithm:       "AES",
					KeySize:         256,
					Type:            "symmetric",
					DateTimeCreated: time.Now(),
					UserID:          "user-1",
				}
				m.On("Upload", mock.Anything, mock.AnythingOfType("string"), "AES", uint32(256)).
					Return([]*keys.CryptoKeyMeta{keyMeta}, nil)
			},
			wantStatus:   http.StatusCreated,
			wantContains: "aes-key-456",
		},
		{
			name:        "successful ECDSA key upload",
			requestBody: `{"algorithm": "ECDSA", "key_size": 256}`,
			mockSetup: func(m *MockCryptoKeyUploadService) {
				keyMeta := &keys.CryptoKeyMeta{
					ID:              "ecdsa-key-789",
					KeyPairID:       "pair-789",
					Algorithm:       "ECDSA",
					KeySize:         256,
					Type:            "private",
					DateTimeCreated: time.Now(),
					UserID:          "user-1",
				}
				m.On("Upload", mock.Anything, mock.AnythingOfType("string"), "ECDSA", uint32(256)).
					Return([]*keys.CryptoKeyMeta{keyMeta}, nil)
			},
			wantStatus:   http.StatusCreated,
			wantContains: "ecdsa-key-789",
		},
		// {
		// 	name:        "invalid request body",
		// 	requestBody: `{"invalid": "data"}`,
		// 	mockSetup:   func(m *MockCryptoKeyUploadService) {},
		// 	wantStatus:  http.StatusBadRequest,
		// },
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockUploadService := new(MockCryptoKeyUploadService)
			mockDownloadService := new(MockCryptoKeyDownloadService)
			mockMetadataService := new(MockCryptoKeyMetadataService)

			handler := NewKeyHandler(mockUploadService, mockDownloadService, mockMetadataService)

			tt.mockSetup(mockUploadService)

			w := httptest.NewRecorder()
			req, _ := http.NewRequest("POST", "/keys", bytes.NewBufferString(tt.requestBody))
			req.Header.Set("Content-Type", "application/json")

			c, _ := gin.CreateTestContext(w)
			c.Request = req

			handler.UploadKeys(c)

			assert.Equal(t, tt.wantStatus, w.Code)
			if tt.wantContains != "" {
				assert.Contains(t, w.Body.String(), tt.wantContains)
			}
			mockUploadService.AssertExpectations(t)
		})
	}
}

// TestKeyHandler_ListMetadata uses table-driven tests
func TestKeyHandler_ListMetadata(t *testing.T) {
	tests := []struct {
		name         string
		queryParams  string
		mockSetup    func(*MockCryptoKeyMetadataService)
		wantStatus   int
		wantContains string
	}{
		{
			name:        "successful list with results",
			queryParams: "",
			mockSetup: func(m *MockCryptoKeyMetadataService) {
				keyMeta := &keys.CryptoKeyMeta{
					ID:        "key-123",
					Algorithm: "RSA",
					KeySize:   2048,
				}
				m.On("List", mock.Anything, mock.Anything).
					Return([]*keys.CryptoKeyMeta{keyMeta}, nil)
			},
			wantStatus:   http.StatusOK,
			wantContains: "key-123",
		},
		{
			name:        "validation error - invalid sortOrder",
			queryParams: "?sortOrder=invalid",
			mockSetup:   func(m *MockCryptoKeyMetadataService) {},
			wantStatus:  http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockUploadService := new(MockCryptoKeyUploadService)
			mockDownloadService := new(MockCryptoKeyDownloadService)
			mockMetadataService := new(MockCryptoKeyMetadataService)

			handler := NewKeyHandler(mockUploadService, mockDownloadService, mockMetadataService)

			tt.mockSetup(mockMetadataService)

			w := httptest.NewRecorder()
			req, _ := http.NewRequest("GET", "/keys"+tt.queryParams, nil)

			c, _ := gin.CreateTestContext(w)
			c.Request = req

			handler.ListMetadata(c)

			assert.Equal(t, tt.wantStatus, w.Code)
			if tt.wantContains != "" {
				assert.Contains(t, w.Body.String(), tt.wantContains)
			}
			mockMetadataService.AssertExpectations(t)
		})
	}
}

// TestKeyHandler_GetMetadataByID uses table-driven tests
func TestKeyHandler_GetMetadataByID(t *testing.T) {
	tests := []struct {
		name         string
		keyID        string
		mockSetup    func(*MockCryptoKeyMetadataService)
		wantStatus   int
		wantContains string
	}{
		{
			name:  "successful retrieval",
			keyID: "key-123",
			mockSetup: func(m *MockCryptoKeyMetadataService) {
				keyMeta := &keys.CryptoKeyMeta{
					ID:        "key-123",
					Algorithm: "RSA",
					KeySize:   2048,
				}
				m.On("GetByID", mock.Anything, "key-123").
					Return(keyMeta, nil)
			},
			wantStatus:   http.StatusOK,
			wantContains: "key-123",
		},
		{
			name:  "key not found",
			keyID: "nonexistent",
			mockSetup: func(m *MockCryptoKeyMetadataService) {
				m.On("GetByID", mock.Anything, "nonexistent").
					Return(nil, errors.New("not found"))
			},
			wantStatus: http.StatusNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockUploadService := new(MockCryptoKeyUploadService)
			mockDownloadService := new(MockCryptoKeyDownloadService)
			mockMetadataService := new(MockCryptoKeyMetadataService)

			handler := NewKeyHandler(mockUploadService, mockDownloadService, mockMetadataService)

			tt.mockSetup(mockMetadataService)

			w := httptest.NewRecorder()
			req, _ := http.NewRequest("GET", "/keys/"+tt.keyID, nil)

			c, _ := gin.CreateTestContext(w)
			c.Request = req
			c.Params = gin.Params{gin.Param{Key: "id", Value: tt.keyID}}

			handler.GetMetadataByID(c)

			assert.Equal(t, tt.wantStatus, w.Code)
			if tt.wantContains != "" {
				assert.Contains(t, w.Body.String(), tt.wantContains)
			}
			mockMetadataService.AssertExpectations(t)
		})
	}
}

// TestKeyHandler_DownloadByID uses table-driven tests
func TestKeyHandler_DownloadByID(t *testing.T) {
	tests := []struct {
		name             string
		keyID            string
		mockSetup        func(*MockCryptoKeyDownloadService, *MockCryptoKeyMetadataService)
		wantStatus       int
		wantContentType  string
		wantDisposition  string
		wantBodyContains string
	}{
		{
			name:  "successful download of public key",
			keyID: "public-key-123",
			mockSetup: func(download *MockCryptoKeyDownloadService, metadata *MockCryptoKeyMetadataService) {
				pemContent := []byte("-----BEGIN PUBLIC KEY-----\nMIIBIjAN...\n-----END PUBLIC KEY-----")
				keyMeta := &keys.CryptoKeyMeta{
					ID:        "public-key-123",
					Type:      "public",
					Algorithm: "RSA",
					KeySize:   2048,
				}
				metadata.On("GetByID", mock.Anything, "public-key-123").
					Return(keyMeta, nil)
				download.On("DownloadByID", mock.Anything, "public-key-123").
					Return(pemContent, nil)
			},
			wantStatus:       http.StatusOK,
			wantContentType:  "application/x-pem-file",
			wantDisposition:  "attachment; filename=public-key-123-public-key.pem",
			wantBodyContains: "BEGIN PUBLIC KEY",
		},
		{
			name:  "successful download of symmetric key",
			keyID: "aes-key-456",
			mockSetup: func(download *MockCryptoKeyDownloadService, metadata *MockCryptoKeyMetadataService) {
				pemContent := []byte("-----BEGIN AES KEY-----\naGVsbG8=\n-----END AES KEY-----")
				keyMeta := &keys.CryptoKeyMeta{
					ID:        "aes-key-456",
					Type:      "symmetric",
					Algorithm: "AES",
					KeySize:   256,
				}
				metadata.On("GetByID", mock.Anything, "aes-key-456").
					Return(keyMeta, nil)
				download.On("DownloadByID", mock.Anything, "aes-key-456").
					Return(pemContent, nil)
			},
			wantStatus:       http.StatusOK,
			wantContentType:  "application/x-pem-file",
			wantDisposition:  "attachment; filename=aes-key-456-symmetrics-key.pem",
			wantBodyContains: "BEGIN AES KEY",
		},
		// {
		// 	name:  "attempt to download private key - forbidden",
		// 	keyID: "private-key-789",
		// 	mockSetup: func(download *MockCryptoKeyDownloadService, metadata *MockCryptoKeyMetadataService) {
		// 		keyMeta := &keys.CryptoKeyMeta{
		// 			ID:        "private-key-789",
		// 			Type:      "private",
		// 			Algorithm: "RSA",
		// 			KeySize:   2048,
		// 		}
		// 		metadata.On("GetByID", mock.Anything, "private-key-789").
		// 			Return(keyMeta, nil)
		// 		// Download should not be called for private keys
		// 	},
		// 	wantStatus:       http.StatusBadRequest,
		// 	wantBodyContains: "download forbidden for private keys",
		// },
		{
			name:  "key metadata not found",
			keyID: "nonexistent-key",
			mockSetup: func(download *MockCryptoKeyDownloadService, metadata *MockCryptoKeyMetadataService) {
				metadata.On("GetByID", mock.Anything, "nonexistent-key").
					Return(nil, errors.New("key not found"))
			},
			wantStatus: http.StatusNotFound,
		},
		{
			name:  "download service error",
			keyID: "error-key",
			mockSetup: func(download *MockCryptoKeyDownloadService, metadata *MockCryptoKeyMetadataService) {
				keyMeta := &keys.CryptoKeyMeta{
					ID:        "error-key",
					Type:      "public",
					Algorithm: "RSA",
					KeySize:   2048,
				}
				metadata.On("GetByID", mock.Anything, "error-key").
					Return(keyMeta, nil)
				download.On("DownloadByID", mock.Anything, "error-key").
					Return(nil, errors.New("download failed"))
			},
			wantStatus: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockUploadService := new(MockCryptoKeyUploadService)
			mockDownloadService := new(MockCryptoKeyDownloadService)
			mockMetadataService := new(MockCryptoKeyMetadataService)

			handler := NewKeyHandler(mockUploadService, mockDownloadService, mockMetadataService)

			tt.mockSetup(mockDownloadService, mockMetadataService)

			w := httptest.NewRecorder()
			req, _ := http.NewRequest("GET", "/keys/"+tt.keyID+"/file", nil)

			c, _ := gin.CreateTestContext(w)
			c.Request = req
			c.Params = gin.Params{gin.Param{Key: "id", Value: tt.keyID}}

			handler.DownloadByID(c)

			assert.Equal(t, tt.wantStatus, w.Code)
			if tt.wantContentType != "" {
				assert.Equal(t, tt.wantContentType, w.Header().Get("Content-Type"))
			}
			if tt.wantDisposition != "" {
				assert.Equal(t, tt.wantDisposition, w.Header().Get("Content-Disposition"))
			}
			if tt.wantBodyContains != "" {
				assert.Contains(t, w.Body.String(), tt.wantBodyContains)
			}

			mockDownloadService.AssertExpectations(t)
			mockMetadataService.AssertExpectations(t)
		})
	}
}

// TestBlobHandler_DownloadSignatureByID uses table-driven tests
func TestBlobHandler_DownloadSignatureByID(t *testing.T) {
	tests := []struct {
		name             string
		blobID           string
		mockSetup        func(*MockBlobMetadataService, *MockBlobDownloadService)
		wantStatus       int
		wantContentType  string
		wantDisposition  string
		wantBodyContains string
	}{
		{
			name:   "successful signature download",
			blobID: "blob-with-sig-123",
			mockSetup: func(metadata *MockBlobMetadataService, download *MockBlobDownloadService) {
				signatureBlobID := "sig-blob-456"
				signatureFileName := "document.pdf.sig"
				blobMeta := &blobs.BlobMeta{
					ID:                "blob-with-sig-123",
					Name:              "document.pdf",
					SignatureBlobID:   &signatureBlobID,
					SignatureFileName: &signatureFileName,
				}
				signatureContent := []byte("signature binary data")

				metadata.On("GetByID", mock.Anything, "blob-with-sig-123").
					Return(blobMeta, nil)
				download.On("DownloadByID", mock.Anything, signatureBlobID, (*string)(nil)).
					Return(signatureContent, nil)
			},
			wantStatus:       http.StatusOK,
			wantContentType:  "application/octet-stream",
			wantDisposition:  "attachment; filename=document.pdf.sig",
			wantBodyContains: "signature binary data",
		},
		{
			name:   "successful signature download with default filename",
			blobID: "blob-sig-no-name",
			mockSetup: func(metadata *MockBlobMetadataService, download *MockBlobDownloadService) {
				signatureBlobID := "sig-blob-789"
				blobMeta := &blobs.BlobMeta{
					ID:                "blob-sig-no-name",
					Name:              "file.txt",
					SignatureBlobID:   &signatureBlobID,
					SignatureFileName: nil, // No signature filename
				}
				signatureContent := []byte("sig data")

				metadata.On("GetByID", mock.Anything, "blob-sig-no-name").
					Return(blobMeta, nil)
				download.On("DownloadByID", mock.Anything, signatureBlobID, (*string)(nil)).
					Return(signatureContent, nil)
			},
			wantStatus:       http.StatusOK,
			wantContentType:  "application/octet-stream",
			wantDisposition:  "attachment; filename=signature.sig",
			wantBodyContains: "sig data",
		},
		{
			name:   "blob not found",
			blobID: "nonexistent-blob",
			mockSetup: func(metadata *MockBlobMetadataService, download *MockBlobDownloadService) {
				metadata.On("GetByID", mock.Anything, "nonexistent-blob").
					Return(nil, errors.New("blob not found"))
			},
			wantStatus:       http.StatusNotFound,
			wantBodyContains: "blob with id nonexistent-blob not found",
		},
		{
			name:   "blob has no signature",
			blobID: "blob-no-sig",
			mockSetup: func(metadata *MockBlobMetadataService, download *MockBlobDownloadService) {
				blobMeta := &blobs.BlobMeta{
					ID:                "blob-no-sig",
					Name:              "unsigned.txt",
					SignatureBlobID:   nil, // No signature
					SignatureFileName: nil,
				}

				metadata.On("GetByID", mock.Anything, "blob-no-sig").
					Return(blobMeta, nil)
			},
			wantStatus:       http.StatusNotFound,
			wantBodyContains: "no signature found for blob blob-no-sig",
		},
		{
			name:   "signature download fails",
			blobID: "blob-sig-error",
			mockSetup: func(metadata *MockBlobMetadataService, download *MockBlobDownloadService) {
				signatureBlobID := "sig-blob-error"
				signatureFileName := "error.sig"
				blobMeta := &blobs.BlobMeta{
					ID:                "blob-sig-error",
					Name:              "error.pdf",
					SignatureBlobID:   &signatureBlobID,
					SignatureFileName: &signatureFileName,
				}

				metadata.On("GetByID", mock.Anything, "blob-sig-error").
					Return(blobMeta, nil)
				download.On("DownloadByID", mock.Anything, signatureBlobID, (*string)(nil)).
					Return(nil, errors.New("storage error"))
			},
			wantStatus:       http.StatusBadRequest,
			wantBodyContains: "could not download signature",
		},
		{
			name:   "RSA signed blob signature download",
			blobID: "rsa-signed-blob",
			mockSetup: func(metadata *MockBlobMetadataService, download *MockBlobDownloadService) {
				signatureBlobID := "rsa-sig-blob"
				signatureFileName := "contract.pdf.sig"
				blobMeta := &blobs.BlobMeta{
					ID:                "rsa-signed-blob",
					Name:              "contract.pdf",
					SignatureBlobID:   &signatureBlobID,
					SignatureFileName: &signatureFileName,
				}
				// RSA signature is binary data
				rsaSignature := []byte{0x30, 0x82, 0x01, 0x0a, 0x02, 0x82, 0x01, 0x01} // Example RSA sig bytes

				metadata.On("GetByID", mock.Anything, "rsa-signed-blob").
					Return(blobMeta, nil)
				download.On("DownloadByID", mock.Anything, signatureBlobID, (*string)(nil)).
					Return(rsaSignature, nil)
			},
			wantStatus:      http.StatusOK,
			wantContentType: "application/octet-stream",
			wantDisposition: "attachment; filename=contract.pdf.sig",
		},
		{
			name:   "ECDSA signed blob signature download",
			blobID: "ecdsa-signed-blob",
			mockSetup: func(metadata *MockBlobMetadataService, download *MockBlobDownloadService) {
				signatureBlobID := "ecdsa-sig-blob"
				signatureFileName := "image.png.sig"
				blobMeta := &blobs.BlobMeta{
					ID:                "ecdsa-signed-blob",
					Name:              "image.png",
					SignatureBlobID:   &signatureBlobID,
					SignatureFileName: &signatureFileName,
				}
				// ECDSA signature is binary data (r || s)
				ecdsaSignature := []byte{0x30, 0x44, 0x02, 0x20} // Example ECDSA sig bytes

				metadata.On("GetByID", mock.Anything, "ecdsa-signed-blob").
					Return(blobMeta, nil)
				download.On("DownloadByID", mock.Anything, signatureBlobID, (*string)(nil)).
					Return(ecdsaSignature, nil)
			},
			wantStatus:      http.StatusOK,
			wantContentType: "application/octet-stream",
			wantDisposition: "attachment; filename=image.png.sig",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockUploadService := new(MockBlobUploadService)
			mockDownloadService := new(MockBlobDownloadService)
			mockMetadataService := new(MockBlobMetadataService)
			mockCryptoKeyUploadService := new(MockCryptoKeyUploadService)

			handler := NewBlobHandler(mockUploadService, mockDownloadService, mockMetadataService, mockCryptoKeyUploadService)

			tt.mockSetup(mockMetadataService, mockDownloadService)

			w := httptest.NewRecorder()
			req, _ := http.NewRequest("GET", "/blobs/"+tt.blobID+"/signature", nil)

			c, _ := gin.CreateTestContext(w)
			c.Request = req
			c.Params = gin.Params{gin.Param{Key: "id", Value: tt.blobID}}

			handler.DownloadSignatureByID(c)

			assert.Equal(t, tt.wantStatus, w.Code)
			if tt.wantContentType != "" {
				assert.Equal(t, tt.wantContentType, w.Header().Get("Content-Type"))
			}
			if tt.wantDisposition != "" {
				assert.Equal(t, tt.wantDisposition, w.Header().Get("Content-Disposition"))
			}
			if tt.wantBodyContains != "" {
				assert.Contains(t, w.Body.String(), tt.wantBodyContains)
			}

			mockMetadataService.AssertExpectations(t)
			mockDownloadService.AssertExpectations(t)
		})
	}
}

// TestKeyHandler_DeleteByID uses table-driven tests
func TestKeyHandler_DeleteByID(t *testing.T) {
	tests := []struct {
		name       string
		keyID      string
		mockSetup  func(*MockCryptoKeyMetadataService)
		wantStatus int
	}{
		{
			name:  "successful deletion",
			keyID: "key-to-delete",
			mockSetup: func(m *MockCryptoKeyMetadataService) {
				m.On("DeleteByID", mock.Anything, "key-to-delete").
					Return(nil)
			},
			wantStatus: http.StatusNoContent,
		},
		{
			name:  "key not found",
			keyID: "nonexistent",
			mockSetup: func(m *MockCryptoKeyMetadataService) {
				m.On("DeleteByID", mock.Anything, "nonexistent").
					Return(errors.New("key not found"))
			},
			wantStatus: http.StatusNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockUploadService := new(MockCryptoKeyUploadService)
			mockDownloadService := new(MockCryptoKeyDownloadService)
			mockMetadataService := new(MockCryptoKeyMetadataService)

			handler := NewKeyHandler(mockUploadService, mockDownloadService, mockMetadataService)

			tt.mockSetup(mockMetadataService)

			w := httptest.NewRecorder()
			req, _ := http.NewRequest("DELETE", "/keys/"+tt.keyID, nil)

			c, _ := gin.CreateTestContext(w)
			c.Request = req
			c.Params = gin.Params{gin.Param{Key: "id", Value: tt.keyID}}

			handler.DeleteByID(c)

			assert.Equal(t, tt.wantStatus, w.Code)
			mockMetadataService.AssertExpectations(t)
		})
	}
}

// Backward compatibility tests (keep some original test structure for edge cases)
func TestKeyHandler_UploadKeys_InvalidJSON(t *testing.T) {
	mockUploadService := new(MockCryptoKeyUploadService)
	mockDownloadService := new(MockCryptoKeyDownloadService)
	mockMetadataService := new(MockCryptoKeyMetadataService)

	handler := NewKeyHandler(mockUploadService, mockDownloadService, mockMetadataService)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/keys", bytes.NewBufferString("invalid json"))
	req.Header.Set("Content-Type", "application/json")

	c, _ := gin.CreateTestContext(w)
	c.Request = req

	handler.UploadKeys(c)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}
