//go:build unit
// +build unit

package v1

import (
	"context"
	"crypto_vault_service/internal/domain/blobs"
	"crypto_vault_service/internal/domain/keys"
	"mime/multipart"

	"github.com/stretchr/testify/mock"
)

// MockBlobUploadService is a mock implementation of BlobUploadService
type MockBlobUploadService struct {
	mock.Mock
}

func (m *MockBlobUploadService) Upload(ctx context.Context, form *multipart.Form, userID string, encryptionKeyID, signKeyID *string) ([]*blobs.BlobMeta, error) {
	args := m.Called(ctx, form, userID, encryptionKeyID, signKeyID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*blobs.BlobMeta), args.Error(1)
}

// MockBlobMetadataService is a mock implementation of BlobMetadataService
type MockBlobMetadataService struct {
	mock.Mock
}

func (m *MockBlobMetadataService) List(ctx context.Context, query *blobs.BlobMetaQuery) ([]*blobs.BlobMeta, error) {
	args := m.Called(ctx, query)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*blobs.BlobMeta), args.Error(1)
}

func (m *MockBlobMetadataService) GetByID(ctx context.Context, blobID string) (*blobs.BlobMeta, error) {
	args := m.Called(ctx, blobID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*blobs.BlobMeta), args.Error(1)
}

func (m *MockBlobMetadataService) DeleteByID(ctx context.Context, blobID string) error {
	args := m.Called(ctx, blobID)
	return args.Error(0)
}

// MockBlobDownloadService is a mock implementation of BlobDownloadService
type MockBlobDownloadService struct {
	mock.Mock
}

func (m *MockBlobDownloadService) DownloadByID(ctx context.Context, blobID string, decryptionKeyID *string) ([]byte, error) {
	args := m.Called(ctx, blobID, decryptionKeyID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]byte), args.Error(1)
}

// MockCryptoKeyUploadService is a mock implementation of CryptoKeyUploadService
type MockCryptoKeyUploadService struct {
	mock.Mock
}

func (m *MockCryptoKeyUploadService) Upload(ctx context.Context, userID, keyAlgorithm string, keySize uint32) ([]*keys.CryptoKeyMeta, error) {
	args := m.Called(ctx, userID, keyAlgorithm, keySize)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*keys.CryptoKeyMeta), args.Error(1)
}

// MockCryptoKeyMetadataService is a mock implementation of CryptoKeyMetadataService
type MockCryptoKeyMetadataService struct {
	mock.Mock
}

func (m *MockCryptoKeyMetadataService) List(ctx context.Context, query *keys.CryptoKeyQuery) ([]*keys.CryptoKeyMeta, error) {
	args := m.Called(ctx, query)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*keys.CryptoKeyMeta), args.Error(1)
}

func (m *MockCryptoKeyMetadataService) GetByID(ctx context.Context, keyID string) (*keys.CryptoKeyMeta, error) {
	args := m.Called(ctx, keyID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*keys.CryptoKeyMeta), args.Error(1)
}

func (m *MockCryptoKeyMetadataService) DeleteByID(ctx context.Context, keyID string) error {
	args := m.Called(ctx, keyID)
	return args.Error(0)
}

// MockCryptoKeyDownloadService is a mock implementation of CryptoKeyDownloadService
type MockCryptoKeyDownloadService struct {
	mock.Mock
}

func (m *MockCryptoKeyDownloadService) DownloadByID(ctx context.Context, keyID string) ([]byte, error) {
	args := m.Called(ctx, keyID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]byte), args.Error(1)
}
