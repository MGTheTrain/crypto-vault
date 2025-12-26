//go:build unit
// +build unit

package v1

import (
	"context"

	"github.com/MGTheTrain/crypto-vault/internal/domain/blobs"
	"github.com/MGTheTrain/crypto-vault/internal/domain/keys"

	"github.com/stretchr/testify/mock"
)

// MockBlobMetadataService is a mock implementation of BlobMetadataService
type MockBlobMetadataService struct {
	mock.Mock
}

func (m *MockBlobMetadataService) GetByID(ctx context.Context, blobID string) (*blobs.BlobMeta, error) {
	args := m.Called(ctx, blobID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*blobs.BlobMeta), args.Error(1)
}

func (m *MockBlobMetadataService) List(ctx context.Context, query *blobs.BlobMetaQuery) ([]*blobs.BlobMeta, error) {
	args := m.Called(ctx, query)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*blobs.BlobMeta), args.Error(1)
}

func (m *MockBlobMetadataService) DeleteByID(ctx context.Context, blobID string) error {
	args := m.Called(ctx, blobID)
	return args.Error(0)
}

// MockCryptoKeyMetadataService is a mock implementation of CryptoKeyMetadataService
type MockCryptoKeyMetadataService struct {
	mock.Mock
}

func (m *MockCryptoKeyMetadataService) GetByID(ctx context.Context, keyID string) (*keys.CryptoKeyMeta, error) {
	args := m.Called(ctx, keyID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*keys.CryptoKeyMeta), args.Error(1)
}

func (m *MockCryptoKeyMetadataService) List(ctx context.Context, query *keys.CryptoKeyQuery) ([]*keys.CryptoKeyMeta, error) {
	args := m.Called(ctx, query)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*keys.CryptoKeyMeta), args.Error(1)
}

func (m *MockCryptoKeyMetadataService) DeleteByID(ctx context.Context, keyID string) error {
	args := m.Called(ctx, keyID)
	return args.Error(0)
}
