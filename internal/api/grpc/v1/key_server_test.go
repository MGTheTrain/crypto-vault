//go:build unit
// +build unit

package v1

import (
	"context"
	"crypto_vault_service/internal/domain/keys"
	"errors"
	"testing"
	"time"

	pb "proto"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestCryptoKeyMetadataServer_GetMetadataByID_Success(t *testing.T) {
	mockService := new(MockCryptoKeyMetadataService)
	server, _ := NewCryptoKeyMetadataServer(mockService)

	keyMeta := &keys.CryptoKeyMeta{
		ID:              "key-123",
		KeyPairID:       "pair-456",
		UserID:          "user-1",
		Algorithm:       "RSA",
		KeySize:         2048,
		Type:            "private",
		DateTimeCreated: time.Now(),
	}

	mockService.On("GetByID", mock.Anything, "key-123").Return(keyMeta, nil)

	req := &pb.IdRequest{Id: "key-123"}
	resp, err := server.GetMetadataByID(context.Background(), req)

	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, "key-123", resp.Id)
	assert.Equal(t, "pair-456", resp.KeyPairId)
	assert.Equal(t, "RSA", resp.Algorithm)
	assert.Equal(t, uint32(2048), resp.KeySize)
	assert.Equal(t, "private", resp.Type)
	mockService.AssertExpectations(t)
}

func TestCryptoKeyMetadataServer_GetMetadataByID_Error(t *testing.T) {
	mockService := new(MockCryptoKeyMetadataService)
	server, _ := NewCryptoKeyMetadataServer(mockService)

	mockService.On("GetByID", mock.Anything, "key-123").
		Return(nil, errors.New("not found"))

	req := &pb.IdRequest{Id: "key-123"}
	resp, err := server.GetMetadataByID(context.Background(), req)

	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "failed to get crypto key metadata by ID")
	mockService.AssertExpectations(t)
}

func TestCryptoKeyMetadataServer_DeleteByID_Success(t *testing.T) {
	mockService := new(MockCryptoKeyMetadataService)
	server, _ := NewCryptoKeyMetadataServer(mockService)

	mockService.On("DeleteByID", mock.Anything, "key-123").Return(nil)

	req := &pb.IdRequest{Id: "key-123"}
	resp, err := server.DeleteByID(context.Background(), req)

	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Contains(t, resp.Message, "key-123")
	assert.Contains(t, resp.Message, "deleted successfully")
	mockService.AssertExpectations(t)
}

func TestCryptoKeyMetadataServer_DeleteByID_Error(t *testing.T) {
	mockService := new(MockCryptoKeyMetadataService)
	server, _ := NewCryptoKeyMetadataServer(mockService)

	mockService.On("DeleteByID", mock.Anything, "key-123").
		Return(errors.New("delete failed"))

	req := &pb.IdRequest{Id: "key-123"}
	resp, err := server.DeleteByID(context.Background(), req)

	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "failed to delete crypto key")
	mockService.AssertExpectations(t)
}
