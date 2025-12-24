//go:build unit
// +build unit

package v1

import (
	"context"
	"crypto_vault_service/internal/domain/blobs"
	"errors"
	"testing"

	pb "proto"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestBlobMetadataServer_GetMetadataByID_Success(t *testing.T) {
	mockService := new(MockBlobMetadataService)
	server, _ := NewBlobMetadataServer(mockService)

	encryptionKeyID := "enc-key-123"
	signKeyID := "sign-key-456"

	blobMeta := &blobs.BlobMeta{
		ID:              "blob-123",
		UserID:          "user-1",
		Name:            "test.txt",
		Size:            1024,
		Type:            "text/plain",
		EncryptionKeyID: &encryptionKeyID,
		SignKeyID:       &signKeyID,
	}

	mockService.On("GetByID", mock.Anything, "blob-123").Return(blobMeta, nil)

	req := &pb.IdRequest{Id: "blob-123"}
	resp, err := server.GetMetadataByID(context.Background(), req)

	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, "blob-123", resp.Id)
	assert.Equal(t, "test.txt", resp.Name)
	assert.Equal(t, encryptionKeyID, resp.EncryptionKeyId)
	assert.Equal(t, signKeyID, resp.SignKeyId)
	mockService.AssertExpectations(t)
}

func TestBlobMetadataServer_GetMetadataByID_Error(t *testing.T) {
	mockService := new(MockBlobMetadataService)
	server, _ := NewBlobMetadataServer(mockService)

	mockService.On("GetByID", mock.Anything, "blob-123").
		Return(nil, errors.New("not found"))

	req := &pb.IdRequest{Id: "blob-123"}
	resp, err := server.GetMetadataByID(context.Background(), req)

	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "failed to get metadata by ID")
	mockService.AssertExpectations(t)
}

func TestBlobMetadataServer_GetMetadataByID_NilPointers(t *testing.T) {
	mockService := new(MockBlobMetadataService)
	server, _ := NewBlobMetadataServer(mockService)

	blobMeta := &blobs.BlobMeta{
		ID:              "blob-123",
		UserID:          "user-1",
		Name:            "test.txt",
		Size:            1024,
		Type:            "text/plain",
		EncryptionKeyID: nil,
		SignKeyID:       nil,
	}

	mockService.On("GetByID", mock.Anything, "blob-123").Return(blobMeta, nil)

	req := &pb.IdRequest{Id: "blob-123"}
	resp, err := server.GetMetadataByID(context.Background(), req)

	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, "", resp.EncryptionKeyId)
	assert.Equal(t, "", resp.SignKeyId)
	mockService.AssertExpectations(t)
}

func TestBlobMetadataServer_DeleteByID_Success(t *testing.T) {
	mockService := new(MockBlobMetadataService)
	server, _ := NewBlobMetadataServer(mockService)

	mockService.On("DeleteByID", mock.Anything, "blob-123").Return(nil)

	req := &pb.IdRequest{Id: "blob-123"}
	resp, err := server.DeleteByID(context.Background(), req)

	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Contains(t, resp.Message, "blob-123")
	assert.Contains(t, resp.Message, "deleted successfully")
	mockService.AssertExpectations(t)
}

func TestBlobMetadataServer_DeleteByID_Error(t *testing.T) {
	mockService := new(MockBlobMetadataService)
	server, _ := NewBlobMetadataServer(mockService)

	mockService.On("DeleteByID", mock.Anything, "blob-123").
		Return(errors.New("delete failed"))

	req := &pb.IdRequest{Id: "blob-123"}
	resp, err := server.DeleteByID(context.Background(), req)

	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "failed to delete blob")
	mockService.AssertExpectations(t)
}
