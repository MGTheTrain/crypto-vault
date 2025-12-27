//go:build unit
// +build unit

package models

import (
	"testing"
	"time"

	"github.com/MGTheTrain/crypto-vault/internal/domain/blobs"
	"github.com/stretchr/testify/assert"
)

func TestBlobModel_ToDomain(t *testing.T) {
	// Setup a test BlobModel instance
	blobModel := &BlobModel{
		ID:                "test-id",
		DateTimeCreated:   time.Now(),
		UserID:            "user-id",
		Name:              "test-blob",
		Size:              1024,
		Type:              "application/octet-stream",
		EncryptionKeyID:   nil,
		SignKeyID:         nil,
		SignatureBlobID:   nil,
		SignatureFileName: nil,
	}

	// Convert to domain
	blobMeta := blobModel.ToDomain()

	// Assertions to ensure the conversion is correct
	assert.Equal(t, blobModel.ID, blobMeta.ID)
	assert.Equal(t, blobModel.DateTimeCreated, blobMeta.DateTimeCreated)
	assert.Equal(t, blobModel.UserID, blobMeta.UserID)
	assert.Equal(t, blobModel.Name, blobMeta.Name)
	assert.Equal(t, blobModel.Size, blobMeta.Size)
	assert.Equal(t, blobModel.Type, blobMeta.Type)
	assert.Nil(t, blobMeta.EncryptionKeyID)
	assert.Nil(t, blobMeta.SignKeyID)
	assert.Nil(t, blobMeta.SignatureBlobID)
	assert.Nil(t, blobMeta.SignatureFileName)
}

func TestBlobModel_FromDomain(t *testing.T) {
	// Setup a test BlobMeta instance (domain entity)
	blobMeta := &blobs.BlobMeta{
		ID:                "test-id",
		DateTimeCreated:   time.Now(),
		UserID:            "user-id",
		Name:              "test-blob",
		Size:              1024,
		Type:              "application/octet-stream",
		EncryptionKeyID:   nil,
		SignKeyID:         nil,
		SignatureBlobID:   nil,
		SignatureFileName: nil,
	}

	// Convert to BlobModel
	blobModel := &BlobModel{}
	blobModel.FromDomain(blobMeta)

	// Assertions to ensure the conversion is correct
	assert.Equal(t, blobMeta.ID, blobModel.ID)
	assert.Equal(t, blobMeta.DateTimeCreated, blobModel.DateTimeCreated)
	assert.Equal(t, blobMeta.UserID, blobModel.UserID)
	assert.Equal(t, blobMeta.Name, blobModel.Name)
	assert.Equal(t, blobMeta.Size, blobModel.Size)
	assert.Equal(t, blobMeta.Type, blobModel.Type)
	assert.Nil(t, blobModel.EncryptionKeyID)
	assert.Nil(t, blobModel.SignKeyID)
	assert.Nil(t, blobModel.SignatureBlobID)
	assert.Nil(t, blobModel.SignatureFileName)
}
