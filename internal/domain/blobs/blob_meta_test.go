//go:build unit
// +build unit

package blobs

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

// BlobValidationTests struct encapsulates the test data and methods for blob validation
type BlobValidationTests struct {
	// TestData can be used for holding the Blob and CryptoKey data
	validBlob    BlobMeta
	invalidBlob  BlobMeta
	invalidBlob2 BlobMeta
}

// NewBlobValidationTests is a constructor to create a new instance of BlobValidationTests
func NewBlobValidationTests() *BlobValidationTests {
	keyID := uuid.New().String()
	// Create valid and invalid test data
	validBlob := BlobMeta{
		ID:              uuid.New().String(),
		DateTimeCreated: time.Now(),
		UserID:          uuid.New().String(),
		Name:            "test_blobs.txt",
		Size:            12345,
		Type:            "text",
		EncryptionKeyID: &keyID,
		SignKeyID:       &keyID,
	}

	invalidBlob := BlobMeta{
		ID:              "", // Invalid empty ID
		DateTimeCreated: time.Now(),
		UserID:          "invalid-uuid", // Invalid UserID
		Name:            "test_blobs.txt",
		Size:            -12345, // Invalid Size (negative)
		Type:            "text",
		EncryptionKeyID: &keyID,
		SignKeyID:       &keyID,
	}

	invalidBlob2 := BlobMeta{
		ID:              uuid.New().String(),
		DateTimeCreated: time.Now(),
		UserID:          uuid.New().String(),
		Name:            "", // Invalid empty Name
		Size:            12345,
		Type:            "text",
		EncryptionKeyID: &keyID,
		SignKeyID:       &keyID,
	}

	return &BlobValidationTests{
		validBlob:    validBlob,
		invalidBlob:  invalidBlob,
		invalidBlob2: invalidBlob2,
	}
}

// TestBlobValidation tests the Validator method for Blob
func (bt *BlobValidationTests) TestBlobValidation(t *testing.T) {
	// Validate the valid Blob
	err := bt.validBlob.Validate()
	assert.Nil(t, err, "Expected no validation errors for valid Blob")

	// Validate the invalid Blob
	err = bt.invalidBlob.Validate()
	assert.NotNil(t, err, "Expected validation errors for invalid Blob")
	assert.Contains(t, err.Error(), "Field: ID, Tag: required")
	assert.Contains(t, err.Error(), "Field: Size, Tag: min")
	assert.Contains(t, err.Error(), "Field: UserID, Tag: uuid4")
}

// TestBlobValidationEdgeCases tests validation edge cases for Blob
func (bt *BlobValidationTests) TestBlobValidationEdgeCases(t *testing.T) {
	// Validate the invalid Blob with empty Name
	err := bt.invalidBlob2.Validate()
	assert.NotNil(t, err, "Expected validation error for missing Name")
	assert.Contains(t, err.Error(), "Field: Name, Tag: required")
}

// TestBlobValidation is the entry point to run the Blob validation tests
func TestBlobValidation(t *testing.T) {
	// Create a new BlobValidationTests instance
	bt := NewBlobValidationTests()

	// Run each test method
	t.Run("TestBlobValidation", bt.TestBlobValidation)
	t.Run("TestBlobValidationEdgeCases", bt.TestBlobValidationEdgeCases)
}
