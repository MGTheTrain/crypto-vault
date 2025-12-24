package v1

import (
	"crypto_vault_service/internal/pkg/validators"
	"errors"
	"fmt"
	"time"

	"github.com/go-playground/validator/v10"
)

// UploadKeyRequest represents the request structure for uploading a cryptographic key
type UploadKeyRequest struct {
	Algorithm string `json:"algorithm" validate:"omitempty,oneof=AES RSA ECDSA"`
	KeySize   uint32 `json:"key_size" validate:"omitempty,keySizeValidation"`
}

// Validate method for UploadKeyRequest struct
func (k *UploadKeyRequest) Validate() error {
	validate := validator.New()

	if err := validate.RegisterValidation("keySizeValidation", validators.KeySizeValidation); err != nil {
		return fmt.Errorf("failed to register custom validator: %w", err)
	}

	err := validate.Struct(k)
	if err != nil {
		var validationErrors validator.ValidationErrors
		if errors.As(err, &validationErrors) {
			var messages []string
			for _, fieldErr := range validationErrors {
				messages = append(messages, fmt.Sprintf("Field: %s, Tag: %s", fieldErr.Field(), fieldErr.Tag()))
			}
			return fmt.Errorf("validation failed: %v", messages)
		}
		return fmt.Errorf("validation error: %w", err)
	}

	return nil
}

// ErrorResponse represents an error response with a message.
type ErrorResponse struct {
	Message string `json:"message"` // The error message
}

// InfoResponse represents an informational response with a message.
type InfoResponse struct {
	Message string `json:"message"` // The informational message
}

// BlobMetaResponse contains metadata about a blob, such as ID, size, and encryption details.
type BlobMetaResponse struct {
	ID              string    `json:"id"`              // Unique identifier for the blob
	DateTimeCreated time.Time `json:"dateTimeCreated"` // Timestamp when the blob was created
	UserID          string    `json:"userID"`          // User who uploaded the blob
	Name            string    `json:"name"`            // Name of the blob
	Size            int64     `json:"size"`            // Size of the blob in bytes
	Type            string    `json:"type"`            // Type of the blob (e.g., file format)
	EncryptionKeyID *string   `json:"encryptionKeyID"` // Optional encryption key ID for the blob
	SignKeyID       *string   `json:"signKeyID"`       // Optional signature key ID for the blob
}

// CryptoKeyMetaResponse contains metadata about a cryptographic key.
type CryptoKeyMetaResponse struct {
	ID              string    `json:"id"`              // Unique identifier for the cryptographic key
	KeyPairID       string    `json:"keyPairID"`       // Identifier for the key pair the key belongs to
	Algorithm       string    `json:"algorithm"`       // Cryptographic algorithm (e.g., AES, RSA, EC)
	KeySize         uint32    `json:"keySize"`         // Size of the cryptographic key
	Type            string    `json:"type"`            // Type of the cryptographic key (e.g., public, private)
	DateTimeCreated time.Time `json:"dateTimeCreated"` // Timestamp when the key was created
	UserID          string    `json:"userID"`          // User who created the key
}
