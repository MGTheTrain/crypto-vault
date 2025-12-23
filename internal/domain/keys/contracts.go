package keys

import (
	"context"
)

// CryptoKeyUploadService defines methods for uploading cryptographic keys.
type CryptoKeyUploadService interface {
	// Upload uploads cryptographic keys
	// It returns a slice of CryptoKeyMeta and any error encountered during the upload process.
	Upload(ctx context.Context, userID, keyAlgorihm string, keySize uint32) ([]*CryptoKeyMeta, error)
}

// CryptoKeyMetadataService defines methods for managing cryptographic key metadata and deleting keys.
type CryptoKeyMetadataService interface {
	// List retrieves all cryptographic keys metadata considering a query filter when set.
	// It returns a slice of CryptoKeyMeta and any error encountered during the retrieval process.
	List(ctx context.Context, query *CryptoKeyQuery) ([]*CryptoKeyMeta, error)

	// GetByID retrieves the metadata of a cryptographic key by its unique ID.
	// It returns the CryptoKeyMeta and any error encountered during the retrieval process.
	GetByID(ctx context.Context, keyID string) (*CryptoKeyMeta, error)

	// DeleteByID deletes a cryptographic key and its associated metadata by ID.
	// It returns any error encountered during the deletion process.
	DeleteByID(ctx context.Context, keyID string) error
}

// CryptoKeyDownloadService defines methods for downloading cryptographic keys.
type CryptoKeyDownloadService interface {
	// Download retrieves a cryptographic key by its ID
	// It returns the CryptoKeyMeta, the key data as a byte slice, and any error encountered during the download process.
	DownloadByID(ctx context.Context, keyID string) ([]byte, error)
}

// CryptoKeyRepository defines the interface for CryptoKey-related operations
type CryptoKeyRepository interface {
	Create(ctx context.Context, key *CryptoKeyMeta) error
	List(ctx context.Context, query *CryptoKeyQuery) ([]*CryptoKeyMeta, error)
	GetByID(ctx context.Context, keyID string) (*CryptoKeyMeta, error)
	UpdateByID(ctx context.Context, key *CryptoKeyMeta) error
	DeleteByID(ctx context.Context, keyID string) error
}

// VaultConnector is an interface for interacting with custom key storage.
// The current implementation uses Azure Blob Storage, but this may be replaced
// with Azure Key Vault, AWS KMS, or any other cloud-based key management system in the future.
type VaultConnector interface {
	// Upload uploads bytes of a single file to Blob Storage
	// and returns the metadata for each uploaded byte stream.
	Upload(ctx context.Context, bytes []byte, userID, keyPairID, keyType, keyAlgorihm string, keySize uint32) (*CryptoKeyMeta, error)

	// Download retrieves a key's content by its IDs and type and returns the data as a byte slice.
	Download(ctx context.Context, keyID, keyPairID, keyType string) ([]byte, error)

	// Delete deletes a key from Vault Storage by its IDs and type and returns any error encountered.
	Delete(ctx context.Context, keyID, keyPairID, keyType string) error
}
