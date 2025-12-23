package blobs

import (
	"context"
	"mime/multipart"
)

// BlobUploadService defines methods for uploading blobs.
type BlobUploadService interface {
	// Upload transfers blobs with the option to encrypt them using an encryption key or sign them with a signing key.
	// It returns a slice of Blob for the uploaded blobs and any error encountered during the upload process.
	Upload(ctx context.Context, form *multipart.Form, userID string, encryptionKeyID, signKeyID *string) ([]*BlobMeta, error)
}

// BlobMetadataService defines methods for retrieving Blob and deleting a blob along with its metadata.
type BlobMetadataService interface {
	// List retrieves all blobs' metadata considering a query filter when set.
	// It returns a slice of Blob and any error encountered during the retrieval.
	List(ctx context.Context, query *BlobMetaQuery) ([]*BlobMeta, error)

	// GetByID retrieves the metadata of a blob by its unique ID.
	// It returns the Blob and any error encountered during the retrieval process.
	GetByID(ctx context.Context, blobID string) (*BlobMeta, error)

	// DeleteByID deletes a blob and its associated metadata by ID.
	// It returns any error encountered during the deletion process.
	DeleteByID(ctx context.Context, blobID string) error
}

// BlobDownloadService defines methods for downloading blobs.
type BlobDownloadService interface {
	// The download function retrieves a blob's content using its ID and also enables data decryption.
	DownloadByID(ctx context.Context, blobID string, decryptionKeyID *string) ([]byte, error)
}

// BlobRepository defines the interface for Blob-related operations
type BlobRepository interface {
	Create(ctx context.Context, blob *BlobMeta) error
	List(ctx context.Context, query *BlobMetaQuery) ([]*BlobMeta, error)
	GetByID(ctx context.Context, blobID string) (*BlobMeta, error)
	UpdateByID(ctx context.Context, blob *BlobMeta) error
	DeleteByID(ctx context.Context, blobID string) error
}

// BlobConnector is an interface for interacting with Blob storage
type BlobConnector interface {
	// UploadFromForm uploads files to a Blob Storage
	// and returns the metadata for each uploaded byte stream.
	Upload(ctx context.Context, form *multipart.Form, userID string, encryptionKeyID, signKeyID *string) ([]*BlobMeta, error)

	// Download retrieves a blob's content by its ID and name, and returns the data as a stream.
	Download(ctx context.Context, blobID, blobName string) ([]byte, error)

	// Delete deletes a blob from Blob Storage by its ID and Name, and returns any error encountered.
	Delete(ctx context.Context, blobID, blobName string) error
}
