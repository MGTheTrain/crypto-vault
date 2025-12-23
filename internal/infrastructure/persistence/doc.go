// Package repository provides the implementation of the BlobRepository and CryptoKeyRepository interfaces.
// It uses GORM as the ORM layer to interact with a database, handling CRUD operations for both blob and
// cryptographic key metadata. The package includes functions to create, retrieve, update and delete metadata
// for blobs and cryptographic keys, with built-in validation and logging for better traceability and error handling.
package persistence
