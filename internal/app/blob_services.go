package app

import (
	"bytes"
	"context"
	crypto_ec "crypto/ecdsa"
	"crypto/elliptic"
	crypto_rsa "crypto/rsa"
	"crypto/x509"
	"crypto_vault_service/internal/domain/blobs"
	"crypto_vault_service/internal/domain/crypto"
	"crypto_vault_service/internal/domain/keys"

	"crypto_vault_service/internal/pkg/logger"
	"crypto_vault_service/internal/pkg/utils"
	"fmt"
	"io"
	"math/big"
	"mime/multipart"
)

// blobUploadService implements the BlobUploadService interface for handling blob uploads
type blobUploadService struct {
	blobConnector  blobs.BlobConnector
	blobRepository blobs.BlobRepository
	aesProcessor   crypto.AESProcessor
	ecdsaProcessor crypto.ECDSAProcessor
	rsaProcessor   crypto.RSAProcessor
	vaultConnector keys.VaultConnector
	cryptoKeyRepo  keys.CryptoKeyRepository
	logger         logger.Logger
}

// NewBlobUploadService creates a new instance of BlobUploadService
func NewBlobUploadService(
	blobConnector blobs.BlobConnector,
	blobRepository blobs.BlobRepository,
	vaultConnector keys.VaultConnector,
	cryptoKeyRepo keys.CryptoKeyRepository,
	aesProcessor crypto.AESProcessor,
	ecdsaProcessor crypto.ECDSAProcessor,
	rsaProcessor crypto.RSAProcessor,
	logger logger.Logger,
) (blobs.BlobUploadService, error) {
	return &blobUploadService{
		blobConnector:  blobConnector,
		blobRepository: blobRepository,
		cryptoKeyRepo:  cryptoKeyRepo,
		vaultConnector: vaultConnector,
		aesProcessor:   aesProcessor,
		ecdsaProcessor: ecdsaProcessor,
		rsaProcessor:   rsaProcessor,
		logger:         logger,
	}, nil
}

// Upload transfers blobs with the option to encrypt them using an encryption key or sign them with a signing key.
// It returns a slice of BlobMeta for the uploaded blobs and any error encountered during the upload process.
func (s *blobUploadService) Upload(ctx context.Context, form *multipart.Form, userID string, encryptionKeyID, signKeyID *string) ([]*blobs.BlobMeta, error) {
	if form == nil || len(form.File["files"]) == 0 {
		return nil, fmt.Errorf("no files provided in upload request")
	}

	uploadForm := form
	var signatureBlobMetas []*blobs.BlobMeta

	// Step 1: Process signing if signKeyID is provided
	if signKeyID != nil {
		keyBytes, cryptoKeyMeta, err := s.getCryptoKeyAndData(ctx, *signKeyID)
		if err != nil {
			return nil, fmt.Errorf("failed to get signing key: %w", err)
		}

		// Generate signatures for all files (raw binary data, like CLI does)
		signatures, originalFileNames, err := s.applyCryptographicOperation(
			form,
			cryptoKeyMeta.Algorithm,
			crypto.OperationSigning,
			keyBytes,
			cryptoKeyMeta.KeySize,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to generate signatures: %w", err)
		}

		// Create signature filenames with .sig extension
		// CLI: os.WriteFile(signatureFilePath, signature, 0600)
		// We do the same but with .sig extension
		signatureFileNames := make([]string, len(originalFileNames))
		for i, originalName := range originalFileNames {
			signatureFileNames[i] = originalName + ".sig"
		}

		// Create multipart form for signature files
		signatureForm, err := utils.CreateMultipleFilesForm(signatures, signatureFileNames)
		if err != nil {
			return nil, fmt.Errorf("failed to create signature form: %w", err)
		}

		// Upload signatures as separate blobs (without encryption/signing metadata)
		// Signatures are standalone files, just like CLI saves them separately
		signatureBlobMetas, err = s.blobConnector.Upload(ctx, signatureForm, userID, nil, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to upload signature blobs: %w", err)
		}

		// Persist signature blob metadata to database
		for i, signatureBlobMeta := range signatureBlobMetas {
			if err := s.blobRepository.Create(ctx, signatureBlobMeta); err != nil {
				return nil, fmt.Errorf("failed to save signature blob metadata for '%s': %w", signatureBlobMeta.Name, err)
			}

			s.logger.Info("signature blob persisted",
				"signature_blob_id", signatureBlobMeta.ID,
				"filename", signatureBlobMeta.Name,
				"size", signatureBlobMeta.Size,
				"algorithm", cryptoKeyMeta.Algorithm,
				"original_file", originalFileNames[i])
		}

		s.logger.Info("signatures uploaded",
			"count", len(signatureBlobMetas),
			"algorithm", cryptoKeyMeta.Algorithm,
			"sign_key_id", *signKeyID)
	}

	// Step 2: Process encryption if encryptionKeyID is provided
	if encryptionKeyID != nil {
		keyBytes, cryptoKeyMeta, err := s.getCryptoKeyAndData(ctx, *encryptionKeyID)
		if err != nil {
			return nil, fmt.Errorf("failed to get encryption key: %w", err)
		}

		// Encrypt the original files (not the signatures)
		encryptedContents, encryptedFileNames, err := s.applyCryptographicOperation(
			form,
			cryptoKeyMeta.Algorithm,
			crypto.OperationEncryption,
			keyBytes,
			cryptoKeyMeta.KeySize,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to encrypt files: %w", err)
		}

		// Create form with encrypted files
		uploadForm, err = utils.CreateMultipleFilesForm(encryptedContents, encryptedFileNames)
		if err != nil {
			return nil, fmt.Errorf("failed to create encrypted form: %w", err)
		}

		s.logger.Info("files encrypted",
			"count", len(encryptedContents),
			"algorithm", cryptoKeyMeta.Algorithm,
			"encryption_key_id", *encryptionKeyID)
	}

	// Step 3: Upload original files (or encrypted files if encryption was applied)
	blobMetas, err := s.blobConnector.Upload(ctx, uploadForm, userID, encryptionKeyID, signKeyID)
	if err != nil {
		return nil, fmt.Errorf("failed to upload blobs: %w", err)
	}

	// Step 4: Link signature blobs to original blobs and persist metadata
	for i, blobMeta := range blobMetas {
		// Link signature if one was generated for this file
		// This creates the association: original file <-> signature file
		if signKeyID != nil && i < len(signatureBlobMetas) {
			signatureBlobID := signatureBlobMetas[i].ID
			signatureFileName := signatureBlobMetas[i].Name
			blobMeta.SignatureBlobID = &signatureBlobID
			blobMeta.SignatureFileName = &signatureFileName

			s.logger.Info("linked signature to blob",
				"blob_id", blobMeta.ID,
				"blob_name", blobMeta.Name,
				"signature_blob_id", signatureBlobID,
				"signature_filename", signatureFileName)
		}

		// Persist blob metadata with signature reference
		if err := s.blobRepository.Create(ctx, blobMeta); err != nil {
			return nil, fmt.Errorf("failed to save blob metadata for '%s': %w", blobMeta.Name, err)
		}
	}

	s.logger.Info("blob upload completed",
		"blob_count", len(blobMetas),
		"encrypted", encryptionKeyID != nil,
		"signed", signKeyID != nil,
		"signature_count", len(signatureBlobMetas))

	return blobMetas, nil
}

// getCryptoKeyAndData retrieves the encryption or signing key along with metadata by ID.
// It downloads the key from the vault and returns the key bytes and associated metadata.
func (s *blobUploadService) getCryptoKeyAndData(ctx context.Context, cryptoKeyID string) ([]byte, *keys.CryptoKeyMeta, error) {
	// Get meta info
	cryptoKeyMeta, err := s.cryptoKeyRepo.GetByID(ctx, cryptoKeyID)
	if err != nil {
		return nil, nil, fmt.Errorf("%w", err)
	}

	// Download key
	keyBytes, err := s.vaultConnector.Download(ctx, cryptoKeyMeta.ID, cryptoKeyMeta.KeyPairID, cryptoKeyMeta.Type)
	if err != nil {
		return nil, nil, fmt.Errorf("%w", err)
	}

	return keyBytes, cryptoKeyMeta, nil
}

// applyCryptographicOperation performs cryptographic operations (encryption or signing)
// on files within a multipart form using the specified algorithm and key.
//
// Supported operations:
//   - AES: Encryption only (no signing support)
//   - RSA: Encryption and signing
//   - ECDSA: Signing only (no encryption support)
//
// Returns processed bytes and original filenames, or an error if the operation fails.
func (s *blobUploadService) applyCryptographicOperation(form *multipart.Form, algorithm, operation string, keyBytes []byte, keySize uint32) ([][]byte, []string, error) {
	var contents [][]byte
	var fileNames []string

	fileHeaders := form.File["files"]
	if len(fileHeaders) == 0 {
		return nil, nil, fmt.Errorf("no files provided in form")
	}

	for _, fileHeader := range fileHeaders {
		file, err := fileHeader.Open()
		if err != nil {
			return nil, nil, fmt.Errorf("failed to open file '%s': %w", fileHeader.Filename, err)
		}
		defer func() {
			if err := file.Close(); err != nil {
				s.logger.Error("failed to close file", "filename", fileHeader.Filename, "error", err)
			}
		}()

		buffer := bytes.NewBuffer(make([]byte, 0))
		_, err = io.Copy(buffer, file)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to read file '%s': %w", fileHeader.Filename, err)
		}
		data := buffer.Bytes()

		var processedBytes []byte

		switch algorithm {
		case crypto.AlgorithmAES:
			// AES only supports encryption, not signing
			switch operation {
			case crypto.OperationEncryption:
				processedBytes, err = s.aesProcessor.Encrypt(data, keyBytes)
				if err != nil {
					return nil, nil, fmt.Errorf("AES encryption failed for '%s': %w", fileHeader.Filename, err)
				}
			case crypto.OperationSigning:
				return nil, nil, fmt.Errorf("AES does not support signing operations; use RSA or ECDSA for digital signatures")
			default:
				return nil, nil, fmt.Errorf("unsupported operation '%s' for AES; only encryption is supported", operation)
			}

		case crypto.AlgorithmRSA:
			// RSA supports both encryption and signing
			switch operation {
			case crypto.OperationEncryption:
				// Unmarshal public key from PKIX format
				publicKeyInterface, err := x509.ParsePKIXPublicKey(keyBytes)
				if err != nil {
					return nil, nil, fmt.Errorf("failed to parse RSA public key: %w", err)
				}
				publicKey, ok := publicKeyInterface.(*crypto_rsa.PublicKey)
				if !ok {
					return nil, nil, fmt.Errorf("key is not an RSA public key")
				}

				processedBytes, err = s.rsaProcessor.Encrypt(data, publicKey)
				if err != nil {
					return nil, nil, fmt.Errorf("RSA encryption failed for '%s': %w", fileHeader.Filename, err)
				}

			case crypto.OperationSigning:
				// Unmarshal private key from PKCS#1 format
				privateKey, err := x509.ParsePKCS1PrivateKey(keyBytes)
				if err != nil {
					return nil, nil, fmt.Errorf("failed to parse RSA private key: %w", err)
				}

				processedBytes, err = s.rsaProcessor.Sign(data, privateKey)
				if err != nil {
					return nil, nil, fmt.Errorf("RSA signing failed for '%s': %w", fileHeader.Filename, err)
				}

			default:
				return nil, nil, fmt.Errorf("unsupported operation '%s' for RSA; use 'encryption' or 'signing'", operation)
			}

		case crypto.AlgorithmECDSA:
			// ECDSA only supports signing, not encryption
			switch operation {
			case crypto.OperationSigning:
				// Validate key bytes length for ECDSA
				if len(keyBytes) < 96 {
					return nil, nil, fmt.Errorf("ECDSA key bytes too short: expected at least 96 bytes, got %d", len(keyBytes))
				}

				// Reconstruct ECDSA private key from raw bytes (D, X, Y components)
				privateKeyD := new(big.Int).SetBytes(keyBytes[:32])
				pubKeyX := new(big.Int).SetBytes(keyBytes[32:64])
				pubKeyY := new(big.Int).SetBytes(keyBytes[64:96])

				var curve elliptic.Curve
				switch keySize {
				case 224:
					curve = elliptic.P224()
				case 256:
					curve = elliptic.P256()
				case 384:
					curve = elliptic.P384()
				case 521:
					curve = elliptic.P521()
				default:
					return nil, nil, fmt.Errorf("unsupported ECDSA key size: %d; use 224, 256, 384, or 521", keySize)
				}

				publicKey := &crypto_ec.PublicKey{
					Curve: curve,
					X:     pubKeyX,
					Y:     pubKeyY,
				}

				privateKey := &crypto_ec.PrivateKey{
					D:         privateKeyD,
					PublicKey: *publicKey,
				}

				processedBytes, err = s.ecdsaProcessor.Sign(data, privateKey)
				if err != nil {
					return nil, nil, fmt.Errorf("ECDSA signing failed for '%s': %w", fileHeader.Filename, err)
				}

			case crypto.OperationEncryption:
				return nil, nil, fmt.Errorf("ECDSA does not support encryption; use RSA for asymmetric encryption")

			default:
				return nil, nil, fmt.Errorf("unsupported operation '%s' for ECDSA; only signing is supported", operation)
			}

		default:
			return nil, nil, fmt.Errorf("unsupported algorithm '%s'; use AES, RSA, or ECDSA", algorithm)
		}

		// Ensure processed bytes were generated
		if len(processedBytes) == 0 {
			return nil, nil, fmt.Errorf("cryptographic operation produced empty result for '%s'", fileHeader.Filename)
		}

		contents = append(contents, processedBytes)
		fileNames = append(fileNames, fileHeader.Filename)
	}

	return contents, fileNames, nil
}

// blobMetadataService implements the BlobMetadataService interface for retrieving and deleting blob metadata
type blobMetadataService struct {
	blobConnector  blobs.BlobConnector
	blobRepository blobs.BlobRepository
	logger         logger.Logger
}

// NewBlobMetadataService creates a new instance of blobMetadataService
func NewBlobMetadataService(blobRepository blobs.BlobRepository, blobConnector blobs.BlobConnector, logger logger.Logger) (blobs.BlobMetadataService, error) {
	return &blobMetadataService{
		blobConnector:  blobConnector,
		blobRepository: blobRepository,
		logger:         logger,
	}, nil
}

// List retrieves all blobs' metadata considering a query filter
func (s *blobMetadataService) List(ctx context.Context, query *blobs.BlobMetaQuery) ([]*blobs.BlobMeta, error) {
	blobMetas, err := s.blobRepository.List(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("%w", err)
	}

	return blobMetas, nil
}

// GetByID retrieves a blob's metadata by ID
func (s *blobMetadataService) GetByID(ctx context.Context, blobID string) (*blobs.BlobMeta, error) {
	blobMeta, err := s.blobRepository.GetByID(ctx, blobID)
	if err != nil {
		return nil, fmt.Errorf("%w", err)
	}
	return blobMeta, nil
}

// DeleteByID deletes a blob and associated metadata by ID
func (s *blobMetadataService) DeleteByID(ctx context.Context, blobID string) error {

	blobMeta, err := s.blobRepository.GetByID(ctx, blobID)
	if err != nil {
		return fmt.Errorf("%w", err)
	}

	err = s.blobRepository.DeleteByID(ctx, blobID)
	if err != nil {
		return fmt.Errorf("%w", err)
	}

	err = s.blobConnector.Delete(ctx, blobMeta.ID, blobMeta.Name)
	if err != nil {
		return fmt.Errorf("%w", err)
	}

	return nil
}

// blobDownloadService implements the BlobDownloadService interface for downloading blobs
type blobDownloadService struct {
	blobConnector  blobs.BlobConnector
	blobRepository blobs.BlobRepository
	vaultConnector keys.VaultConnector
	cryptoKeyRepo  keys.CryptoKeyRepository
	aesProcessor   crypto.AESProcessor
	rsaProcessor   crypto.RSAProcessor
	logger         logger.Logger
}

// NewBlobDownloadService creates a new instance of BlobDownloadService
func NewBlobDownloadService(
	blobConnector blobs.BlobConnector,
	blobRepository blobs.BlobRepository,
	vaultConnector keys.VaultConnector,
	cryptoKeyRepo keys.CryptoKeyRepository,
	aesProcessor crypto.AESProcessor,
	rsaProcessor crypto.RSAProcessor,
	logger logger.Logger,
) (blobs.BlobDownloadService, error) {
	return &blobDownloadService{
		blobConnector:  blobConnector,
		blobRepository: blobRepository,
		cryptoKeyRepo:  cryptoKeyRepo,
		vaultConnector: vaultConnector,
		aesProcessor:   aesProcessor,
		rsaProcessor:   rsaProcessor,
		logger:         logger,
	}, nil
}

// The download function retrieves a blob's content using ID and also enables data decryption.
// NOTE: Signing should be performed locally by first downloading the associated key, followed by verification.
// Optionally, a verify endpoint will be available soon for optional use.
func (s *blobDownloadService) DownloadByID(ctx context.Context, blobID string, decryptionKeyID *string) ([]byte, error) {

	blobMeta, err := s.blobRepository.GetByID(ctx, blobID)
	if err != nil {
		return nil, fmt.Errorf("%w", err)
	}

	blobBytes, err := s.blobConnector.Download(ctx, blobID, blobMeta.Name)
	if err != nil {
		return nil, fmt.Errorf("%w", err)
	}

	if decryptionKeyID != nil {
		var processedBytes []byte
		keyBytes, cryptoKeyMeta, err := s.getCryptoKeyAndData(ctx, *decryptionKeyID)
		if err != nil {
			return nil, fmt.Errorf("%w", err)
		}

		switch cryptoKeyMeta.Algorithm {
		case crypto.AlgorithmAES:
			processedBytes, err = s.aesProcessor.Decrypt(blobBytes, keyBytes)
			if err != nil {
				return nil, fmt.Errorf("%w", err)
			}
		case crypto.AlgorithmRSA:
			privateKey, err := x509.ParsePKCS1PrivateKey(keyBytes)
			if err != nil {
				return nil, fmt.Errorf("error parsing private key: %w", err)
			}
			processedBytes, err = s.rsaProcessor.Decrypt(blobBytes, privateKey)
			if err != nil {
				return nil, fmt.Errorf("%w", err)
			}
		default:
			return nil, fmt.Errorf("unsupported algorithm: %s", cryptoKeyMeta.Algorithm)
		}
		return processedBytes, nil
	}
	return blobBytes, nil
}

// getCryptoKeyAndData retrieves the encryption or signing key along with metadata by ID.
// It downloads the key from the vault and returns the key bytes and associated metadata.
func (s *blobDownloadService) getCryptoKeyAndData(ctx context.Context, cryptoKeyID string) ([]byte, *keys.CryptoKeyMeta, error) {
	// Get meta info
	cryptoKeyMeta, err := s.cryptoKeyRepo.GetByID(ctx, cryptoKeyID)
	if err != nil {
		return nil, nil, fmt.Errorf("%w", err)
	}

	// Download key
	keyBytes, err := s.vaultConnector.Download(ctx, cryptoKeyMeta.ID, cryptoKeyMeta.KeyPairID, cryptoKeyMeta.Type)
	if err != nil {
		return nil, nil, fmt.Errorf("%w", err)
	}

	return keyBytes, cryptoKeyMeta, nil
}
