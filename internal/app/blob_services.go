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
	"log"
	"math/big"
	"mime/multipart"
)

// blobUploadService implements the BlobUploadService interface for handling blob uploads
type blobUploadService struct {
	blobConnector  blobs.BlobConnector
	blobRepository blobs.BlobRepository
	aesProcessor   crypto.AESProcessor
	ecProcessor    crypto.ECProcessor
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
	ecProcessor crypto.ECProcessor,
	rsaProcessor crypto.RSAProcessor,
	logger logger.Logger,
) (blobs.BlobUploadService, error) {
	return &blobUploadService{
		blobConnector:  blobConnector,
		blobRepository: blobRepository,
		cryptoKeyRepo:  cryptoKeyRepo,
		vaultConnector: vaultConnector,
		aesProcessor:   aesProcessor,
		ecProcessor:    ecProcessor,
		rsaProcessor:   rsaProcessor,
		logger:         logger,
	}, nil
}

// Upload transfers blobs with the option to encrypt them using an encryption key or sign them with a signing key.
// It returns a slice of Blob for the uploaded blobs and any error encountered during the upload process.
func (s *blobUploadService) Upload(ctx context.Context, form *multipart.Form, userID string, encryptionKeyID, signKeyID *string) ([]*blobs.BlobMeta, error) {
	var newForm *multipart.Form

	// Process signKeyID if provided
	if signKeyID != nil {
		keyBytes, cryptoKeyMeta, err := s.getCryptoKeyAndData(ctx, *signKeyID)
		if err != nil {
			return nil, fmt.Errorf("%w", err)
		}

		cryptoOperation := crypto.OperationSigning
		contents, fileNames, err := s.applyCryptographicOperation(form, cryptoKeyMeta.Algorithm, cryptoOperation, keyBytes, cryptoKeyMeta.KeySize)
		if err != nil {
			return nil, fmt.Errorf("%w", err)
		}

		newForm, err = utils.CreateMultipleFilesForm(contents, fileNames)
		if err != nil {
			return nil, fmt.Errorf("%w", err)
		}
	}

	// Process encryptionKeyID if provided
	if encryptionKeyID != nil {
		keyBytes, cryptoKeyMeta, err := s.getCryptoKeyAndData(ctx, *encryptionKeyID)
		if err != nil {
			return nil, fmt.Errorf("%w", err)
		}

		cryptoOperation := crypto.OperationEncryption
		contents, fileNames, err := s.applyCryptographicOperation(form, cryptoKeyMeta.Algorithm, cryptoOperation, keyBytes, cryptoKeyMeta.KeySize)
		if err != nil {
			return nil, fmt.Errorf("%w", err)
		}

		newForm, err = utils.CreateMultipleFilesForm(contents, fileNames)
		if err != nil {
			return nil, fmt.Errorf("%w", err)
		}
	}

	if signKeyID != nil || encryptionKeyID != nil {
		blobMetas, err := s.blobConnector.Upload(ctx, newForm, userID, encryptionKeyID, signKeyID)
		if err != nil {
			return nil, fmt.Errorf("%w", err)
		}

		for _, blobMeta := range blobMetas {
			err := s.blobRepository.Create(ctx, blobMeta)
			if err != nil {
				return nil, fmt.Errorf("%w", err)
			}
		}
		return blobMetas, nil
	}

	blobMetas, err := s.blobConnector.Upload(ctx, form, userID, encryptionKeyID, signKeyID)
	if err != nil {
		return nil, fmt.Errorf("%w", err)
	}

	for _, blobMeta := range blobMetas {
		err := s.blobRepository.Create(ctx, blobMeta)
		if err != nil {
			return nil, fmt.Errorf("%w", err)
		}
	}

	return blobMetas, nil
}

// getCryptoKeyAndData retrieves the encryption or signing key along with its metadata by ID.
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
func (s *blobUploadService) applyCryptographicOperation(form *multipart.Form, algorithm, operation string, keyBytes []byte, keySize uint32) ([][]byte, []string, error) {
	var contents [][]byte
	var fileNames []string

	fileHeaders := form.File["files"]
	for _, fileHeader := range fileHeaders {
		file, err := fileHeader.Open()
		if err != nil {
			return nil, nil, fmt.Errorf("%w", err)
		}
		defer func() {
			if err := file.Close(); err != nil {
				log.Printf("warning: failed to close file: %v\n", err)
			}
		}()

		buffer := bytes.NewBuffer(make([]byte, 0))
		_, err = io.Copy(buffer, file)
		if err != nil {
			return nil, nil, fmt.Errorf("%w", err)
		}
		data := buffer.Bytes()

		var processedBytes []byte

		switch algorithm {
		case crypto.AlgorithmAES:
			if operation == crypto.OperationEncryption {
				processedBytes, err = s.aesProcessor.Encrypt(data, keyBytes)
				if err != nil {
					return nil, nil, fmt.Errorf("%w", err)
				}
			}
		case crypto.AlgorithmRSA:
			switch operation {
			case crypto.OperationEncryption:
				publicKeyInterface, err := x509.ParsePKIXPublicKey(keyBytes)
				if err != nil {
					return nil, nil, fmt.Errorf("error parsing public key: %w", err)
				}
				publicKey, ok := publicKeyInterface.(*crypto_rsa.PublicKey)
				if !ok {
					return nil, nil, fmt.Errorf("public key is not of type RSA")
				}
				processedBytes, err = s.rsaProcessor.Encrypt(data, publicKey)
				if err != nil {
					return nil, nil, fmt.Errorf("encryption error: %w", err)
				}

			case crypto.OperationSigning:
				privateKey, err := x509.ParsePKCS1PrivateKey(keyBytes)
				if err != nil {
					return nil, nil, fmt.Errorf("error parsing private key: %w", err)
				}
				processedBytes, err = s.rsaProcessor.Sign(data, privateKey)
				if err != nil {
					return nil, nil, fmt.Errorf("signing error: %w", err)
				}

			default:
				return nil, nil, fmt.Errorf("unsupported operation: %s", operation)
			}
		case crypto.AlgorithmEC:
			if operation == crypto.OperationSigning {

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
					return nil, nil, fmt.Errorf("key size %v not supported for EC", keySize)
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
				processedBytes, err = s.ecProcessor.Sign(data, privateKey)
				if err != nil {
					return nil, nil, fmt.Errorf("%w", err)
				}
			}
		default:
			return nil, nil, fmt.Errorf("unsupported algorithm: %s", algorithm)
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

// GetByID retrieves a blob's metadata by its unique ID
func (s *blobMetadataService) GetByID(ctx context.Context, blobID string) (*blobs.BlobMeta, error) {
	blobMeta, err := s.blobRepository.GetByID(ctx, blobID)
	if err != nil {
		return nil, fmt.Errorf("%w", err)
	}
	return blobMeta, nil
}

// DeleteByID deletes a blob and its associated metadata by ID
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

// The download function retrieves a blob's content using its ID and also enables data decryption.
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

// getCryptoKeyAndData retrieves the encryption or signing key along with its metadata by ID.
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
