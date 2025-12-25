package app

import (
	"context"
	"crypto/elliptic"
	"crypto/x509"
	"crypto_vault_service/internal/domain/crypto"
	"crypto_vault_service/internal/domain/keys"
	"crypto_vault_service/internal/pkg/logger"
	"encoding/pem"
	"fmt"

	"github.com/google/uuid"
)

// cryptoKeyUploadService implements the CryptoKeyUploadService interface for handling blob uploads
type cryptoKeyUploadService struct {
	vaultConnector keys.VaultConnector
	cryptoKeyRepo  keys.CryptoKeyRepository
	aesProcessor   crypto.AESProcessor
	ecdsaProcessor crypto.ECDSAProcessor
	rsaProcessor   crypto.RSAProcessor
	logger         logger.Logger
}

// NewCryptoKeyUploadService creates a new cryptoKeyUploadService instance
func NewCryptoKeyUploadService(
	vaultConnector keys.VaultConnector,
	cryptoKeyRepo keys.CryptoKeyRepository,
	aesProcessor crypto.AESProcessor,
	ecdsaProcessor crypto.ECDSAProcessor,
	rsaProcessor crypto.RSAProcessor,
	logger logger.Logger,
) (keys.CryptoKeyUploadService, error) {
	return &cryptoKeyUploadService{
		vaultConnector: vaultConnector,
		cryptoKeyRepo:  cryptoKeyRepo,
		aesProcessor:   aesProcessor,
		ecdsaProcessor: ecdsaProcessor,
		rsaProcessor:   rsaProcessor,
		logger:         logger,
	}, nil
}

// Upload uploads cryptographic keys
// It returns a slice of CryptoKeyMeta and any error encountered during the upload process.
func (s *cryptoKeyUploadService) Upload(ctx context.Context, userID, keyAlgorithm string, keySize uint32) ([]*keys.CryptoKeyMeta, error) {
	var cryptKeyMetas []*keys.CryptoKeyMeta

	keyPairID := uuid.New().String()
	var err error
	switch keyAlgorithm {
	case crypto.AlgorithmAES:
		cryptKeyMetas, err = s.uploadAESKey(ctx, userID, keyPairID, keyAlgorithm, keySize)
	case crypto.AlgorithmECDSA:
		cryptKeyMetas, err = s.uploadECKey(ctx, userID, keyPairID, keyAlgorithm, keySize)
	case crypto.AlgorithmRSA:
		cryptKeyMetas, err = s.uploadRSAKey(ctx, userID, keyPairID, keyAlgorithm, keySize)
	default:
		return nil, fmt.Errorf("unsupported algorithm: %s", keyAlgorithm)
	}

	if err != nil {
		return nil, err
	}

	return cryptKeyMetas, nil
}

// Helper function for uploading AES key
func (s *cryptoKeyUploadService) uploadAESKey(ctx context.Context, userID, keyPairID, keyAlgorithm string, keySize uint32) ([]*keys.CryptoKeyMeta, error) {
	var keyMetas []*keys.CryptoKeyMeta

	var keySizeInBytes int
	switch keySize {
	case 128:
		keySizeInBytes = crypto.AESKeySize128
	case 192:
		keySizeInBytes = crypto.AESKeySize192
	case 256:
		keySizeInBytes = crypto.AESKeySize256
	default:
		return nil, fmt.Errorf("key size %v not supported for AES", keySize)
	}

	symmetricKeyBytes, err := s.aesProcessor.GenerateKey(keySizeInBytes)
	if err != nil {
		return nil, fmt.Errorf("%w", err)
	}

	keyType := crypto.KeyTypeSymmetric
	cryptoKeyMeta, err := s.vaultConnector.Upload(ctx, symmetricKeyBytes, userID, keyPairID, keyType, keyAlgorithm, keySize)
	if err != nil {
		return nil, fmt.Errorf("%w", err)
	}

	if err := s.cryptoKeyRepo.Create(ctx, cryptoKeyMeta); err != nil {
		return nil, fmt.Errorf("%w", err)
	}

	keyMetas = append(keyMetas, cryptoKeyMeta)
	return keyMetas, nil
}

// Helper function for uploading EC key pair (private and public)
func (s *cryptoKeyUploadService) uploadECKey(ctx context.Context, userID, keyPairID, keyAlgorithm string, keySize uint32) ([]*keys.CryptoKeyMeta, error) {
	var keyMetas []*keys.CryptoKeyMeta

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
		return nil, fmt.Errorf("key size %v not supported for EC", keySize)
	}

	privateKey, publicKey, err := s.ecdsaProcessor.GenerateKeys(curve)
	if err != nil {
		return nil, fmt.Errorf("%w", err)
	}

	// Upload Private Key
	privateKeyBytes := append(privateKey.D.Bytes(), privateKey.X.Bytes()...)
	privateKeyBytes = append(privateKeyBytes, privateKey.Y.Bytes()...)
	keyType := crypto.KeyTypePrivate
	cryptoKeyMeta, err := s.vaultConnector.Upload(ctx, privateKeyBytes, userID, keyPairID, keyType, keyAlgorithm, keySize)
	if err != nil {
		return nil, fmt.Errorf("%w", err)
	}

	if err := s.cryptoKeyRepo.Create(ctx, cryptoKeyMeta); err != nil {
		return nil, fmt.Errorf("%w", err)
	}

	keyMetas = append(keyMetas, cryptoKeyMeta)

	// Upload Public Key
	publicKeyBytes := append(publicKey.X.Bytes(), publicKey.Y.Bytes()...)
	keyType = crypto.KeyTypePublic
	cryptoKeyMeta, err = s.vaultConnector.Upload(ctx, publicKeyBytes, userID, keyPairID, keyType, keyAlgorithm, keySize)
	if err != nil {
		return nil, fmt.Errorf("%w", err)
	}

	if err := s.cryptoKeyRepo.Create(ctx, cryptoKeyMeta); err != nil {
		return nil, fmt.Errorf("%w", err)
	}

	keyMetas = append(keyMetas, cryptoKeyMeta)
	return keyMetas, nil
}

// Helper function for uploading RSA key pair (private and public)
func (s *cryptoKeyUploadService) uploadRSAKey(ctx context.Context, userID, keyPairID, keyAlgorithm string, keySize uint32) ([]*keys.CryptoKeyMeta, error) {
	var keyMetas []*keys.CryptoKeyMeta

	privateKey, publicKey, err := s.rsaProcessor.GenerateKeys(int(keySize))
	if err != nil {
		return nil, fmt.Errorf("%w", err)
	}

	// Upload Private Key
	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	keyType := crypto.KeyTypePrivate
	cryptoKeyMeta, err := s.vaultConnector.Upload(ctx, privateKeyBytes, userID, keyPairID, keyType, keyAlgorithm, keySize)
	if err != nil {
		return nil, fmt.Errorf("%w", err)
	}

	if err := s.cryptoKeyRepo.Create(ctx, cryptoKeyMeta); err != nil {
		return nil, fmt.Errorf("%w", err)
	}

	keyMetas = append(keyMetas, cryptoKeyMeta)

	// Upload Public Key
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key: %w", err)
	}
	keyType = crypto.KeyTypePublic
	cryptoKeyMeta, err = s.vaultConnector.Upload(ctx, publicKeyBytes, userID, keyPairID, keyType, keyAlgorithm, keySize)
	if err != nil {
		return nil, fmt.Errorf("%w", err)
	}

	if err := s.cryptoKeyRepo.Create(ctx, cryptoKeyMeta); err != nil {
		return nil, fmt.Errorf("%w", err)
	}

	keyMetas = append(keyMetas, cryptoKeyMeta)
	return keyMetas, nil
}

// cryptoKeyMetadataService implements the CryptoKeyMetadataService interface to manages cryptographic key metadata.
type cryptoKeyMetadataService struct {
	vaultConnector keys.VaultConnector
	cryptoKeyRepo  keys.CryptoKeyRepository
	logger         logger.Logger
}

// NewCryptoKeyMetadataService creates a new cryptoKeyMetadataService instance
func NewCryptoKeyMetadataService(vaultConnector keys.VaultConnector, cryptoKeyRepo keys.CryptoKeyRepository, logger logger.Logger) (keys.CryptoKeyMetadataService, error) {
	return &cryptoKeyMetadataService{
		vaultConnector: vaultConnector,
		cryptoKeyRepo:  cryptoKeyRepo,
		logger:         logger,
	}, nil
}

// List retrieves all cryptographic key metadata based on a query.
func (s *cryptoKeyMetadataService) List(ctx context.Context, query *keys.CryptoKeyQuery) ([]*keys.CryptoKeyMeta, error) {
	crypoKeyMetas, err := s.cryptoKeyRepo.List(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("%w", err)
	}

	return crypoKeyMetas, nil
}

// GetByID retrieves the crypto key metadata by ID.
func (s *cryptoKeyMetadataService) GetByID(ctx context.Context, keyID string) (*keys.CryptoKeyMeta, error) {
	keyMeta, err := s.cryptoKeyRepo.GetByID(ctx, keyID)
	if err != nil {
		return nil, fmt.Errorf("%w", err)
	}

	return keyMeta, nil
}

// DeleteByID deletes a cryptographic key's metadata by ID.
func (s *cryptoKeyMetadataService) DeleteByID(ctx context.Context, keyID string) error {
	keyMeta, err := s.GetByID(ctx, keyID)
	if err != nil {
		return fmt.Errorf("failed to get key metadata: %w", err)
	}

	err = s.vaultConnector.Delete(ctx, keyID, keyMeta.KeyPairID, keyMeta.Type)
	if err != nil {
		return fmt.Errorf("failed to delete key from vault: %w", err)
	}

	err = s.cryptoKeyRepo.DeleteByID(ctx, keyID)
	if err != nil {
		return fmt.Errorf("failed to delete key from database: %w", err)
	}
	return nil
}

// cryptoKeyDownloadService implements the CryptoKeyDownloadService interface to handle the download of cryptographic keys.
type cryptoKeyDownloadService struct {
	vaultConnector keys.VaultConnector
	cryptoKeyRepo  keys.CryptoKeyRepository
	logger         logger.Logger
}

// NewCryptoKeyDownloadService creates a new cryptoKeyDownloadService instance
func NewCryptoKeyDownloadService(vaultConnector keys.VaultConnector, cryptoKeyRepo keys.CryptoKeyRepository, logger logger.Logger) (keys.CryptoKeyDownloadService, error) {
	return &cryptoKeyDownloadService{
		vaultConnector: vaultConnector,
		cryptoKeyRepo:  cryptoKeyRepo,
		logger:         logger,
	}, nil
}

// Download retrieves a cryptographic key by ID.
// DownloadByID downloads a cryptographic key and returns it in PEM format
func (s *cryptoKeyDownloadService) DownloadByID(ctx context.Context, keyID string) ([]byte, error) {
	keyMeta, err := s.cryptoKeyRepo.GetByID(ctx, keyID)
	if err != nil {
		return nil, fmt.Errorf("failed to get key metadata: %w", err)
	}

	// Download raw key bytes from vault (DER format)
	rawKeyBytes, err := s.vaultConnector.Download(ctx, keyMeta.ID, keyMeta.KeyPairID, keyMeta.Type)
	if err != nil {
		return nil, fmt.Errorf("failed to download key from vault: %w", err)
	}

	// Convert raw bytes to PEM format based on algorithm and type
	pemBytes, err := s.convertToPEM(rawKeyBytes, keyMeta.Algorithm, keyMeta.Type)
	if err != nil {
		return nil, fmt.Errorf("failed to convert key to PEM format: %w", err)
	}

	s.logger.Info("key downloaded and converted to PEM",
		"key_id", keyID,
		"algorithm", keyMeta.Algorithm,
		"type", keyMeta.Type,
		"pem_size", len(pemBytes))

	return pemBytes, nil
}

// convertToPEM converts raw key bytes (DER format) to PEM format based on algorithm and key type
func (s *cryptoKeyDownloadService) convertToPEM(rawBytes []byte, algorithm, keyType string) ([]byte, error) {
	var pemBlock *pem.Block

	switch algorithm {
	case crypto.AlgorithmRSA:
		switch keyType {
		case crypto.KeyTypePublic:
			// RSA public key - already in PKIX/DER format from x509.MarshalPKIXPublicKey
			pemBlock = &pem.Block{
				Type:  "PUBLIC KEY",
				Bytes: rawBytes,
			}
		case crypto.KeyTypePrivate:
			// RSA private key - already in PKCS#1/DER format from x509.MarshalPKCS1PrivateKey
			pemBlock = &pem.Block{
				Type:  "RSA PRIVATE KEY",
				Bytes: rawBytes,
			}
		default:
			return nil, fmt.Errorf("unsupported RSA key type: %s", keyType)
		}

	case crypto.AlgorithmECDSA:
		switch keyType {
		case crypto.KeyTypePublic:
			// ECDSA public key - raw bytes (X || Y coordinates)
			// Wrap in PKIX format for standard PEM
			pemBlock = &pem.Block{
				Type:  "PUBLIC KEY",
				Bytes: rawBytes,
			}
		case crypto.KeyTypePrivate:
			// ECDSA private key - raw bytes (D || X || Y)
			// Keep as custom EC PRIVATE KEY format
			pemBlock = &pem.Block{
				Type:  "EC PRIVATE KEY",
				Bytes: rawBytes,
			}
		default:
			return nil, fmt.Errorf("unsupported ECDSA key type: %s", keyType)
		}

	case crypto.AlgorithmAES:
		// AES keys are symmetric - use custom PEM type
		pemBlock = &pem.Block{
			Type:  "AES KEY",
			Bytes: rawBytes,
		}

	default:
		return nil, fmt.Errorf("unsupported algorithm: %s", algorithm)
	}

	// Encode to PEM format
	pemData := pem.EncodeToMemory(pemBlock)
	if pemData == nil {
		return nil, fmt.Errorf("failed to encode key to PEM format")
	}

	return pemData, nil
}
