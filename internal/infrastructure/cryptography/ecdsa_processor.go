package cryptography

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"os"
	"path/filepath"

	"github.com/MGTheTrain/crypto-vault/internal/domain/cryptoalg"
	"github.com/MGTheTrain/crypto-vault/internal/pkg/logger"
)

// ecdsaProcessor struct that implements the ECDSAProcessor interface
type ecdsaProcessor struct {
	logger logger.Logger
}

// NewECDSAProcessor creates and returns a new instance of ecdsaProcessor
func NewECDSAProcessor(logger logger.Logger) (cryptoalg.ECDSAProcessor, error) {
	return &ecdsaProcessor{
		logger: logger,
	}, nil
}

// GenerateKeys generates an ECDSA key pair on the specified elliptic curve.
// Supported curves: P-224, P-256, P-384 P-521.
func (e *ecdsaProcessor) GenerateKeys(curve elliptic.Curve) (*ecdsa.PrivateKey, *ecdsa.PublicKey, error) {
	privateKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate elliptic curve keys: %w", err)
	}

	publicKey := &privateKey.PublicKey
	e.logger.Info("Generated EC key pairs")
	return privateKey, publicKey, nil
}

// Sign creates a digital signature of the message using ECDSA with the private key.
// Returns the signature bytes or an error if signing fails.
func (e *ecdsaProcessor) Sign(message []byte, privateKey *ecdsa.PrivateKey) ([]byte, error) {
	if privateKey == nil {
		return nil, fmt.Errorf("private key cannot be nil")
	}

	// Check if the private key is valid (D should not be zero)
	if privateKey.D.Sign() == 0 {
		return nil, fmt.Errorf("invalid private key: D cannot be zero")
	}

	// Hash the message before signing it
	hash := sha256.Sum256(message)
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, hash[:])
	if err != nil {
		return nil, fmt.Errorf("failed to sign message: %w", err)
	}

	// Encode the signature as r and s
	signature := append(r.Bytes(), s.Bytes()...)

	e.logger.Info("ECDSA signing succeeded")
	return signature, nil
}

// Verify verifies an ECDSA signature using the public key.
// Returns true if the signature is valid, false otherwise.
func (e *ecdsaProcessor) Verify(message, signature []byte, publicKey *ecdsa.PublicKey) (bool, error) {
	if publicKey == nil {
		return false, fmt.Errorf("public key cannot be nil")
	}

	// Hash the message before verifying it
	hash := sha256.Sum256(message)

	// Split the signature into r and s
	r, s := signature[:len(signature)/2], signature[len(signature)/2:]
	rInt := new(big.Int).SetBytes(r)
	sInt := new(big.Int).SetBytes(s)

	// Verify the signature
	valid := ecdsa.Verify(publicKey, hash[:], rInt, sInt)

	e.logger.Info("ECDSA verification succeeded")
	return valid, nil
}

// SavePrivateKeyToFile saves the ECDSA private key to a PEM-encoded file.
func (e *ecdsaProcessor) SavePrivateKeyToFile(privateKey *ecdsa.PrivateKey, filename string) error {
	// Marshal private key components (private key 'D' and public key components 'X' and 'Y')
	privKeyBytes := append(privateKey.D.Bytes(), privateKey.X.Bytes()...)
	privKeyBytes = append(privKeyBytes, privateKey.Y.Bytes()...)

	// Prepare the PEM block
	privKeyPem := &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: privKeyBytes,
	}

	// Write the PEM block to a file
	file, err := os.Create(filepath.Clean(filename))
	if err != nil {
		return fmt.Errorf("failed to create private key file: %w", err)
	}
	defer func() {
		if err := file.Close(); err != nil {
			log.Printf("warning: failed to close file: %v\n", err)
		}
	}()

	// Encode and write the private key in PEM format
	err = pem.Encode(file, privKeyPem)
	if err != nil {
		return fmt.Errorf("failed to encode private key: %w", err)
	}

	e.logger.Info("Saved EC private key ", filename)
	return nil
}

// SavePublicKeyToFile saves the ECDSA public key to a PEM-encoded file.
func (e *ecdsaProcessor) SavePublicKeyToFile(publicKey *ecdsa.PublicKey, filename string) error {
	pubKeyBytes := append(publicKey.X.Bytes(), publicKey.Y.Bytes()...)

	// Prepare the PEM block for the public key
	pubKeyPem := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKeyBytes,
	}

	// Write the PEM block to a file
	file, err := os.Create(filepath.Clean(filename))
	if err != nil {
		return fmt.Errorf("failed to create public key file: %w", err)
	}
	defer func() {
		if err := file.Close(); err != nil {
			log.Printf("warning: failed to close file: %v\n", err)
		}
	}()

	// Encode and write the public key in PEM format
	err = pem.Encode(file, pubKeyPem)
	if err != nil {
		return fmt.Errorf("failed to encode public key: %w", err)
	}
	e.logger.Info("Saved EC public key ", filename)

	return nil
}

// SaveSignatureToFile saves the signature bytes to a file (typically as hex-encoded text).
func (e *ecdsaProcessor) SaveSignatureToFile(filename string, data []byte) error {
	hexData := hex.EncodeToString(data)
	err := os.WriteFile(filename, []byte(hexData), 0600)
	if err != nil {
		return fmt.Errorf("failed to write data to file %s: %w", filename, err)
	}
	e.logger.Info("Saved signature file ", filename)
	return nil
}

// ReadPrivateKey reads an ECDSA private key from a PEM-encoded file.
func (e *ecdsaProcessor) ReadPrivateKey(privateKeyPath string, curve elliptic.Curve) (*ecdsa.PrivateKey, error) {
	privKeyPEM, err := os.ReadFile(filepath.Clean(privateKeyPath))
	if err != nil {
		return nil, fmt.Errorf("unable to read private key file: %w", err)
	}

	// Decode the PEM block
	block, _ := pem.Decode(privKeyPEM)
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM block containing the private key")
	}

	// Extract the private key (first part is 'D', followed by 'X' and 'Y' of the public key)
	privKeyBytes := block.Bytes
	privKeyD := new(big.Int).SetBytes(privKeyBytes[:32])  // first 32 bytes for D
	pubKeyX := new(big.Int).SetBytes(privKeyBytes[32:64]) // next 32 bytes for X
	pubKeyY := new(big.Int).SetBytes(privKeyBytes[64:96]) // last 32 bytes for Y

	publicKey := &ecdsa.PublicKey{
		Curve: curve, // Use dynamic curve
		X:     pubKeyX,
		Y:     pubKeyY,
	}

	privateKey := &ecdsa.PrivateKey{
		D:         privKeyD,
		PublicKey: *publicKey,
	}

	return privateKey, nil
}

// ReadPublicKey reads an ECDSA public key from a PEM-encoded file.
func (e *ecdsaProcessor) ReadPublicKey(publicKeyPath string, curve elliptic.Curve) (*ecdsa.PublicKey, error) {
	pubKeyPEM, err := os.ReadFile(filepath.Clean(publicKeyPath))
	if err != nil {
		return nil, fmt.Errorf("unable to read public key file: %w", err)
	}

	// Decode the PEM block
	block, _ := pem.Decode(pubKeyPEM)
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM block containing the public key")
	}

	// Extract the public key (first 32 bytes for 'X' and next 32 bytes for 'Y')
	pubKeyBytes := block.Bytes
	pubKeyX := new(big.Int).SetBytes(pubKeyBytes[:32])   // first 32 bytes for X
	pubKeyY := new(big.Int).SetBytes(pubKeyBytes[32:64]) // next 32 bytes for Y

	publicKey := &ecdsa.PublicKey{
		Curve: curve, // Use dynamic curve
		X:     pubKeyX,
		Y:     pubKeyY,
	}

	return publicKey, nil
}
