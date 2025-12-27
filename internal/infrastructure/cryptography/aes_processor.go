package cryptography

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"

	"github.com/MGTheTrain/crypto-vault/internal/domain/cryptoalg"
	"github.com/MGTheTrain/crypto-vault/internal/pkg/logger"
)

// aesProcessor struct that implements the AESProcessor interface
type aesProcessor struct {
	logger logger.Logger
}

// NewAESProcessor creates and returns a new instance of aesProcessor
func NewAESProcessor(logger logger.Logger) (cryptoalg.AESProcessor, error) {
	return &aesProcessor{
		logger: logger,
	}, nil
}

// Pad data to make it a multiple of AES block size
func pkcs7Pad(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	// nolint: gocritic
	padded := append(data, bytes.Repeat([]byte{byte(padding)}, padding)...)
	return padded
}

// Unpad data after decryption
func pkcs7Unpad(data []byte, blockSize int) ([]byte, error) {
	length := len(data)
	padding := int(data[length-1])

	if padding > length || padding > blockSize {
		return nil, fmt.Errorf("invalid padding size")
	}
	return data[:length-padding], nil
}

// GenerateKey generates a random AES key of the specified size.
// Supported key sizes: 16 (AES-128), 24 (AES-192), 32 (AES-256) bytes.
func (a *aesProcessor) GenerateKey(keySize int) ([]byte, error) {
	key := make([]byte, keySize)
	_, err := rand.Read(key)
	if err != nil {
		return nil, fmt.Errorf("failed to generate AES key: %w", err)
	}

	a.logger.Info("Generated AES key")
	return key, nil
}

// Encrypt encrypts plaintext data using AES with the provided symmetric key.
// Returns the encrypted ciphertext or an error if encryption fails.
func (a *aesProcessor) Encrypt(data, key []byte) ([]byte, error) {
	if key == nil || data == nil {
		return nil, fmt.Errorf("key and data cannot be nil")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create new AES cipher with the provided key of length %d: %w", len(key), err)
	}

	data = pkcs7Pad(data, aes.BlockSize)

	ciphertext := make([]byte, aes.BlockSize+len(data))
	iv := ciphertext[:aes.BlockSize]
	if _, err := rand.Read(iv); err != nil {
		return nil, fmt.Errorf("failed to read random bytes for IV: %w", err)
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext[aes.BlockSize:], data)

	a.logger.Info("AES encryption succeeded")
	return ciphertext, nil
}

// Decrypt decrypts AES ciphertext using the provided symmetric key.
// Returns the original plaintext or an error if decryption fails.
func (a *aesProcessor) Decrypt(ciphertext, key []byte) ([]byte, error) {
	if key == nil || ciphertext == nil {
		return nil, fmt.Errorf("ciphertext and key cannot be nil")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create new AES cipher with the provided key: %w", err)
	}

	if len(ciphertext) < aes.BlockSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(ciphertext, ciphertext)

	a.logger.Info("AES decryption succeeded")
	return pkcs7Unpad(ciphertext, aes.BlockSize)
}
