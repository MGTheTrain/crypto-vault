package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
)

// TODO(MGTheTrain): Implicitly implement interface signatures
// // CryptoKeyOperationService defines methods for local cryptographic key management, encryption, signing, and PKCS#11 operations.
// type CryptoKeyOperationService interface {

// 	// --- Key Generation ---

// 	// GenerateKey generates a cryptographic key of the specified type and size (e.g., AES, RSA, ECDSA).
// 	// It returns the generated key as a byte slice and any error encountered during the key generation.
// 	GenerateKey(keyType string, keySize int) ([]byte, error)

// 	// --- Key Storage and Retrieval ---

// 	// SaveKey saves a cryptographic key to a specified file.
// 	// It returns any error encountered during the saving process.
// 	SaveKey(key []byte, filename string) error

// 	// LoadKey loads a cryptographic key from a specified file.
// 	// It returns the loaded key as a byte slice and any error encountered during the loading process.
// 	LoadKey(filename string) ([]byte, error)

// 	// --- Encryption and Decryption (Symmetric algorithms like AES) ---

// 	// EncryptWithSymmetricKey encrypts data using a symmetric key (e.g., AES).
// 	// It returns the encrypted data as a byte slice and any error encountered during encryption.
// 	EncryptWithSymmetricKey(plainText []byte, key []byte) ([]byte, error)

// 	// DecryptWithSymmetricKey decrypts data using a symmetric key (e.g., AES).
// 	// It returns the decrypted data as a byte slice and any error encountered during decryption.
// 	DecryptWithSymmetricKey(cipherText []byte, key []byte) ([]byte, error)

// 	// --- Asymmetric Encryption (RSA, ECDSA, PKCS#11) ---

// 	// EncryptWithPublicKey encrypts data with a public key using asymmetric encryption algorithms (e.g., RSA, ECDSA).
// 	// It optionally supports PKCS#11 hardware tokens for key storage.
// 	// It returns the encrypted data as a byte slice and any error encountered during encryption.
// 	EncryptWithPublicKey(plainText []byte, publicKey interface{}) ([]byte, error)

// 	// DecryptWithPrivateKey decrypts data with a private key using asymmetric encryption algorithms (e.g., RSA, ECDSA).
// 	// It optionally supports PKCS#11 hardware tokens for key storage.
// 	// It returns the decrypted data as a byte slice and any error encountered during decryption.
// 	DecryptWithPrivateKey(cipherText []byte, privateKey interface{}) ([]byte, error)

// 	// --- Signing and Verification (For RSA, ECDSA) ---

// 	// SignWithPrivateKey signs a message using a private key with asymmetric algorithms (e.g., RSA, ECDSA).
// 	// It optionally supports PKCS#11 hardware tokens for key storage.
// 	// It returns the signature and any error encountered during the signing process.
// 	SignWithPrivateKey(message []byte, privateKey interface{}) ([]byte, error)

// 	// VerifyWithPublicKey verifies a signature using a public key with asymmetric algorithms (e.g., RSA, ECDSA).
// 	// It optionally supports PKCS#11 hardware tokens for key storage.
// 	// It returns true if the signature is valid, false otherwise, and any error encountered during the verification process.
// 	VerifyWithPublicKey(message []byte, signature []byte, publicKey interface{}) (bool, error)

// 	// --- PKCS#11 Operations ---

// 	// InitializeToken initializes a PKCS#11 token in the specified hardware slot.
// 	// It returns any error encountered during the initialization.
// 	InitializeToken(slot string) error

// 	// AddKeyToToken adds a cryptographic key to a PKCS#11 token.
// 	// It returns any error encountered during the addition of the key.
// 	AddKeyToToken() error

// 	// DeleteKeyFromToken deletes a cryptographic key from a PKCS#11 token by type and label.
// 	// It returns any error encountered during the deletion of the key.
// 	DeleteKeyFromToken(objectType, objectLabel string) error
// }

// AESProcessor handles AES encryption operations
type AESProcessor interface {
	Encrypt(data, key []byte) ([]byte, error)
	Decrypt(ciphertext, key []byte) ([]byte, error)
	GenerateKey(keySize int) ([]byte, error)
}

// ECProcessor handles elliptic curve operations
type ECProcessor interface {
	GenerateKeys(curve elliptic.Curve) (*ecdsa.PrivateKey, *ecdsa.PublicKey, error)
	Sign(message []byte, privateKey *ecdsa.PrivateKey) ([]byte, error)
	Verify(message, signature []byte, publicKey *ecdsa.PublicKey) (bool, error)
	SaveSignatureToFile(filename string, data []byte) error
	SavePrivateKeyToFile(privateKey *ecdsa.PrivateKey, filename string) error
	SavePublicKeyToFile(publicKey *ecdsa.PublicKey, filename string) error
	ReadPrivateKey(privateKeyPath string, curve elliptic.Curve) (*ecdsa.PrivateKey, error)
	ReadPublicKey(publicKeyPath string, curve elliptic.Curve) (*ecdsa.PublicKey, error)
}

// RSAProcessor handles RSA operations
type RSAProcessor interface {
	Encrypt(plainText []byte, publicKey *rsa.PublicKey) ([]byte, error)
	Decrypt(ciphertext []byte, privateKey *rsa.PrivateKey) ([]byte, error)
	Sign(data []byte, privateKey *rsa.PrivateKey) ([]byte, error)
	Verify(data []byte, signature []byte, publicKey *rsa.PublicKey) (bool, error)
	GenerateKeys(keySize int) (*rsa.PrivateKey, *rsa.PublicKey, error)
	SavePrivateKeyToFile(privateKey *rsa.PrivateKey, filename string) error
	SavePublicKeyToFile(publicKey *rsa.PublicKey, filename string) error
	ReadPrivateKey(privateKeyPath string) (*rsa.PrivateKey, error)
	ReadPublicKey(publicKeyPath string) (*rsa.PublicKey, error)
}

// PKCS11Handler defines the operations for working with a PKCS#11 token
type PKCS11Handler interface {
	// ListTokenSlots lists all available tokens in the available slots
	ListTokenSlots() ([]Token, error)
	// ListObjects lists all objects (e.g. keys) in a specific token based on the token label
	ListObjects(tokenLabel string) ([]TokenObject, error)
	// InitializeToken initializes the token with the provided label and pins
	InitializeToken(label string) error
	// AddSignKey adds a signing key (ECDSA or RSA) to the token
	AddSignKey(label, objectLabel, keyType string, keySize uint) error
	// AddEncryptKey adds an encryption key (RSA only currently) to the token
	AddEncryptKey(label, objectLabel, keyType string, keySize uint) error
	// Encrypt encrypts data using the cryptographic capabilities of the PKCS#11 token
	Encrypt(label, objectLabel, inputFilePath, outputFilePath, keyType string) error
	// Decrypt decrypts data using the cryptographic capabilities of the PKCS#11 token
	Decrypt(label, objectLabel, inputFilePath, outputFilePath, keyType string) error
	// Sign signs data using the cryptographic capabilities of the PKCS#11 token
	Sign(label, objectLabel, dataFilePath, signatureFilePath, keyType string) error
	// Verify verifies the signature of data using the cryptographic capabilities of the PKCS#11 token
	Verify(label, objectLabel, dataFilePath, signatureFilePath, keyType string) (bool, error)
	// DeleteObject deletes a key or object from the token
	DeleteObject(label, objectType, objectLabel string) error
}
