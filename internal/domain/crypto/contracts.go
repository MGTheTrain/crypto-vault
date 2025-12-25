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

// AESProcessor handles AES symmetric encryption operations.
// AES is used for encrypting/decrypting data with a shared secret key.
// NOTE: AES does NOT support signing/verification operations - use RSA or ECDSA for digital signatures.
type AESProcessor interface {
	// GenerateKey generates a random AES key of the specified size.
	// Supported key sizes: 16 (AES-128), 24 (AES-192), 32 (AES-256) bytes.
	GenerateKey(keySize int) ([]byte, error)

	// Encrypt encrypts plaintext data using AES with the provided symmetric key.
	// Returns the encrypted ciphertext or an error if encryption fails.
	Encrypt(data, key []byte) ([]byte, error)

	// Decrypt decrypts AES ciphertext using the provided symmetric key.
	// Returns the original plaintext or an error if decryption fails.
	Decrypt(ciphertext, key []byte) ([]byte, error)
}

// ECDSAProcessor handles elliptic curve (ECDSA) cryptographic operations.
// ECDSA is used for digital signatures but NOT for encryption.
// Use RSA if you need both encryption and signing capabilities.
type ECDSAProcessor interface {
	// GenerateKeys generates an ECDSA key pair on the specified elliptic curve.
	// Supported curves: P-224, P-256, P-384, P-521.
	GenerateKeys(curve elliptic.Curve) (*ecdsa.PrivateKey, *ecdsa.PublicKey, error)

	// Sign creates a digital signature of the message using ECDSA with the private key.
	// Returns the signature bytes or an error if signing fails.
	Sign(message []byte, privateKey *ecdsa.PrivateKey) ([]byte, error)

	// Verify verifies an ECDSA signature using the public key.
	// Returns true if the signature is valid, false otherwise.
	Verify(message, signature []byte, publicKey *ecdsa.PublicKey) (bool, error)

	// SaveSignatureToFile saves the signature bytes to a file (typically as hex-encoded text).
	SaveSignatureToFile(filename string, data []byte) error

	// SavePrivateKeyToFile saves the ECDSA private key to a PEM-encoded file.
	SavePrivateKeyToFile(privateKey *ecdsa.PrivateKey, filename string) error

	// SavePublicKeyToFile saves the ECDSA public key to a PEM-encoded file.
	SavePublicKeyToFile(publicKey *ecdsa.PublicKey, filename string) error

	// ReadPrivateKey reads an ECDSA private key from a PEM-encoded file.
	ReadPrivateKey(privateKeyPath string, curve elliptic.Curve) (*ecdsa.PrivateKey, error)

	// ReadPublicKey reads an ECDSA public key from a PEM-encoded file.
	ReadPublicKey(publicKeyPath string, curve elliptic.Curve) (*ecdsa.PublicKey, error)
}

// RSAProcessor handles RSA asymmetric cryptographic operations.
// RSA supports both encryption/decryption AND digital signatures.
// For encryption-only use cases, consider using hybrid encryption (AES + RSA) for better performance.
type RSAProcessor interface {
	// GenerateKeys generates an RSA key pair with the specified bit size.
	// Recommended sizes: 2048 (minimum), 3072, 4096 bits.
	GenerateKeys(keySize int) (*rsa.PrivateKey, *rsa.PublicKey, error)

	// Encrypt encrypts plaintext using RSA-OAEP with the public key.
	// NOTE: RSA can only encrypt small amounts of data (< key size - padding).
	// For large files, use hybrid encryption (encrypt data with AES, encrypt AES key with RSA).
	Encrypt(plainText []byte, publicKey *rsa.PublicKey) ([]byte, error)

	// Decrypt decrypts RSA-OAEP ciphertext using the private key.
	// Returns the original plaintext or an error if decryption fails.
	Decrypt(ciphertext []byte, privateKey *rsa.PrivateKey) ([]byte, error)

	// Sign creates a digital signature using RSA-PSS with the private key.
	// Returns the signature bytes or an error if signing fails.
	Sign(data []byte, privateKey *rsa.PrivateKey) ([]byte, error)

	// Verify verifies an RSA-PSS signature using the public key.
	// Returns true if the signature is valid, false otherwise.
	Verify(data []byte, signature []byte, publicKey *rsa.PublicKey) (bool, error)

	// SavePrivateKeyToFile saves the RSA private key to a PEM-encoded file (PKCS#1 format).
	SavePrivateKeyToFile(privateKey *rsa.PrivateKey, filename string) error

	// SavePublicKeyToFile saves the RSA public key to a PEM-encoded file (PKIX format).
	SavePublicKeyToFile(publicKey *rsa.PublicKey, filename string) error

	// ReadPrivateKey reads an RSA private key from a PEM-encoded file (PKCS#1 format).
	ReadPrivateKey(privateKeyPath string) (*rsa.PrivateKey, error)

	// ReadPublicKey reads an RSA public key from a PEM-encoded file (PKIX format).
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
