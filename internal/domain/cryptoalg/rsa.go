package cryptoalg

import "crypto/rsa"

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
