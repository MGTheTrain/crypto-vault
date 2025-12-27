package cryptoalg

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
