package cryptoalg

import (
	"crypto/ecdsa"
	"crypto/elliptic"
)

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
