package crypto

const (
	// Cryptographic operations
	OperationEncryption = "encryption"
	OperationSigning    = "signing"

	// Key Algorithms
	AlgorithmAES   = "AES"
	AlgorithmECDSA = "ECDSA"
	AlgorithmRSA   = "RSA"

	// Key Types
	KeyTypePrivate   = "private"
	KeyTypePublic    = "public"
	KeyTypeSymmetric = "symmetric"

	// Supported AES key sizes (in bytes)
	AESKeySize128 = 16
	AESKeySize192 = 24
	AESKeySize256 = 32
)
