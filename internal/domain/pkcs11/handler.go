package pkcs11

// Handler defines the operations for working with a PKCS#11 token
type Handler interface {
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
