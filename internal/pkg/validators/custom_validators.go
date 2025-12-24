package validators

import "github.com/go-playground/validator/v10"

// KeySizeValidation validates the key size based on the algorithm type (AES, RSA or EC).
func KeySizeValidation(fl validator.FieldLevel) bool {
	algorithm := fl.Parent().FieldByName("Algorithm").String()
	keySize := fl.Field().Uint()

	switch algorithm {
	case "AES":
		// AES key sizes should be 128, 192, or 256
		return keySize == 128 || keySize == 192 || keySize == 256
	case "RSA":
		// RSA key sizes should be 512, 1024, 2048, 4096
		return keySize == 512 || keySize == 1024 || keySize == 2048 || keySize == 4096
	case "ECDSA":
		// EC key sizes can be 256, 384, or 521
		return keySize == 256 || keySize == 384 || keySize == 521
	default:
		return false
	}
}
