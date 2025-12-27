package validators

import (
	"github.com/go-playground/validator/v10"
)

// KeySizeValidation validates the key size based on the algorithm type (AES, RSA or EC).
func KeySizeValidation(fl validator.FieldLevel) bool {
	algorithm := fl.Parent().FieldByName("Algorithm").String()
	keySize := fl.Field().Uint()

	switch algorithm {
	case "AES":
		return keySize == 128 || keySize == 192 || keySize == 256
	case "RSA":
		return keySize == 512 || keySize == 1024 || keySize == 2048 || keySize == 3072 || keySize == 4096
	case "ECDSA":
		return keySize == 224 || keySize == 256 || keySize == 384 || keySize == 521
	default:
		return false
	}
}
