//go:build unit
// +build unit

package cryptography

import (
	"testing"

	"github.com/MGTheTrain/crypto-vault/internal/domain/crypto"
	pkgTesting "github.com/MGTheTrain/crypto-vault/internal/pkg/testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	TestAESKey128 = 16
	TestAESKey256 = 32
)

func setupAESProcessor(t *testing.T) crypto.AESProcessor {
	t.Helper()
	logger := pkgTesting.SetupTestLogger(t)
	processor, err := NewAESProcessor(logger)
	require.NoError(t, err)
	return processor
}

func TestAESProcessor(t *testing.T) {
	processor := setupAESProcessor(t)

	t.Run("EncryptDecrypt", func(t *testing.T) {
		key, err := processor.GenerateKey(TestAESKey128)
		assert.NoError(t, err)

		plainText := []byte("This is a test message.")

		ciphertext, err := processor.Encrypt(plainText, key)
		assert.NoError(t, err)
		assert.NotNil(t, ciphertext)
		assert.Greater(t, len(ciphertext), 0)

		decryptedText, err := processor.Decrypt(ciphertext, key)
		assert.NoError(t, err)
		assert.NotNil(t, decryptedText)
		assert.Equal(t, plainText, decryptedText)
	})

	t.Run("EncryptionWithInvalidKey", func(t *testing.T) {
		key := []byte("shortkey")
		plainText := []byte("This is a test.")

		_, err := processor.Encrypt(plainText, key)
		assert.Error(t, err)
	})

	t.Run("GenerateKey", func(t *testing.T) {
		key, err := processor.GenerateKey(TestAESKey128)
		assert.NoError(t, err)
		assert.Equal(t, TestAESKey128, len(key))

		key256, err := processor.GenerateKey(TestAESKey256)
		assert.NoError(t, err)
		assert.Equal(t, TestAESKey256, len(key256))
	})

	t.Run("DecryptWithWrongKey", func(t *testing.T) {
		key, err := processor.GenerateKey(TestAESKey128)
		assert.NoError(t, err)

		plainText := []byte("Test decryption with wrong key.")
		ciphertext, err := processor.Encrypt(plainText, key)
		assert.NoError(t, err)

		wrongKey, err := processor.GenerateKey(TestAESKey128)
		assert.NoError(t, err)

		decrypted, err := processor.Decrypt(ciphertext, wrongKey)

		if err == nil {
			assert.NotEqual(t, plainText, decrypted, "Decryption with wrong key should not return original message")
		} else {
			assert.Error(t, err, "Expected an error when decrypting with wrong key")
		}
	})

	t.Run("DecryptShortCiphertext", func(t *testing.T) {
		key, err := processor.GenerateKey(TestAESKey128)
		assert.NoError(t, err)

		_, err = processor.Decrypt([]byte("short"), key)
		assert.Error(t, err)
	})
}
