//go:build unit
// +build unit

package cryptography

import (
	"crypto/rsa"
	"path/filepath"
	"testing"

	"crypto_vault_service/internal/domain/crypto"
	pkgTesting "crypto_vault_service/internal/pkg/testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	TestKeySize2048 = 2048
)

func setupRSAProcessor(t *testing.T) crypto.RSAProcessor {
	t.Helper()
	logger := pkgTesting.SetupTestLogger(t)
	processor, err := NewRSAProcessor(logger)
	require.NoError(t, err)
	return processor
}

func TestRSAProcessor(t *testing.T) {
	processor := setupRSAProcessor(t)

	t.Run("GenerateKeys", func(t *testing.T) {
		privateKey, publicKey, err := processor.GenerateKeys(TestKeySize2048)
		assert.NoError(t, err)
		assert.NotNil(t, privateKey)
		assert.NotNil(t, publicKey)
		assert.IsType(t, &rsa.PublicKey{}, publicKey)
		assert.Equal(t, TestKeySize2048, privateKey.N.BitLen())
	})

	t.Run("EncryptDecrypt", func(t *testing.T) {
		privateKey, publicKey, err := processor.GenerateKeys(TestKeySize2048)
		assert.NoError(t, err)

		plainText := []byte("This is a secret message")
		encrypted, err := processor.Encrypt(plainText, publicKey)
		assert.NoError(t, err)
		decrypted, err := processor.Decrypt(encrypted, privateKey)
		assert.NoError(t, err)
		assert.Equal(t, plainText, decrypted)
	})

	t.Run("SaveAndReadKeys", func(t *testing.T) {
		tmpDir := t.TempDir()
		privFile := filepath.Join(tmpDir, "private.pem")
		pubFile := filepath.Join(tmpDir, "public.pem")

		privateKey, publicKey, err := processor.GenerateKeys(TestKeySize2048)
		assert.NoError(t, err)

		assert.NoError(t, processor.SavePrivateKeyToFile(privateKey, privFile))
		assert.NoError(t, processor.SavePublicKeyToFile(publicKey, pubFile))

		readPriv, err := processor.ReadPrivateKey(privFile)
		assert.NoError(t, err)
		assert.Equal(t, privateKey.N, readPriv.N)
		assert.Equal(t, privateKey.E, readPriv.E)

		readPub, err := processor.ReadPublicKey(pubFile)
		assert.NoError(t, err)
		assert.Equal(t, publicKey.N, readPub.N)
		assert.Equal(t, publicKey.E, readPub.E)
	})

	t.Run("EncryptWithInvalidKey", func(t *testing.T) {
		_, publicKey, err := processor.GenerateKeys(TestKeySize2048)
		assert.NoError(t, err)

		plainText := []byte("This should fail encryption")
		encrypted, err := processor.Encrypt(plainText, publicKey)
		assert.NoError(t, err)

		wrongPrivKey, _, err := processor.GenerateKeys(TestKeySize2048)
		assert.NoError(t, err)

		_, err = processor.Decrypt(encrypted, wrongPrivKey)
		assert.Error(t, err)
	})

	t.Run("SavePrivateKeyInvalidPath", func(t *testing.T) {
		privateKey, _, err := processor.GenerateKeys(TestKeySize2048)
		assert.NoError(t, err)

		err = processor.SavePrivateKeyToFile(privateKey, "/invalid/path/private.pem")
		assert.Error(t, err)
	})

	t.Run("SavePublicKeyInvalidPath", func(t *testing.T) {
		_, publicKey, err := processor.GenerateKeys(TestKeySize2048)
		assert.NoError(t, err)

		err = processor.SavePublicKeyToFile(publicKey, "/invalid/path/public.pem")
		assert.Error(t, err)
	})

	t.Run("SignAndVerify", func(t *testing.T) {
		privateKey, publicKey, err := processor.GenerateKeys(TestKeySize2048)
		assert.NoError(t, err)

		data := []byte("This is a test message")
		signature, err := processor.Sign(data, privateKey)
		assert.NoError(t, err)
		assert.NotNil(t, signature)

		valid, err := processor.Verify(data, signature, publicKey)
		assert.NoError(t, err)
		assert.True(t, valid)

		tampered := []byte("This is a tampered message")
		valid, err = processor.Verify(tampered, signature, publicKey)
		assert.Error(t, err)
		assert.False(t, valid)
	})
}
