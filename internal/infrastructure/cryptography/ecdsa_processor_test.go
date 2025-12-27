//go:build unit
// +build unit

package cryptography

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/hex"
	"math/big"
	"os"
	"path/filepath"
	"testing"

	"github.com/MGTheTrain/crypto-vault/internal/domain/cryptoalg"
	"github.com/MGTheTrain/crypto-vault/internal/pkg/testutil"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupECDSAProcessor(t *testing.T) cryptoalg.ECDSAProcessor {
	t.Helper()
	logger := testutil.SetupTestLogger(t)
	processor, err := NewECDSAProcessor(logger)
	require.NoError(t, err)
	return processor
}

func TestECDSAProcessor(t *testing.T) {
	processor := setupECDSAProcessor(t)

	t.Run("GenerateKeys", func(t *testing.T) {
		priv, pub, err := processor.GenerateKeys(elliptic.P256())
		assert.NoError(t, err)
		assert.NotNil(t, priv)
		assert.NotNil(t, pub)
		assert.Equal(t, elliptic.P256(), priv.PublicKey.Curve)
		assert.Equal(t, elliptic.P256(), pub.Curve)
	})

	t.Run("SignVerify", func(t *testing.T) {
		priv, pub, err := processor.GenerateKeys(elliptic.P256())
		assert.NoError(t, err)

		msg := []byte("This is a test message.")
		sig, err := processor.Sign(msg, priv)
		assert.NoError(t, err)
		assert.NotNil(t, sig)

		valid, err := processor.Verify(msg, sig, pub)
		assert.NoError(t, err)
		assert.True(t, valid)

		invalidMsg := []byte("Modified message.")
		valid, err = processor.Verify(invalidMsg, sig, pub)
		assert.NoError(t, err)
		assert.False(t, valid)
	})

	t.Run("SaveAndReadKeys", func(t *testing.T) {
		tmpDir := t.TempDir()
		privateFile := filepath.Join(tmpDir, "private_test.pem")
		publicFile := filepath.Join(tmpDir, "public_test.pem")

		priv, pub, err := processor.GenerateKeys(elliptic.P256())
		assert.NoError(t, err)

		err = processor.SavePrivateKeyToFile(priv, privateFile)
		assert.NoError(t, err)

		err = processor.SavePublicKeyToFile(pub, publicFile)
		assert.NoError(t, err)

		readPriv, err := processor.ReadPrivateKey(privateFile, elliptic.P256())
		assert.NoError(t, err)
		assert.Equal(t, priv.D, readPriv.D)
		assert.Equal(t, priv.PublicKey.X, readPriv.PublicKey.X)
		assert.Equal(t, priv.PublicKey.Y, readPriv.PublicKey.Y)

		readPub, err := processor.ReadPublicKey(publicFile, elliptic.P256())
		assert.NoError(t, err)
		assert.Equal(t, pub.X, readPub.X)
		assert.Equal(t, pub.Y, readPub.Y)
	})

	t.Run("SaveSignatureToFile", func(t *testing.T) {
		tmpDir := t.TempDir()
		sigFile := filepath.Join(tmpDir, "signature_test.hex")

		priv, _, err := processor.GenerateKeys(elliptic.P256())
		assert.NoError(t, err)

		msg := []byte("This is a test message.")
		sig, err := processor.Sign(msg, priv)
		assert.NoError(t, err)

		err = processor.SaveSignatureToFile(sigFile, sig)
		assert.NoError(t, err)

		hexData, err := os.ReadFile(sigFile)
		assert.NoError(t, err)

		decoded, err := hex.DecodeString(string(hexData))
		assert.NoError(t, err)
		assert.Equal(t, sig, decoded)
	})

	t.Run("SignWithInvalidPrivateKey", func(t *testing.T) {
		invalidPriv := &ecdsa.PrivateKey{
			D: new(big.Int).SetInt64(0),
			PublicKey: ecdsa.PublicKey{
				Curve: elliptic.P256(),
			},
		}
		_, err := processor.Sign([]byte("Invalid signing"), invalidPriv)
		assert.Error(t, err)
	})

	t.Run("VerifyWithInvalidPublicKey", func(t *testing.T) {
		priv, _, err := processor.GenerateKeys(elliptic.P256())
		assert.NoError(t, err)

		msg := []byte("Test message")
		sig, err := processor.Sign(msg, priv)
		assert.NoError(t, err)

		invalidPub := &ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     big.NewInt(0),
			Y:     big.NewInt(0),
		}

		valid, err := processor.Verify(msg, sig, invalidPub)
		assert.NoError(t, err)
		assert.False(t, valid)
	})
}
