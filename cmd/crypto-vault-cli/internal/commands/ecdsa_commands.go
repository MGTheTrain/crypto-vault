package commands

import (
	"crypto/elliptic"
	"crypto_vault_service/internal/domain/crypto"
	"crypto_vault_service/internal/infrastructure/cryptography"
	"crypto_vault_service/internal/pkg/logger"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
)

// ECDSACommandHandler encapsulates logic for handling elliptic curve cryptographic operations via CLI.
type ECDSACommandHandler struct {
	ecdsaProcessor crypto.ECDSAProcessor
	logger         logger.Logger
}

// NewECDSACommandHandler initializes a new ECDSACommandHandler
// with configured logger and an ECDSA processor.
func NewECDSACommandHandler() (*ECDSACommandHandler, error) {
	loggerInstance, err := setupLogger()
	if err != nil {
		return nil, fmt.Errorf("failed to setup logger: %w", err)
	}

	ecdsaProcessor, err := cryptography.NewECDSAProcessor(loggerInstance)
	if err != nil {
		return nil, fmt.Errorf("failed to create ECDSA processor: %w", err)
	}

	return &ECDSACommandHandler{
		ecdsaProcessor: ecdsaProcessor,
		logger:         loggerInstance,
	}, nil
}

// GenerateECDSAKeysCmd generates ECDSA key pairs and persists those in a selected directory
func (commandHandler *ECDSACommandHandler) GenerateECDSAKeysCmd(cmd *cobra.Command, _ []string) {
	keySize, err := cmd.Flags().GetInt("key-size")
	if err != nil {
		commandHandler.logger.Error("invalid key-size flag ", err)
		return
	}
	keyDir, err := cmd.Flags().GetString("key-dir")
	if err != nil {
		commandHandler.logger.Error("invalid key-dir flag ", err)
		return
	}

	uniqueID := uuid.New()

	var curve elliptic.Curve
	switch keySize {
	case 224:
		curve = elliptic.P224()
	case 256:
		curve = elliptic.P256()
	case 384:
		curve = elliptic.P384()
	case 521:
		curve = elliptic.P521()
	default:
		commandHandler.logger.Error("key size ", keySize, " not supported")
		return
	}

	privateKey, publicKey, err := commandHandler.ecdsaProcessor.GenerateKeys(curve)
	if err != nil {
		commandHandler.logger.Error(err)
		return
	}

	privateKeyFilePath := fmt.Sprintf("%s/%s-private-key.pem", keyDir, uniqueID.String())
	err = commandHandler.ecdsaProcessor.SavePrivateKeyToFile(privateKey, privateKeyFilePath)
	if err != nil {
		commandHandler.logger.Error(err)
		return
	}

	publicKeyFilePath := fmt.Sprintf("%s/%s-public-key.pem", keyDir, uniqueID.String())
	err = commandHandler.ecdsaProcessor.SavePublicKeyToFile(publicKey, publicKeyFilePath)
	if err != nil {
		commandHandler.logger.Error(err)
		return
	}
}

// SignECDSACmd signs the contents of a file with ECDSA
func (commandHandler *ECDSACommandHandler) SignECDSACmd(cmd *cobra.Command, _ []string) {
	inputFilePath, err := cmd.Flags().GetString("input-file")
	if err != nil {
		commandHandler.logger.Error("invalid input-file flag ", err)
		return
	}
	privateKeyFilePath, err := cmd.Flags().GetString("private-key")
	if err != nil {
		commandHandler.logger.Error("invalid private-key flag ", err)
		return
	}
	signatureFilePath, err := cmd.Flags().GetString("output-file")
	if err != nil {
		commandHandler.logger.Error("invalid output-file flag ", err)
		return
	}

	fileContent, err := os.ReadFile(filepath.Clean(inputFilePath))
	if err != nil {
		commandHandler.logger.Error(err)
		return
	}

	privateKey, err := commandHandler.ecdsaProcessor.ReadPrivateKey(privateKeyFilePath, elliptic.P256())
	if err != nil {
		commandHandler.logger.Error(err)
		return
	}

	signature, err := commandHandler.ecdsaProcessor.Sign(fileContent, privateKey)
	if err != nil {
		commandHandler.logger.Error(err)
		return
	}

	err = commandHandler.ecdsaProcessor.SaveSignatureToFile(signatureFilePath, signature)
	if err != nil {
		commandHandler.logger.Error(err)
		return
	}
}

// VerifyECDSACmd verifies the signature of a file's content using ECDSA
func (commandHandler *ECDSACommandHandler) VerifyECDSACmd(cmd *cobra.Command, _ []string) {
	inputFilePath, err := cmd.Flags().GetString("input-file")
	if err != nil {
		commandHandler.logger.Error("invalid input-file flag ", err)
		return
	}
	publicKeyPath, err := cmd.Flags().GetString("public-key")
	if err != nil {
		commandHandler.logger.Error("invalid public-key flag ", err)
		return
	}
	signatureFile, err := cmd.Flags().GetString("signature-file")
	if err != nil {
		commandHandler.logger.Error("invalid signature-file flag ", err)
		return
	}

	publicKey, err := commandHandler.ecdsaProcessor.ReadPublicKey(publicKeyPath, elliptic.P256())
	if err != nil {
		commandHandler.logger.Error(err)
		return
	}

	fileContent, err := os.ReadFile(filepath.Clean(inputFilePath))
	if err != nil {
		commandHandler.logger.Error(err)
		return
	}

	signatureHex, err := os.ReadFile(filepath.Clean(signatureFile))
	if err != nil {
		commandHandler.logger.Error(err)
		return
	}

	signature, err := hex.DecodeString(string(signatureHex))
	if err != nil {
		commandHandler.logger.Error(err)
		return
	}

	valid, err := commandHandler.ecdsaProcessor.Verify(fileContent, signature, publicKey)
	if err != nil {
		commandHandler.logger.Error(err)
		return
	}

	if valid {
		commandHandler.logger.Info("Signature valid for ", inputFilePath)
	} else {
		commandHandler.logger.Info("Signature invalid for ", inputFilePath)
	}
}

// InitECDSACommands registers EC-related commands
func InitECDSACommands(rootCmd *cobra.Command) error {
	handler, err := NewECDSACommandHandler()
	if err != nil {
		return fmt.Errorf("failed to create ECDSA command handler %w", err)
	}

	var generateECDSAKeysCmd = &cobra.Command{
		Use:   "generate-ecdsa-keys",
		Short: "Generate ECDSA keys",
		Run:   handler.GenerateECDSAKeysCmd,
	}
	generateECDSAKeysCmd.Flags().IntP("key-size", "", 256, "ECDSA key size (default 256 bytes for ECDSA-256)")
	generateECDSAKeysCmd.Flags().StringP("key-dir", "", "", "Directory to store the ECDSA keys")
	rootCmd.AddCommand(generateECDSAKeysCmd)

	var signECDSAMessageCmd = &cobra.Command{
		Use:   "sign-ecdsa",
		Short: "Sign a message using ECDSA",
		Run:   handler.SignECDSACmd,
	}
	signECDSAMessageCmd.Flags().StringP("input-file", "", "", "Path to file that needs to be signed")
	signECDSAMessageCmd.Flags().StringP("private-key", "", "", "Path to ECDSA private key")
	signECDSAMessageCmd.Flags().StringP("output-file", "", "", "Path to signature output file")
	rootCmd.AddCommand(signECDSAMessageCmd)

	var verifyECDSASignatureCmd = &cobra.Command{
		Use:   "verify-ecdsa",
		Short: "Verify a signature using ECDSA",
		Run:   handler.VerifyECDSACmd,
	}
	verifyECDSASignatureCmd.Flags().StringP("input-file", "", "", "Path to file which needs to be validated")
	verifyECDSASignatureCmd.Flags().StringP("public-key", "", "", "Path to ECDSA public key")
	verifyECDSASignatureCmd.Flags().StringP("signature-file", "", "", "Path to signature input file")
	rootCmd.AddCommand(verifyECDSASignatureCmd)

	return nil
}
