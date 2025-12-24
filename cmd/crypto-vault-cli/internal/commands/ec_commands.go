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

// ECCommandHandler encapsulates logic for handling elliptic curve cryptographic operations via CLI.
type ECCommandHandler struct {
	ecProcessor crypto.ECProcessor
	logger      logger.Logger
}

// NewECCommandHandler initializes a new ECCommandHandler with logging and an EC processor.
func NewECCommandHandler() (*ECCommandHandler, error) {
	loggerInstance, err := setupLogger()
	if err != nil {
		return nil, fmt.Errorf("failed to setup logger: %w", err)
	}

	ecProcessor, err := cryptography.NewECProcessor(loggerInstance)
	if err != nil {
		return nil, fmt.Errorf("failed to create EC processor: %w", err)
	}

	return &ECCommandHandler{
		ecProcessor: ecProcessor,
		logger:      loggerInstance,
	}, nil
}

// GenerateECKeysCmd generates EC key pairs and persists those in a selected directory
func (commandHandler *ECCommandHandler) GenerateECKeysCmd(cmd *cobra.Command, _ []string) {
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
		commandHandler.logger.Error("key size %v not supported", keySize)
		return
	}

	privateKey, publicKey, err := commandHandler.ecProcessor.GenerateKeys(curve)
	if err != nil {
		commandHandler.logger.Error(err)
		return
	}

	privateKeyFilePath := fmt.Sprintf("%s/%s-private-key.pem", keyDir, uniqueID.String())
	err = commandHandler.ecProcessor.SavePrivateKeyToFile(privateKey, privateKeyFilePath)
	if err != nil {
		commandHandler.logger.Error(err)
		return
	}

	publicKeyFilePath := fmt.Sprintf("%s/%s-public-key.pem", keyDir, uniqueID.String())
	err = commandHandler.ecProcessor.SavePublicKeyToFile(publicKey, publicKeyFilePath)
	if err != nil {
		commandHandler.logger.Error(err)
		return
	}
}

// SignECCCmd signs the contents of a file with ECDSA
func (commandHandler *ECCommandHandler) SignECCCmd(cmd *cobra.Command, _ []string) {
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

	privateKey, err := commandHandler.ecProcessor.ReadPrivateKey(privateKeyFilePath, elliptic.P256())
	if err != nil {
		commandHandler.logger.Error(err)
		return
	}

	signature, err := commandHandler.ecProcessor.Sign(fileContent, privateKey)
	if err != nil {
		commandHandler.logger.Error(err)
		return
	}

	err = commandHandler.ecProcessor.SaveSignatureToFile(signatureFilePath, signature)
	if err != nil {
		commandHandler.logger.Error(err)
		return
	}
}

// VerifyECCCmd verifies the signature of a file's content using ECDSA
func (commandHandler *ECCommandHandler) VerifyECCCmd(cmd *cobra.Command, _ []string) {
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

	publicKey, err := commandHandler.ecProcessor.ReadPublicKey(publicKeyPath, elliptic.P256())
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

	valid, err := commandHandler.ecProcessor.Verify(fileContent, signature, publicKey)
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
	handler, err := NewECCommandHandler()
	if err != nil {
		return fmt.Errorf("failed to create EC command handler %w", err)
	}

	var generateECKeysCmd = &cobra.Command{
		Use:   "generate-ecc-keys",
		Short: "Generate ECC keys",
		Run:   handler.GenerateECKeysCmd,
	}
	generateECKeysCmd.Flags().IntP("key-size", "", 256, "ECC key size (default 256 bytes for ECC-256)")
	generateECKeysCmd.Flags().StringP("key-dir", "", "", "Directory to store the ECC keys")
	rootCmd.AddCommand(generateECKeysCmd)

	var signECCMessageCmd = &cobra.Command{
		Use:   "sign-ecc",
		Short: "Sign a message using ECC",
		Run:   handler.SignECCCmd,
	}
	signECCMessageCmd.Flags().StringP("input-file", "", "", "Path to file that needs to be signed")
	signECCMessageCmd.Flags().StringP("private-key", "", "", "Path to ECC private key")
	signECCMessageCmd.Flags().StringP("output-file", "", "", "Path to signature output file")
	rootCmd.AddCommand(signECCMessageCmd)

	var verifyECCSignatureCmd = &cobra.Command{
		Use:   "verify-ecc",
		Short: "Verify a signature using ECC",
		Run:   handler.VerifyECCCmd,
	}
	verifyECCSignatureCmd.Flags().StringP("input-file", "", "", "Path to file which needs to be validated")
	verifyECCSignatureCmd.Flags().StringP("public-key", "", "", "Path to ECC public key")
	verifyECCSignatureCmd.Flags().StringP("signature-file", "", "", "Path to signature input file")
	rootCmd.AddCommand(verifyECCSignatureCmd)

	return nil
}
