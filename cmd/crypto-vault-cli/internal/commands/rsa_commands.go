package commands

import (
	"crypto_vault_service/internal/domain/crypto"
	"crypto_vault_service/internal/infrastructure/cryptography"
	"crypto_vault_service/internal/pkg/logger"
	"fmt"
	"os"
	"path/filepath"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
)

// RSACommandHandler encapsulates logic for handling RSA operations via CLI.
type RSACommandHandler struct {
	rsaProcessor crypto.RSAProcessor
	logger       logger.Logger
}

// NewRSACommandHandler initializes a new RSACommandHandler with logging and an RSA processor.
// It panics if any setup step fails.
func NewRSACommandHandler() (*RSACommandHandler, error) {
	loggerInstance, err := setupLogger()
	if err != nil {
		return nil, fmt.Errorf("failed to setup logger: %w", err)
	}

	rsaProcessor, err := cryptography.NewRSAProcessor(loggerInstance)
	if err != nil {
		return nil, fmt.Errorf("failed to create RSA processor: %w", err)
	}

	return &RSACommandHandler{
		rsaProcessor: rsaProcessor,
		logger:       loggerInstance,
	}, nil
}

// GenerateRSAKeysCmd generates RSA key pairs and persists those in a selected directory
func (commandHandler *RSACommandHandler) GenerateRSAKeysCmd(cmd *cobra.Command, _ []string) {
	keySize, err := cmd.Flags().GetInt("key-size")
	if err != nil {
		commandHandler.logger.Error("invalid key-size flag: %v", err)
		return
	}
	keyDir, err := cmd.Flags().GetString("key-dir")
	if err != nil {
		commandHandler.logger.Error("invalid key-dir flag: %v", err)
		return
	}

	uniqueID := uuid.New()

	privateKey, publicKey, err := commandHandler.rsaProcessor.GenerateKeys(keySize)
	if err != nil {
		commandHandler.logger.Error("%v", err)
		return
	}

	privateKeyFilePath := fmt.Sprintf("%s/%s-private-key.pem", keyDir, uniqueID.String())

	err = commandHandler.rsaProcessor.SavePrivateKeyToFile(privateKey, privateKeyFilePath)
	if err != nil {
		commandHandler.logger.Error("%v", err)
		return
	}

	publicKeyFilePath := fmt.Sprintf("%s/%s-public-key.pem", keyDir, uniqueID.String())
	err = commandHandler.rsaProcessor.SavePublicKeyToFile(publicKey, publicKeyFilePath)
	if err != nil {
		commandHandler.logger.Error("%v", err)
		return
	}
}

// EncryptRSACmd encrypts a file using RSA and saves asymmetric key pairs
func (commandHandler *RSACommandHandler) EncryptRSACmd(cmd *cobra.Command, _ []string) {
	inputFile, err := cmd.Flags().GetString("input-file")
	if err != nil {
		commandHandler.logger.Error("invalid input-file flag: %v", err)
		return
	}
	outputFile, err := cmd.Flags().GetString("output-file")
	if err != nil {
		commandHandler.logger.Error("invalid output-file flag: %v", err)
		return
	}
	publicKeyPath, err := cmd.Flags().GetString("public-key")
	if err != nil {
		commandHandler.logger.Error("invalid public-key flag: %v", err)
		return
	}

	publicKey, err := commandHandler.rsaProcessor.ReadPublicKey(publicKeyPath)
	if err != nil {
		commandHandler.logger.Error("%v", err)
		return
	}

	plainText, err := os.ReadFile(filepath.Clean(inputFile))
	if err != nil {
		commandHandler.logger.Error("%v", err)
		return
	}

	encryptedData, err := commandHandler.rsaProcessor.Encrypt(plainText, publicKey)
	if err != nil {
		commandHandler.logger.Error("%v", err)
		return
	}

	err = os.WriteFile(outputFile, encryptedData, 0600)
	if err != nil {
		commandHandler.logger.Error("%v", err)
		return
	}

	commandHandler.logger.Info("Encrypted data path ", outputFile)
}

// DecryptRSACmd decrypts a file using RSA
func (commandHandler *RSACommandHandler) DecryptRSACmd(cmd *cobra.Command, _ []string) {
	inputFile, err := cmd.Flags().GetString("input-file")
	if err != nil {
		commandHandler.logger.Error("invalid input-file flag: %v", err)
		return
	}
	outputFile, err := cmd.Flags().GetString("output-file")
	if err != nil {
		commandHandler.logger.Error("invalid output-file flag: %v", err)
		return
	}
	privateKeyPath, err := cmd.Flags().GetString("private-key")
	if err != nil {
		commandHandler.logger.Error("invalid private-key flag: %v", err)
		return
	}

	privateKey, err := commandHandler.rsaProcessor.ReadPrivateKey(privateKeyPath)
	if err != nil {
		commandHandler.logger.Error("%v", err)
		return
	}

	encryptedData, err := os.ReadFile(filepath.Clean(inputFile))
	if err != nil {
		commandHandler.logger.Error("%v", err)
		return
	}

	decryptedData, err := commandHandler.rsaProcessor.Decrypt(encryptedData, privateKey)
	if err != nil {
		commandHandler.logger.Error("%v", err)
		return
	}

	err = os.WriteFile(outputFile, decryptedData, 0600)
	if err != nil {
		commandHandler.logger.Error("%v", err)
		return
	}

	commandHandler.logger.Info("Decrypted data path ", outputFile)
}

// SignRSACmd signs a file using RSA and saves the signature
func (commandHandler *RSACommandHandler) SignRSACmd(cmd *cobra.Command, _ []string) {
	inputFilePath, err := cmd.Flags().GetString("input-file")
	if err != nil {
		commandHandler.logger.Error("invalid input-file flag: %v", err)
		return
	}
	signatureFilePath, err := cmd.Flags().GetString("output-file")
	if err != nil {
		commandHandler.logger.Error("invalid output-file flag: %v", err)
		return
	}
	privateKeyPath, err := cmd.Flags().GetString("private-key")
	if err != nil {
		commandHandler.logger.Error("invalid private-key flag: %v", err)
		return
	}

	// Read private key
	privateKey, err := commandHandler.rsaProcessor.ReadPrivateKey(privateKeyPath)
	if err != nil {
		commandHandler.logger.Error("%v", err)
		return
	}

	// Read data to sign
	data, err := os.ReadFile(filepath.Clean(inputFilePath))
	if err != nil {
		commandHandler.logger.Error("%v", err)
		return
	}

	// Sign the data
	signature, err := commandHandler.rsaProcessor.Sign(data, privateKey)
	if err != nil {
		commandHandler.logger.Error("%v", err)
		return
	}

	// Save the signature to a file
	err = os.WriteFile(signatureFilePath, signature, 0600)
	if err != nil {
		commandHandler.logger.Error("%v", err)
		return
	}

	commandHandler.logger.Info("Signature saved at ", signatureFilePath)
}

// VerifyRSACmd verifies a signature using RSA
func (commandHandler *RSACommandHandler) VerifyRSACmd(cmd *cobra.Command, _ []string) {
	inputFilePath, err := cmd.Flags().GetString("input-file")
	if err != nil {
		commandHandler.logger.Error("invalid input-file flag: %v", err)
		return
	}
	signatureFilePath, err := cmd.Flags().GetString("signature-file")
	if err != nil {
		commandHandler.logger.Error("invalid signature-file flag: %v", err)
		return
	}
	publicKeyPath, err := cmd.Flags().GetString("public-key")
	if err != nil {
		commandHandler.logger.Error("invalid public-key flag: %v", err)
		return
	}

	// Read public key
	publicKey, err := commandHandler.rsaProcessor.ReadPublicKey(publicKeyPath)
	if err != nil {
		commandHandler.logger.Error("%v", err)
		return
	}

	// Read data and signature
	data, err := os.ReadFile(filepath.Clean(inputFilePath))
	if err != nil {
		commandHandler.logger.Error("%v", err)
		return
	}

	signature, err := os.ReadFile(filepath.Clean(signatureFilePath))
	if err != nil {
		commandHandler.logger.Error("%v", err)
		return
	}

	// Verify the signature
	valid, err := commandHandler.rsaProcessor.Verify(data, signature, publicKey)
	if err != nil {
		commandHandler.logger.Error("%v", err)
		return
	}

	if valid {
		commandHandler.logger.Info("Signature is valid")
	} else {
		commandHandler.logger.Error("Signature is invalid")
	}
}

// InitRSACommands registers RSA-related commands
func InitRSACommands(rootCmd *cobra.Command) error {
	handler, err := NewRSACommandHandler()
	if err != nil {
		return fmt.Errorf("failed to create RSA command handler %w", err)
	}

	var generateRSAKeysCmd = &cobra.Command{
		Use:   "generate-rsa-keys",
		Short: "Generate RSA keys",
		Run:   handler.GenerateRSAKeysCmd,
	}
	generateRSAKeysCmd.Flags().IntP("key-size", "", 2048, "RSA key size (default 2048 bytes for RSA-2048)")
	generateRSAKeysCmd.Flags().StringP("key-dir", "", "", "Directory to store the RSA keys")
	rootCmd.AddCommand(generateRSAKeysCmd)

	var encryptRSAFileCmd = &cobra.Command{
		Use:   "encrypt-rsa",
		Short: "Encrypt a file using RSA",
		Run:   handler.EncryptRSACmd,
	}
	encryptRSAFileCmd.Flags().StringP("input-file", "", "", "Path to input file which needs to be encrypted")
	encryptRSAFileCmd.Flags().StringP("output-file", "", "", "Path to encrypted output file")
	encryptRSAFileCmd.Flags().StringP("public-key", "", "", "Path to RSA public private key")
	rootCmd.AddCommand(encryptRSAFileCmd)

	var decryptRSAFileCmd = &cobra.Command{
		Use:   "decrypt-rsa",
		Short: "Decrypt a file using RSA",
		Run:   handler.DecryptRSACmd,
	}
	decryptRSAFileCmd.Flags().StringP("input-file", "", "", "Path to encrypted file")
	decryptRSAFileCmd.Flags().StringP("output-file", "", "", "Path to decrypted output file")
	decryptRSAFileCmd.Flags().StringP("private-key", "", "", "Path to RSA private key")
	rootCmd.AddCommand(decryptRSAFileCmd)

	var signRSAFileCmd = &cobra.Command{
		Use:   "sign-rsa",
		Short: "Sign a file using RSA",
		Run:   handler.SignRSACmd,
	}

	signRSAFileCmd.Flags().StringP("input-file", "", "", "Path to file which needs to be signed")
	signRSAFileCmd.Flags().StringP("output-file", "", "", "Path to signature output file")
	signRSAFileCmd.Flags().StringP("private-key", "", "", "Path to RSA private key")
	rootCmd.AddCommand(signRSAFileCmd)

	var verifyRSAFileCmd = &cobra.Command{
		Use:   "verify-rsa",
		Short: "Verify a file is valid using RSA",
		Run:   handler.VerifyRSACmd,
	}

	verifyRSAFileCmd.Flags().StringP("input-file", "", "", "Path to file which needs to be validated")
	verifyRSAFileCmd.Flags().StringP("signature-file", "", "", "Path to signature input file")
	verifyRSAFileCmd.Flags().StringP("public-key", "", "", "Path to RSA public key")
	rootCmd.AddCommand(verifyRSAFileCmd)
	return nil
}
