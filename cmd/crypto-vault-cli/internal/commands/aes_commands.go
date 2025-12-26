package commands

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/MGTheTrain/crypto-vault/internal/domain/crypto"
	"github.com/MGTheTrain/crypto-vault/internal/infrastructure/cryptography"
	"github.com/MGTheTrain/crypto-vault/internal/pkg/logger"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
)

// AESCommandHandler encapsulates logic for handling AES operations via CLI.
type AESCommandHandler struct {
	aesProcessor crypto.AESProcessor
	logger       logger.Logger
}

// NewAESCommandHandler initializes and returns an AESCommandHandler instance with
// configured logger and AES processor.
func NewAESCommandHandler() (*AESCommandHandler, error) {
	loggerInstance, err := setupLogger()
	if err != nil {
		return nil, fmt.Errorf("failed to setup logger: %w", err)
	}

	aesProcessor, err := cryptography.NewAESProcessor(loggerInstance)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES processor: %w", err)
	}

	return &AESCommandHandler{
		aesProcessor: aesProcessor,
		logger:       loggerInstance,
	}, nil
}

// GenerateAESKeysCmd generates AES key pairs and persists those in a selected directory
func (commandHandler *AESCommandHandler) GenerateAESKeysCmd(cmd *cobra.Command, _ []string) {
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

	secretKey, err := commandHandler.aesProcessor.GenerateKey(keySize)
	if err != nil {
		commandHandler.logger.Error(err)
		return
	}

	keyFilePath := filepath.Join(keyDir, fmt.Sprintf("%s-symmetric-key.bin", uniqueID))
	err = os.WriteFile(keyFilePath, secretKey, 0600)
	if err != nil {
		commandHandler.logger.Error(err)
		return
	}
	commandHandler.logger.Info("AES key saved to ", keyFilePath)
}

// EncryptAESCmd encrypts a file using AES and saves the symmetric key with a UUID prefix
func (commandHandler *AESCommandHandler) EncryptAESCmd(cmd *cobra.Command, _ []string) {
	inputFilePath, err := cmd.Flags().GetString("input-file")
	if err != nil {
		commandHandler.logger.Error("invalid input-file flag ", err)
		return
	}
	outputFilePath, err := cmd.Flags().GetString("output-file")
	if err != nil {
		commandHandler.logger.Error("invalid output-file flag ", err)
		return
	}
	symmetricKey, err := cmd.Flags().GetString("symmetric-key")
	if err != nil {
		commandHandler.logger.Error("invalid symmetric-key flag ", err)
		return
	}

	plainText, err := os.ReadFile(filepath.Clean(inputFilePath))
	if err != nil {
		commandHandler.logger.Error(err)
		return
	}

	key, err := os.ReadFile(filepath.Clean(symmetricKey))
	if err != nil {
		commandHandler.logger.Error(err)
		return
	}

	encryptedData, err := commandHandler.aesProcessor.Encrypt(plainText, key)
	if err != nil {
		commandHandler.logger.Error(err)
		return
	}

	err = os.WriteFile(outputFilePath, encryptedData, 0600)
	if err != nil {
		commandHandler.logger.Error(err)
		return
	}

	commandHandler.logger.Info("Encrypted data saved to ", outputFilePath)
}

// DecryptAESCmd decrypts a file using AES and reads the corresponding symmetric key with a UUID prefix
func (commandHandler *AESCommandHandler) DecryptAESCmd(cmd *cobra.Command, _ []string) {
	inputFilePath, err := cmd.Flags().GetString("input-file")
	if err != nil {
		commandHandler.logger.Error("invalid input-file flag ", err)
		return
	}
	outputFilePath, err := cmd.Flags().GetString("output-file")
	if err != nil {
		commandHandler.logger.Error("invalid output-file flag ", err)
		return
	}
	symmetricKey, err := cmd.Flags().GetString("symmetric-key")
	if err != nil {
		commandHandler.logger.Error("invalid symmetric-key flag ", err)
		return
	}

	key, err := os.ReadFile(filepath.Clean(symmetricKey))
	if err != nil {
		commandHandler.logger.Error(err)
		return
	}

	encryptedData, err := os.ReadFile(filepath.Clean(inputFilePath))
	if err != nil {
		commandHandler.logger.Error(err)
		return
	}

	decryptedData, err := commandHandler.aesProcessor.Decrypt(encryptedData, key)
	if err != nil {
		commandHandler.logger.Error(err)
		return
	}

	err = os.WriteFile(outputFilePath, decryptedData, 0600)
	if err != nil {
		commandHandler.logger.Error(err)
		return
	}

	commandHandler.logger.Info("Decrypted data saved to ", outputFilePath)
}

// InitAESCommands registers AES-related commands
func InitAESCommands(rootCmd *cobra.Command) error {
	handler, err := NewAESCommandHandler()

	if err != nil {
		return fmt.Errorf("failed to create AES command handler %w", err)
	}

	var generateAESKeysCmd = &cobra.Command{
		Use:   "generate-aes-keys",
		Short: "Generate AES keys",
		Run:   handler.GenerateAESKeysCmd,
	}
	generateAESKeysCmd.Flags().IntP("key-size", "", 16, "AES key size (default 16 bytes for AES-128)")
	generateAESKeysCmd.Flags().StringP("key-dir", "", "", "Directory to store the encryption key")
	rootCmd.AddCommand(generateAESKeysCmd)

	var encryptAESFileCmd = &cobra.Command{
		Use:   "encrypt-aes",
		Short: "Encrypt a file using AES",
		Run:   handler.EncryptAESCmd,
	}
	encryptAESFileCmd.Flags().StringP("input-file", "", "", "Path to input file that needs to be encrypted")
	encryptAESFileCmd.Flags().StringP("output-file", "", "", "Path to encrypted output file")
	encryptAESFileCmd.Flags().StringP("symmetric-key", "", "", "Path to the symmetric key")
	rootCmd.AddCommand(encryptAESFileCmd)

	var decryptAESFileCmd = &cobra.Command{
		Use:   "decrypt-aes",
		Short: "Decrypt a file using AES",
		Run:   handler.DecryptAESCmd,
	}
	decryptAESFileCmd.Flags().StringP("input-file", "", "", "Input encrypted file path")
	decryptAESFileCmd.Flags().StringP("output-file", "", "", "Path to decrypted output file")
	decryptAESFileCmd.Flags().StringP("symmetric-key", "", "", "Path to the symmetric key")
	rootCmd.AddCommand(decryptAESFileCmd)

	return nil
}
