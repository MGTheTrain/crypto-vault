package commands

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/MGTheTrain/crypto-vault/internal/domain/cryptoalg"
	"github.com/MGTheTrain/crypto-vault/internal/domain/pkcs11"
	"github.com/MGTheTrain/crypto-vault/internal/infrastructure/cryptography"
	"github.com/MGTheTrain/crypto-vault/internal/pkg/config"
	"github.com/MGTheTrain/crypto-vault/internal/pkg/logger"

	"github.com/spf13/cobra"
)

// PKCS11 environment variable names
const (
	EnvPKCS11ModulePath = "PKCS11_MODULE_PATH"
	EnvPKCS11SOPin      = "PKCS11_SO_PIN"
	EnvPKCS11UserPin    = "PKCS11_USER_PIN"
	EnvPKCS11SlotID     = "PKCS11_SLOT_ID"
)

// PKCS11CommandsHandler holds settings and methods for managing PKCS#11 token operations
type PKCS11CommandsHandler struct {
	pkcs11Handler pkcs11.Handler
	logger        logger.Logger
}

// NewPKCS11CommandsHandler initializes a new PKCS11CommandsHandler with logger and PKCS#11 config.
func NewPKCS11CommandsHandler() (*PKCS11CommandsHandler, error) {
	loggerInstance, err := setupLogger()
	if err != nil {
		return nil, fmt.Errorf("failed to setup logger: %w", err)
	}

	pkcs11Settings, err := ReadPkcs11SettingsFromEnv()
	if err != nil {
		return nil, fmt.Errorf("failed to read PKCS#11 settings: %w", err)
	}

	pkcs11Handler, err := cryptography.NewPKCS11Handler(pkcs11Settings, loggerInstance)
	if err != nil {
		return nil, fmt.Errorf("failed to create PKCS#11 handler: %w", err)
	}

	return &PKCS11CommandsHandler{
		pkcs11Handler: pkcs11Handler,
		logger:        loggerInstance,
	}, nil
}

// ReadPkcs11SettingsFromEnv reads PKCS#11 configuration from environment variables.
// Returns error listing ALL missing variables if any are not set.
func ReadPkcs11SettingsFromEnv() (*config.PKCS11Settings, error) {
	// Check all required environment variables
	envVars := map[string]string{
		EnvPKCS11ModulePath: os.Getenv(EnvPKCS11ModulePath),
		EnvPKCS11SOPin:      os.Getenv(EnvPKCS11SOPin),
		EnvPKCS11UserPin:    os.Getenv(EnvPKCS11UserPin),
		EnvPKCS11SlotID:     os.Getenv(EnvPKCS11SlotID),
	}

	// Collect all missing variables
	var missing []string
	for name, value := range envVars {
		if value == "" {
			missing = append(missing, name)
		}
	}

	// Return error with all missing variables listed
	if len(missing) > 0 {
		return nil, fmt.Errorf("missing required environment variables:%s", strings.Join(missing, ", "))
	}

	return &config.PKCS11Settings{
		ModulePath: envVars[EnvPKCS11ModulePath],
		SOPin:      envVars[EnvPKCS11SOPin],
		UserPin:    envVars[EnvPKCS11UserPin],
		SlotID:     envVars[EnvPKCS11SlotID],
	}, nil
}

// ListTokenSlotsCmd lists PKCS#11 tokens
func (h *PKCS11CommandsHandler) ListTokenSlotsCmd(_ *cobra.Command, _ []string) {
	tokens, err := h.pkcs11Handler.ListTokenSlots()
	if err != nil {
		h.logger.Error("failed to list token slots ", err)
		return
	}

	tokensJSON, err := json.MarshalIndent(tokens, "", "  ")
	if err != nil {
		h.logger.Error("failed to marshal tokens to JSON ", err)
		return
	}

	h.logger.Info(string(tokensJSON))
}

// ListObjectsSlotsCmd lists PKCS#11 token objects
func (h *PKCS11CommandsHandler) ListObjectsSlotsCmd(cmd *cobra.Command, _ []string) {
	tokenLabel, err := cmd.Flags().GetString("token-label")
	if err != nil {
		h.logger.Error("invalid token-label flag ", err)
		return
	}

	objects, err := h.pkcs11Handler.ListObjects(tokenLabel)
	if err != nil {
		h.logger.Error("failed to list objects ", err)
		return
	}

	objectsJSON, err := json.MarshalIndent(objects, "", "  ")
	if err != nil {
		h.logger.Error("failed to marshal objects to JSON ", err)
		return
	}

	h.logger.Info(string(objectsJSON))
}

// InitializeTokenCmd initializes a PKCS#11 token
func (h *PKCS11CommandsHandler) InitializeTokenCmd(cmd *cobra.Command, _ []string) {
	tokenLabel, err := cmd.Flags().GetString("token-label")
	if err != nil {
		h.logger.Error("invalid token-label flag ", err)
		return
	}

	if err := h.pkcs11Handler.InitializeToken(tokenLabel); err != nil {
		h.logger.Error("failed to initialize token ", err)
		return
	}

	h.logger.Info("Token ", tokenLabel, " initialized successfully")
}

// AddKeyCmd adds a key to the PKCS#11 token
func (h *PKCS11CommandsHandler) AddKeyCmd(cmd *cobra.Command, _ []string) {
	tokenLabel, err := cmd.Flags().GetString("token-label")
	if err != nil {
		h.logger.Error("invalid token-label flag ", err)
		return
	}

	objectLabel, err := cmd.Flags().GetString("object-label")
	if err != nil {
		h.logger.Error("invalid object-label flag ", err)
		return
	}

	keyType, err := cmd.Flags().GetString("key-type")
	if err != nil {
		h.logger.Error("invalid key-type flag ", err)
		return
	}

	keySize, err := cmd.Flags().GetUint("key-size")
	if err != nil {
		h.logger.Error("invalid key-size flag ", err)
		return
	}

	operation, err := cmd.Flags().GetString("key-operation")
	if err != nil {
		h.logger.Error("invalid key-operation flag ", err)
		return
	}

	switch operation {
	case cryptoalg.OperationSigning:
		if err := h.pkcs11Handler.AddSignKey(tokenLabel, objectLabel, keyType, keySize); err != nil {
			h.logger.Error("failed to add signing key ", err)
			return
		}
		h.logger.Info("Signing key ", objectLabel, " added successfully to token ", tokenLabel)

	case cryptoalg.OperationEncryption:
		if err := h.pkcs11Handler.AddEncryptKey(tokenLabel, objectLabel, keyType, keySize); err != nil {
			h.logger.Error("failed to add encryption key ", err)
			return
		}
		h.logger.Info("Encryption key ", objectLabel, " added successfully to token ", tokenLabel)

	default:
		h.logger.Error("invalid key-operation: ", operation, " (must be 'signing' or 'encryption')")
	}
}

// DeleteObjectCmd deletes an object (key) from the PKCS#11 token
func (h *PKCS11CommandsHandler) DeleteObjectCmd(cmd *cobra.Command, _ []string) {
	tokenLabel, err := cmd.Flags().GetString("token-label")
	if err != nil {
		h.logger.Error("invalid token-label flag ", err)
		return
	}

	objectType, err := cmd.Flags().GetString("object-type")
	if err != nil {
		h.logger.Error("invalid object-type flag ", err)
		return
	}

	objectLabel, err := cmd.Flags().GetString("object-label")
	if err != nil {
		h.logger.Error("invalid object-label flag ", err)
		return
	}

	if err := h.pkcs11Handler.DeleteObject(tokenLabel, objectType, objectLabel); err != nil {
		h.logger.Error("failed to delete object ", err)
		return
	}

	h.logger.Info("Object '%s' (type: %s) deleted successfully from token '%s'", objectLabel, objectType, tokenLabel)
}

// EncryptCmd encrypts data using the PKCS#11 token
func (h *PKCS11CommandsHandler) EncryptCmd(cmd *cobra.Command, _ []string) {
	tokenLabel, err := cmd.Flags().GetString("token-label")
	if err != nil {
		h.logger.Error("invalid token-label flag ", err)
		return
	}

	objectLabel, err := cmd.Flags().GetString("object-label")
	if err != nil {
		h.logger.Error("invalid object-label flag ", err)
		return
	}

	inputFilePath, err := cmd.Flags().GetString("input-file")
	if err != nil {
		h.logger.Error("invalid input-file flag ", err)
		return
	}

	outputFilePath, err := cmd.Flags().GetString("output-file")
	if err != nil {
		h.logger.Error("invalid output-file flag ", err)
		return
	}

	keyType, err := cmd.Flags().GetString("key-type")
	if err != nil {
		h.logger.Error("invalid key-type flag ", err)
		return
	}

	if err := h.pkcs11Handler.Encrypt(tokenLabel, objectLabel, inputFilePath, outputFilePath, keyType); err != nil {
		h.logger.Error("failed to encrypt ", err)
		return
	}

	h.logger.Info("File encrypted successfully: %s", outputFilePath)
}

// DecryptCmd decrypts data using the PKCS#11 token
func (h *PKCS11CommandsHandler) DecryptCmd(cmd *cobra.Command, _ []string) {
	tokenLabel, err := cmd.Flags().GetString("token-label")
	if err != nil {
		h.logger.Error("invalid token-label flag ", err)
		return
	}

	objectLabel, err := cmd.Flags().GetString("object-label")
	if err != nil {
		h.logger.Error("invalid object-label flag ", err)
		return
	}

	inputFilePath, err := cmd.Flags().GetString("input-file")
	if err != nil {
		h.logger.Error("invalid input-file flag ", err)
		return
	}

	outputFilePath, err := cmd.Flags().GetString("output-file")
	if err != nil {
		h.logger.Error("invalid output-file flag ", err)
		return
	}

	keyType, err := cmd.Flags().GetString("key-type")
	if err != nil {
		h.logger.Error("invalid key-type flag ", err)
		return
	}

	if err := h.pkcs11Handler.Decrypt(tokenLabel, objectLabel, inputFilePath, outputFilePath, keyType); err != nil {
		h.logger.Error("failed to decrypt ", err)
		return
	}

	h.logger.Info("File decrypted successfully: %s", outputFilePath)
}

// SignCmd signs data using the PKCS#11 token
func (h *PKCS11CommandsHandler) SignCmd(cmd *cobra.Command, _ []string) {
	tokenLabel, err := cmd.Flags().GetString("token-label")
	if err != nil {
		h.logger.Error("invalid token-label flag ", err)
		return
	}

	objectLabel, err := cmd.Flags().GetString("object-label")
	if err != nil {
		h.logger.Error("invalid object-label flag ", err)
		return
	}

	dataFilePath, err := cmd.Flags().GetString("data-file")
	if err != nil {
		h.logger.Error("invalid data-file flag ", err)
		return
	}

	signatureFilePath, err := cmd.Flags().GetString("signature-file")
	if err != nil {
		h.logger.Error("invalid signature-file flag ", err)
		return
	}

	keyType, err := cmd.Flags().GetString("key-type")
	if err != nil {
		h.logger.Error("invalid key-type flag ", err)
		return
	}

	if err := h.pkcs11Handler.Sign(tokenLabel, objectLabel, dataFilePath, signatureFilePath, keyType); err != nil {
		h.logger.Error("failed to sign ", err)
		return
	}

	h.logger.Info("File signed successfully: %s", signatureFilePath)
}

// VerifyCmd verifies the signature using the PKCS#11 token
func (h *PKCS11CommandsHandler) VerifyCmd(cmd *cobra.Command, _ []string) {
	tokenLabel, err := cmd.Flags().GetString("token-label")
	if err != nil {
		h.logger.Error("invalid token-label flag ", err)
		return
	}

	objectLabel, err := cmd.Flags().GetString("object-label")
	if err != nil {
		h.logger.Error("invalid object-label flag ", err)
		return
	}

	dataFilePath, err := cmd.Flags().GetString("data-file")
	if err != nil {
		h.logger.Error("invalid data-file flag ", err)
		return
	}

	signatureFilePath, err := cmd.Flags().GetString("signature-file")
	if err != nil {
		h.logger.Error("invalid signature-file flag ", err)
		return
	}

	keyType, err := cmd.Flags().GetString("key-type")
	if err != nil {
		h.logger.Error("invalid key-type flag ", err)
		return
	}

	valid, err := h.pkcs11Handler.Verify(tokenLabel, objectLabel, dataFilePath, signatureFilePath, keyType)
	if err != nil {
		h.logger.Error("failed to verify signature ", err)
		return
	}

	if valid {
		h.logger.Info("Signature is VALID")
	} else {
		h.logger.Info("Signature is INVALID")
	}
}

// InitPKCS11Commands initializes all the PKCS#11 commands
func InitPKCS11Commands(rootCmd *cobra.Command) error {
	handler, err := NewPKCS11CommandsHandler()
	if err != nil {
		return fmt.Errorf("failed to create PKCS#11 command handler: %w", err)
	}

	// Initialize token command
	initTokenCmd := &cobra.Command{
		Use:   "initialize-token",
		Short: "Initialize a PKCS#11 token",
		Run:   handler.InitializeTokenCmd,
	}
	initTokenCmd.Flags().String("token-label", "", "Label of the PKCS#11 token")
	rootCmd.AddCommand(initTokenCmd)

	// List slots command
	listSlotsCmd := &cobra.Command{
		Use:   "list-slots",
		Short: "List PKCS#11 token slots",
		Run:   handler.ListTokenSlotsCmd,
	}
	rootCmd.AddCommand(listSlotsCmd)

	// List objects command
	listObjectsCmd := &cobra.Command{
		Use:   "list-objects",
		Short: "List PKCS#11 token objects",
		Run:   handler.ListObjectsSlotsCmd,
	}
	listObjectsCmd.Flags().String("token-label", "", "Label of the PKCS#11 token")
	rootCmd.AddCommand(listObjectsCmd)

	// Add key command
	addKeyCmd := &cobra.Command{
		Use:   "add-key",
		Short: "Add key (ECDSA or RSA) to the PKCS#11 token",
		Run:   handler.AddKeyCmd,
	}
	addKeyCmd.Flags().String("token-label", "", "Label of the PKCS#11 token")
	addKeyCmd.Flags().String("object-label", "", "Label of the object (key)")
	addKeyCmd.Flags().String("key-type", "", "Type of the key (ECDSA or RSA)")
	addKeyCmd.Flags().Uint("key-size", 0, "Key size in bits (2048 for RSA, 256 for ECDSA)")
	addKeyCmd.Flags().String("key-operation", "", "Key operation type: 'signing' or 'encryption'")
	rootCmd.AddCommand(addKeyCmd)

	// Delete object command
	deleteObjectCmd := &cobra.Command{
		Use:   "delete-object",
		Short: "Delete an object (key) from the PKCS#11 token",
		Run:   handler.DeleteObjectCmd,
	}
	deleteObjectCmd.Flags().String("token-label", "", "Label of the PKCS#11 token")
	deleteObjectCmd.Flags().String("object-label", "", "Label of the object to delete")
	deleteObjectCmd.Flags().String("object-type", "", "Type of the object (e.g., privkey, pubkey, cert)")
	rootCmd.AddCommand(deleteObjectCmd)

	// Encrypt command
	encryptCmd := &cobra.Command{
		Use:   "encrypt",
		Short: "Encrypt data using a PKCS#11 token",
		Run:   handler.EncryptCmd,
	}
	encryptCmd.Flags().String("token-label", "", "Label of the PKCS#11 token")
	encryptCmd.Flags().String("object-label", "", "Label of the object (key) for encryption")
	encryptCmd.Flags().String("key-type", "", "Type of the key (ECDSA or RSA)")
	encryptCmd.Flags().String("input-file", "", "Path to the unencrypted input file")
	encryptCmd.Flags().String("output-file", "", "Path to encrypted output file")
	rootCmd.AddCommand(encryptCmd)

	// Decrypt command
	decryptCmd := &cobra.Command{
		Use:   "decrypt",
		Short: "Decrypt data using a PKCS#11 token",
		Run:   handler.DecryptCmd,
	}
	decryptCmd.Flags().String("token-label", "", "Label of the PKCS#11 token")
	decryptCmd.Flags().String("object-label", "", "Label of the object (key) for decryption")
	decryptCmd.Flags().String("key-type", "", "Type of the key (ECDSA or RSA)")
	decryptCmd.Flags().String("input-file", "", "Path to the encrypted input file")
	decryptCmd.Flags().String("output-file", "", "Path to decrypted output file")
	rootCmd.AddCommand(decryptCmd)

	// Sign command
	signCmd := &cobra.Command{
		Use:   "sign",
		Short: "Sign data using a PKCS#11 token",
		Run:   handler.SignCmd,
	}
	signCmd.Flags().String("token-label", "", "Label of the PKCS#11 token")
	signCmd.Flags().String("object-label", "", "Label of the object (key) for signing")
	signCmd.Flags().String("key-type", "", "Type of the key (ECDSA or RSA)")
	signCmd.Flags().String("data-file", "", "Path to the input file to be signed")
	signCmd.Flags().String("signature-file", "", "Path to store the signature output file")
	rootCmd.AddCommand(signCmd)

	// Verify command
	verifyCmd := &cobra.Command{
		Use:   "verify",
		Short: "Verify the signature using a PKCS#11 token",
		Run:   handler.VerifyCmd,
	}
	verifyCmd.Flags().String("token-label", "", "Label of the PKCS#11 token")
	verifyCmd.Flags().String("object-label", "", "Label of the object (key) for signature verification")
	verifyCmd.Flags().String("key-type", "", "Type of the key (ECDSA or RSA)")
	verifyCmd.Flags().String("data-file", "", "Path to the input file to verify the signature")
	verifyCmd.Flags().String("signature-file", "", "Path to the signature file used for signature verifying")
	rootCmd.AddCommand(verifyCmd)

	return nil
}
