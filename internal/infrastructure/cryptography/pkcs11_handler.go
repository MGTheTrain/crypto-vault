package cryptography

import (
	"crypto_vault_service/internal/domain/crypto"
	"crypto_vault_service/internal/pkg/config"
	"crypto_vault_service/internal/pkg/logger"
	"crypto_vault_service/internal/pkg/utils"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
)

// pkcs11Handler represents the parameters and operations for interacting with a PKCS#11 token
type pkcs11Handler struct {
	settings *config.PKCS11Settings
	logger   logger.Logger
}

// NewPKCS11Handler creates and returns a new instance of PKCS11Handler
func NewPKCS11Handler(settings *config.PKCS11Settings, logger logger.Logger) (crypto.PKCS11Handler, error) {
	if err := settings.Validate(); err != nil {
		return nil, fmt.Errorf("failed to validate settings: %w", err)
	}

	return &pkcs11Handler{
		settings: settings,
		logger:   logger,
	}, nil
}

// Private method to execute pkcs11-tool commands and return output
func (token *pkcs11Handler) executePKCS11ToolCommand(args []string) (string, error) {
	cmd := exec.Command("pkcs11-tool", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("pkcs11-tool command failed: %w\nOutput: %s", err, output)
	}
	return string(output), nil
}

// ListTokenSlots lists all available tokens in the available slots
func (token *pkcs11Handler) ListTokenSlots() ([]crypto.Token, error) {
	if err := utils.CheckNonEmptyStrings(token.settings.ModulePath); err != nil {
		return nil, fmt.Errorf("failed to check non-empty string for ModulePath='%s': %w", token.settings.ModulePath, err)
	}

	// #nosec G204 -- TODO(MGTheTrain) validate all inputs used in exec.Command
	listCmd := exec.Command(
		"pkcs11-tool", "--module", token.settings.ModulePath, "-L",
	)

	output, err := listCmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("failed to list tokens with pkcs11-tool: %w\nOutput: %s", err, output)
	}

	var tokens []crypto.Token
	lines := strings.Split(string(output), "\n")
	var currentToken *crypto.Token

	for _, line := range lines {

		if strings.Contains(line, "Slot") {
			if currentToken != nil {
				tokens = append(tokens, *currentToken)
			}

			currentToken = &crypto.Token{
				SlotID:       "",
				Label:        "",
				Manufacturer: "",
				Model:        "",
				SerialNumber: "",
			}

			re := regexp.MustCompile(`\((0x[0-9a-fA-F]+)\)`) // e.g. `(0x39e9d82d)` in `Slot 1 (0x39e9d82d): SoftHSM slot ID 0x39e9d82d`
			matches := re.FindStringSubmatch(line)
			currentToken.SlotID = matches[1]
		}

		if strings.Contains(line, "token label") {
			currentToken.Label = strings.TrimSpace(strings.Split(line, ":")[1])
		}
		if currentToken != nil {
			if strings.Contains(line, "token manufacturer") {
				currentToken.Manufacturer = strings.TrimSpace(strings.Split(line, ":")[1])
			}
			if strings.Contains(line, "token model") {
				currentToken.Model = strings.TrimSpace(strings.Split(line, ":")[1])
			}
			if strings.Contains(line, "serial num") {
				currentToken.SerialNumber = strings.TrimSpace(strings.Split(line, ":")[1])
			}
		}
	}

	if currentToken != nil {
		tokens = append(tokens, *currentToken)
	}

	return tokens, nil
}

// ListObjects lists all objects (e.g. keys) in a specific token based on the token label.
func (token *pkcs11Handler) ListObjects(tokenLabel string) ([]crypto.TokenObject, error) {
	if err := utils.CheckNonEmptyStrings(tokenLabel, token.settings.ModulePath); err != nil {
		return nil, fmt.Errorf("failed to check non-empty strings for tokenLabel='%s' and ModulePath='%s': %w", tokenLabel, token.settings.ModulePath, err)
	}

	// #nosec G204 -- TODO(MGTheTrain) validate all inputs used in exec.Command
	listObjectsCmd := exec.Command(
		"pkcs11-tool", "--module", token.settings.ModulePath, "-O", "--token-label", tokenLabel, "--pin", token.settings.UserPin,
	)

	output, err := listObjectsCmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("failed to list objects with pkcs11-tool: %w\nOutput: %s", err, output)
	}

	var objects []crypto.TokenObject
	lines := strings.Split(string(output), "\n")
	var currentObject *crypto.TokenObject

	for _, line := range lines {

		if strings.Contains(line, "Private") || strings.Contains(line, "Public") || strings.Contains(line, "Secret") {
			if currentObject != nil {
				objects = append(objects, *currentObject)
			}

			currentObject = &crypto.TokenObject{
				Label:  "",
				Type:   "",
				Usage:  "",
				Access: "",
			}
			currentObject.Type = line
		}
		if strings.Contains(line, "label:") {
			currentObject.Label = strings.TrimSpace(strings.Split(line, ":")[1])
		}
		if strings.Contains(line, "Usage:") {
			currentObject.Usage = strings.TrimSpace(strings.Split(line, ":")[1])
		}
		if strings.Contains(line, "Access:") {
			currentObject.Access = strings.TrimSpace(strings.Split(line, ":")[1])
		}
	}

	if currentObject != nil {
		objects = append(objects, *currentObject)
	}

	return objects, nil
}

// isTokenSet checks if the token exists in the given module path
func (token *pkcs11Handler) isTokenSet(label string) (bool, error) {
	if err := utils.CheckNonEmptyStrings(label); err != nil {
		return false, fmt.Errorf("failed to check non-empty string for label='%s': %w", label, err)
	}

	args := []string{"--module", token.settings.ModulePath, "-T"}
	output, err := token.executePKCS11ToolCommand(args)
	if err != nil {
		return false, fmt.Errorf("failed to execute PKCS#11 tool command with args=%v: %w", args, err)
	}

	if strings.Contains(output, label) && strings.Contains(output, "token initialized") {
		token.logger.Info("Token with label ", label, " exists")
		return true, nil
	}

	token.logger.Info("Token with label ", label, " does not exist")
	return false, nil
}

// InitializeToken initializes the token with the provided label and pins
func (token *pkcs11Handler) InitializeToken(label string) error {
	if err := utils.CheckNonEmptyStrings(label); err != nil {
		return fmt.Errorf("failed to check non-empty string for label='%s': %w", label, err)
	}

	tokenExists, err := token.isTokenSet(label)
	if err != nil {
		return fmt.Errorf("failed to check if token is set for label='%s': %w", label, err)
	}

	if tokenExists {
		return nil
	}

	args := []string{"--module", token.settings.ModulePath, "--init-token", "--label", label, "--so-pin", token.settings.SOPin, "--init-pin", "--pin", token.settings.UserPin, "--slot", token.settings.SlotID}
	_, err = token.executePKCS11ToolCommand(args)
	if err != nil {
		return fmt.Errorf("failed to initialize token with label '%s': %w", label, err)
	}

	token.logger.Info("Token with label ", label, " initialized successfully")
	return nil
}

// AddSignKey adds a signing key (ECDSA or RSA) to the token
func (token *pkcs11Handler) AddSignKey(label, objectLabel, keyType string, keySize uint) error {
	if err := utils.CheckNonEmptyStrings(label, objectLabel, keyType); err != nil {
		return fmt.Errorf("failed to check non-empty strings for label='%s', objectLabel='%s', keyType='%s': %w", label, objectLabel, keyType, err)
	}

	switch keyType {
	case "ECDSA":
		return token.addECDSASignKey(label, objectLabel, keySize)
	case "RSA":
		return token.addRSASignKey(label, objectLabel, keySize)
	default:
		return fmt.Errorf("unsupported key type: %s", keyType)
	}
}

// AddEncryptKey adds an encryption key (RSA only currently) to the token
func (token *pkcs11Handler) AddEncryptKey(label, objectLabel, keyType string, keySize uint) error {
	if err := utils.CheckNonEmptyStrings(label, objectLabel, keyType); err != nil {
		return fmt.Errorf("failed to check non-empty strings for label='%s', objectLabel='%s', keyType='%s': %w", label, objectLabel, keyType, err)
	}

	// Currently only RSA is supported for encryption
	if keyType != "RSA" {
		return fmt.Errorf("only RSA keys are supported for encryption, got: %s", keyType)
	}

	return token.addRSAEncryptKey(label, objectLabel, keySize)
}

// addECDSASignKey adds an ECDSA signing key to the token
func (token *pkcs11Handler) addECDSASignKey(label, objectLabel string, keySize uint) error {
	if err := utils.CheckNonEmptyStrings(label, objectLabel); err != nil {
		return fmt.Errorf("failed to check non-empty strings for label='%s' and objectLabel='%s': %w", label, objectLabel, err)
	}

	// Generate the key pair (example using secp256r1)
	// Supported ECDSA key sizes and their corresponding elliptic curves
	ecdsaCurves := map[uint]string{
		256: "secp256r1",
		384: "secp384r1",
		521: "secp521r1",
	}

	curve, supported := ecdsaCurves[keySize]
	if !supported {
		return fmt.Errorf("ECDSA key size must be one of 256, 384, or 521 bits, but got %d", keySize)
	}

	args := []string{
		"--module", token.settings.ModulePath,
		"--token-label", label,
		"--keypairgen",
		"--key-type", fmt.Sprintf("EC:%s", curve), // Use the dynamically selected curve
		"--label", objectLabel,
		"--pin", token.settings.UserPin,
		"--usage-sign",
	}

	_, err := token.executePKCS11ToolCommand(args)
	if err != nil {
		return fmt.Errorf("failed to add ECDSA key to token: %w", err)
	}

	token.logger.Info("ECDSA key with label", label, " added to token ", objectLabel)
	return nil
}

// addRSASignKey adds an RSA signing key to the token
func (token *pkcs11Handler) addRSASignKey(label, objectLabel string, keySize uint) error {
	if err := utils.CheckNonEmptyStrings(label, objectLabel); err != nil {
		return fmt.Errorf("failed to check non-empty strings for label='%s' and objectLabel='%s': %w", label, objectLabel, err)
	}

	// Supported RSA key sizes (for example, 2048, 3072, and 4096)
	supportedRSASizes := []uint{2048, 3072, 4096}

	validKeySize := false
	for _, size := range supportedRSASizes {
		if keySize == size {
			validKeySize = true
			break
		}
	}

	if !validKeySize {
		return fmt.Errorf("RSA key size must be one of %v bits, but got %d", supportedRSASizes, keySize)
	}

	args := []string{
		"--module", token.settings.ModulePath,
		"--token-label", label,
		"--keypairgen",
		"--key-type", fmt.Sprintf("RSA:%d", keySize),
		"--label", objectLabel,
		"--pin", token.settings.UserPin,
		"--usage-sign",
	}
	_, err := token.executePKCS11ToolCommand(args)
	if err != nil {
		return fmt.Errorf("failed to add RSA key to token: %w", err)
	}

	token.logger.Info("RSA key with label ", label, " added to token ", objectLabel)
	return nil
}

// addRSAEncryptKey adds an RSA encryption/decryption key to the token
func (token *pkcs11Handler) addRSAEncryptKey(label, objectLabel string, keySize uint) error {
	if err := utils.CheckNonEmptyStrings(label, objectLabel); err != nil {
		return fmt.Errorf("failed to check non-empty strings for label='%s' and objectLabel='%s': %w", label, objectLabel, err)
	}

	supportedRSASizes := []uint{2048, 3072, 4096}
	validKeySize := false
	for _, size := range supportedRSASizes {
		if keySize == size {
			validKeySize = true
			break
		}
	}

	if !validKeySize {
		return fmt.Errorf("RSA key size must be one of %v bits, but got %d", supportedRSASizes, keySize)
	}

	args := []string{
		"--module", token.settings.ModulePath,
		"--token-label", label,
		"--keypairgen",
		"--key-type", fmt.Sprintf("RSA:%d", keySize),
		"--label", objectLabel,
		"--pin", token.settings.UserPin,
		"--usage-decrypt",
	}
	_, err := token.executePKCS11ToolCommand(args)
	if err != nil {
		return fmt.Errorf("failed to add RSA encryption key to token: %w", err)
	}

	token.logger.Info("RSA encryption key with label ", label, " added to token ", objectLabel)
	return nil
}

// Encrypt encrypts data using the cryptographic capabilities of the PKCS#11 token. Refer to: https://docs.yubico.com/hardware/yubihsm-2/hsm-2-user-guide/hsm2-openssl-libp11.html#rsa-pkcs
func (token *pkcs11Handler) Encrypt(label, objectLabel, inputFilePath, outputFilePath, keyType string) error {
	if err := utils.CheckNonEmptyStrings(label, objectLabel, inputFilePath, outputFilePath, keyType); err != nil {
		return fmt.Errorf("failed to check non-empty strings for label='%s', objectLabel='%s', inputFilePath='%s', outputFilePath='%s', keyType='%s': %w",
			label, objectLabel, inputFilePath, outputFilePath, keyType, err)
	}

	if err := utils.CheckFilesExist(inputFilePath); err != nil {
		return fmt.Errorf("failed to check if input file exists (inputFilePath='%s'): %w", inputFilePath, err)
	}

	if keyType != "RSA" {
		return fmt.Errorf("only RSA keys are supported for encryption")
	}

	// Prepare the URI to use PKCS#11 engine for accessing the public key
	keyURI := fmt.Sprintf("pkcs11:token=%s;object=%s;type=public;pin-value=%s", label, objectLabel, token.settings.UserPin)

	// Run OpenSSL command to encrypt using the public key from the PKCS#11 token
	// #nosec G204 -- TODO(MGTheTrain) validate all inputs used in exec.Command
	encryptCmd := exec.Command(
		"openssl", "pkeyutl", "-engine", "pkcs11", "-keyform", "engine", "-pubin", "-encrypt",
		"-inkey", keyURI, "-pkeyopt", "rsa_padding_mode:pkcs1", "-in", inputFilePath, "-out", outputFilePath,
	)

	// Execute the encryption command
	encryptOutput, err := encryptCmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to encrypt data with OpenSSL: %w\nOutput: %s", err, encryptOutput)
	}

	token.logger.Info("Encryption successful. Encrypted data written to ", outputFilePath)
	return nil
}

// Decrypt decrypts data using the cryptographic capabilities of the PKCS#11 token. Refer to: https://docs.yubico.com/hardware/yubihsm-2/hsm-2-user-guide/hsm2-openssl-libp11.html#rsa-pkcs
func (token *pkcs11Handler) Decrypt(label, objectLabel, inputFilePath, outputFilePath, keyType string) error {
	if err := utils.CheckNonEmptyStrings(label, objectLabel, inputFilePath, outputFilePath, keyType); err != nil {
		return fmt.Errorf("failed to check non-empty strings for label='%s', objectLabel='%s', inputFilePath='%s', outputFilePath='%s', keyType='%s': %w",
			label, objectLabel, inputFilePath, outputFilePath, keyType, err)
	}

	if err := utils.CheckFilesExist(inputFilePath); err != nil {
		return fmt.Errorf("failed to check if input file exists (inputFilePath='%s'): %w", inputFilePath, err)
	}

	if keyType != "RSA" {
		return fmt.Errorf("only RSA keys are supported for decryption")
	}

	// Prepare the URI to use PKCS#11 engine for accessing the private key
	keyURI := fmt.Sprintf("pkcs11:token=%s;object=%s;type=private;pin-value=%s", label, objectLabel, token.settings.UserPin)

	// Run OpenSSL command to decrypt the data using the private key from the PKCS#11 token
	// #nosec G204 -- TODO(MGTheTrain) validate all inputs used in exec.Command
	decryptCmd := exec.Command(
		"openssl", "pkeyutl", "-engine", "pkcs11", "-keyform", "engine", "-decrypt",
		"-inkey", keyURI, "-pkeyopt", "rsa_padding_mode:pkcs1", "-in", inputFilePath, "-out", outputFilePath,
	)

	// Execute the decryption command
	decryptOutput, err := decryptCmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to decrypt data with OpenSSL: %w\nOutput: %s", err, decryptOutput)
	}

	token.logger.Info("Decryption successful. Decrypted data written to ", outputFilePath)
	return nil
}

// Sign signs data using the cryptographic capabilities of the PKCS#11 token. Refer to: https://docs.yubico.com/hardware/yubihsm-2/hsm-2-user-guide/hsm2-openssl-libp11.html#rsa-pss
func (token *pkcs11Handler) Sign(label, objectLabel, dataFilePath, signatureFilePath, keyType string) error {
	if err := utils.CheckNonEmptyStrings(label, objectLabel, dataFilePath, signatureFilePath, keyType); err != nil {
		return fmt.Errorf("failed to check non-empty strings for label='%s', objectLabel='%s', dataFilePath='%s', signatureFilePath='%s', keyType='%s': %w",
			label, objectLabel, dataFilePath, signatureFilePath, keyType, err)
	}

	if err := utils.CheckFilesExist(dataFilePath); err != nil {
		return fmt.Errorf("failed to check if file exists (dataFilePath='%s'): %w", dataFilePath, err)
	}

	if keyType != "RSA" && keyType != "ECDSA" {
		return fmt.Errorf("only RSA and ECDSA keys are supported for signing")
	}

	// Prepare the OpenSSL command based on key type
	var signCmd *exec.Cmd
	var signatureFormat string

	switch keyType {
	case "RSA":
		signatureFormat = "rsa_padding_mode:pss"
		// Command for signing with RSA-PSS
		// #nosec G204 -- TODO(MGTheTrain) validate all inputs used in exec.Command
		signCmd = exec.Command(
			"openssl", "dgst", "-engine", "pkcs11", "-keyform", "engine", "-sign",
			"pkcs11:token="+label+";object="+objectLabel+";type=private;pin-value="+token.settings.UserPin,
			"-sigopt", signatureFormat,
			"-sha384", // Use SHA-384
			"-out", signatureFilePath, dataFilePath,
		)
	case "ECDSA":
		// Command for signing with ECDSA
		// #nosec G204 -- TODO(MGTheTrain) validate all inputs used in exec.Command
		signCmd = exec.Command(
			"openssl", "dgst", "-engine", "pkcs11", "-keyform", "engine", "-sign",
			"pkcs11:token="+label+";object="+objectLabel+";type=private;pin-value="+token.settings.UserPin,
			"-sha384", // ECDSA typically uses SHA-384
			"-out", signatureFilePath, dataFilePath,
		)
	default:
		return fmt.Errorf("unsupported key type: %s", keyType)
	}

	// Execute the sign command
	signOutput, err := signCmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to sign data: %w\nOutput: %s", err, signOutput)
	}

	token.logger.Info("Signing successful. Signature written to ", signatureFilePath)
	return nil
}

// Verify verifies the signature of data using the cryptographic capabilities of the PKCS#11 token. Refer to: https://docs.yubico.com/hardware/yubihsm-2/hsm-2-user-guide/hsm2-openssl-libp11.html#rsa-pss
func (token *pkcs11Handler) Verify(label, objectLabel, dataFilePath, signatureFilePath, keyType string) (bool, error) {

	if err := utils.CheckNonEmptyStrings(label, objectLabel, keyType, dataFilePath, signatureFilePath); err != nil {
		return false, fmt.Errorf("failed to check non-empty strings for label='%s', objectLabel='%s', keyType='%s', dataFilePath='%s', signatureFilePath='%s': %w",
			label, objectLabel, keyType, dataFilePath, signatureFilePath, err)
	}

	if err := utils.CheckFilesExist(dataFilePath, signatureFilePath); err != nil {
		return false, fmt.Errorf("failed to check if files exist (dataFilePath='%s', signatureFilePath='%s'): %w",
			dataFilePath, signatureFilePath, err)
	}

	if keyType != "RSA" && keyType != "ECDSA" {
		return false, fmt.Errorf("only RSA and ECDSA keys are supported for verification")
	}

	// Prepare the OpenSSL command based on key type
	var verifyCmd *exec.Cmd

	switch keyType {
	case "RSA":
		// Command for verifying with RSA-PSS
		// #nosec G204 -- TODO(MGTheTrain) validate all inputs used in exec.Command
		verifyCmd = exec.Command(
			"openssl", "dgst", "-engine", "pkcs11", "-keyform", "engine", "-verify",
			"pkcs11:token="+label+";object="+objectLabel+";type=public;pin-value="+token.settings.UserPin,
			"-sigopt", "rsa_padding_mode:pss",
			"-sha384", // Use SHA-384 for verification
			"-signature", signatureFilePath, "-binary", dataFilePath,
		)
	case "ECDSA":
		// Command for verifying with ECDSA
		// #nosec G204 -- TODO(MGTheTrain) validate all inputs used in exec.Command
		verifyCmd = exec.Command(
			"openssl", "dgst", "-engine", "pkcs11", "-keyform", "engine", "-verify",
			"pkcs11:token="+label+";object="+objectLabel+";type=public;pin-value="+token.settings.UserPin,
			"-sha384", // ECDSA typically uses SHA-384
			"-signature", signatureFilePath, "-binary", dataFilePath,
		)
	default:
		return false, fmt.Errorf("unsupported key type: %s", keyType)
	}

	// Execute the verify command
	verifyOutput, err := verifyCmd.CombinedOutput()
	if err != nil {
		return false, fmt.Errorf("failed to verify signature: %w\nOutput: %s", err, verifyOutput)
	}

	// Check the output from OpenSSL to determine if the verification was successful
	if strings.Contains(string(verifyOutput), "Verified OK") {
		token.logger.Info("The signature is valid")
		return true, nil
	}
	token.logger.Info("The signature is invalid")
	return false, nil
}

// DeleteObject deletes a key or object from the token
func (token *pkcs11Handler) DeleteObject(label, objectType, objectLabel string) error {
	if err := utils.CheckNonEmptyStrings(label, objectType, objectLabel); err != nil {
		return fmt.Errorf("failed to check non-empty strings for label='%s', objectType='%s', objectLabel='%s': %w", label, objectType, objectLabel, err)
	}

	// Ensure the object type is valid (privkey, pubkey, secrkey, cert, data)
	validObjectTypes := map[string]bool{
		"privkey": true,
		"pubkey":  true,
		"secrkey": true,
		"cert":    true,
		"data":    true,
	}

	if !validObjectTypes[objectType] {
		return fmt.Errorf("invalid object type '%s'. Valid types are privkey, pubkey, secrkey, cert, data", objectType)
	}

	args := []string{
		"--module", token.settings.ModulePath,
		"--token-label", label,
		"--pin", token.settings.UserPin,
		"--delete-object",
		"--type", objectType,
		"--label", objectLabel,
	}

	_, err := token.executePKCS11ToolCommand(args)
	if err != nil {
		return fmt.Errorf("failed to delete object of type '%s' with label '%s': %w", objectType, objectLabel, err)
	}

	token.logger.Info("Object of type ", objectType, " with object label ", objectLabel, " deleted successfully")
	return nil
}
