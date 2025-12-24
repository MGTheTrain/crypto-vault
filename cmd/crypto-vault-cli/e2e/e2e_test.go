//go:build e2e
// +build e2e

package e2e

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"testing"
)

func ensurePKCS11Settings(t *testing.T) {
	// Set the default environment variables for PKCS#11 settings
	os.Setenv("PKCS11_MODULE_PATH", "/usr/lib/softhsm/libsofthsm2.so")
	os.Setenv("PKCS11_SO_PIN", "1234")
	os.Setenv("PKCS11_USER_PIN", "5678")
	os.Setenv("PKCS11_SLOT_ID", "0x0")

	// Optionally, you can log these values to verify they are being set
	t.Log("Environment variables for PKCS#11 are set:")
	t.Log("PKCS11_MODULE_PATH =", os.Getenv("PKCS11_MODULE_PATH"))
	t.Log("PKCS11_SO_PIN =", os.Getenv("PKCS11_SO_PIN"))
	t.Log("PKCS11_USER_PIN =", os.Getenv("PKCS11_USER_PIN"))
	t.Log("PKCS11_SLOT_ID =", os.Getenv("PKCS11_SLOT_ID"))
}

func runCommand(t *testing.T, cmd string, args []string) (string, error) {
	command := exec.Command(cmd, args...)
	var out bytes.Buffer
	command.Stdout = &out
	command.Stderr = &out

	err := command.Run()
	if err != nil {
		t.Fatalf("Command failed: %v\nOutput: %v", err, out.String())
		return "", err
	}

	return out.String(), nil
}

func TestAESEncryptionAndDecryption(t *testing.T) {
	uuid := "test-uuid-1234"
	inputFile := "data/input.txt"

	encOutputFile := fmt.Sprintf("data/%s-output.enc", uuid)
	cmdEncrypt := "go"
	argsEncrypt := []string{"run", "../main.go", "encrypt-aes", "--input-file", inputFile, "--output-file", encOutputFile, "--symmetric-key", "your-generated-symmetric-key"}

	_, err := runCommand(t, cmdEncrypt, argsEncrypt)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	decOutputFile := fmt.Sprintf("data/%s-decrypted.txt", uuid)
	cmdDecrypt := "go"
	argsDecrypt := []string{"run", "../main.go", "decrypt-aes", "--input-file", encOutputFile, "--output-file", decOutputFile, "--symmetric-key", "your-generated-symmetric-key"}

	_, err = runCommand(t, cmdDecrypt, argsDecrypt)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}
}

func TestRSAEncryptionAndDecryption(t *testing.T) {
	uuid := "test-uuid-5678"
	inputFile := "data/input.txt"

	encOutputFile := fmt.Sprintf("data/%s-encrypted.txt", uuid)
	cmdEncryptRSA := "go"
	argsEncryptRSA := []string{"run", "../main.go", "encrypt-rsa", "--input-file", inputFile, "--output-file", encOutputFile, "--public-key", "your-generated-public-key"}

	_, err := runCommand(t, cmdEncryptRSA, argsEncryptRSA)
	if err != nil {
		t.Fatalf("RSA Encryption failed: %v", err)
	}

	decOutputFile := fmt.Sprintf("data/%s-decrypted.txt", uuid)
	cmdDecryptRSA := "go"
	argsDecryptRSA := []string{"run", "../main.go", "decrypt-rsa", "--input-file", encOutputFile, "--output-file", decOutputFile, "--private-key", "your-generated-private-key"}

	_, err = runCommand(t, cmdDecryptRSA, argsDecryptRSA)
	if err != nil {
		t.Fatalf("RSA Decryption failed: %v", err)
	}
}

func TestRSASignAndVerify(t *testing.T) {
	uuid := "test-uuid-5678"
	inputFile := "data/input.txt"
	signatureFile := fmt.Sprintf("data/%s-signature.bin", uuid)

	// Sign
	cmdSignRSA := "go"
	argsSignRSA := []string{"run", "../main.go", "sign-rsa", "--input-file", inputFile, "--output-file", signatureFile, "--private-key", "your-generated-private-key"}

	_, err := runCommand(t, cmdSignRSA, argsSignRSA)
	if err != nil {
		t.Fatalf("RSA Signing failed: %v", err)
	}

	// Verify
	cmdVerifyRSA := "go"
	argsVerifyRSA := []string{
		"run", "../main.go", "verify-rsa", "--input-file", inputFile, "--signature-file", signatureFile, "--public-key", "your-generated-public-key",
	}

	_, err = runCommand(t, cmdVerifyRSA, argsVerifyRSA)
	if err != nil {
		t.Fatalf("RSA Verification failed: %v", err)
	}
}

func TestSigningAndVerificationECDSA(t *testing.T) {
	uuid := "test-uuid-ecc"
	inputFile := "data/input.txt"
	signatureFile := fmt.Sprintf("data/%s-signature.bin", uuid)

	// Sign
	cmdSignECDSA := "go"
	argsSignECDSA := []string{"run", "../main.go", "sign-ecc", "--input-file", inputFile, "--output-file", signatureFile, "--private-key", "your-generated-private-key"}

	_, err := runCommand(t, cmdSignECDSA, argsSignECDSA)
	if err != nil {
		t.Fatalf("ECDSA Signing failed: %v", err)
	}

	// Verify
	cmdVerifyECDSA := "go"
	argsVerifyECDSA := []string{
		"run", "../main.go", "verify-ecc", "--input-file", inputFile, "--signature-file", signatureFile, "--public-key", "your-generated-public-key",
	}

	_, err = runCommand(t, cmdVerifyECDSA, argsVerifyECDSA)
	if err != nil {
		t.Fatalf("ECDSA Verification failed: %v", err)
	}
}

func TestPKCS11EncryptionAndDecryption(t *testing.T) {
	ensurePKCS11Settings(t)
	uuid := "test-uuid-pkcs11"
	inputFile := "data/input.txt"

	encOutputFile := fmt.Sprintf("data/%s-encrypted-output.enc", uuid)
	cmdEncryptPKCS11 := "go"
	argsEncryptPKCS11 := []string{
		"run", "../main.go", "encrypt", "--token-label", "my-token", "--object-label", "my-rsa-key", "--key-type", "RSA", "--input-file", inputFile, "--output-file", encOutputFile,
	}

	_, err := runCommand(t, cmdEncryptPKCS11, argsEncryptPKCS11)
	if err != nil {
		t.Fatalf("PKCS11 Encryption failed: %v", err)
	}

	decOutputFile := fmt.Sprintf("data/%s-decrypted-output.txt", uuid)
	cmdDecryptPKCS11 := "go"
	argsDecryptPKCS11 := []string{
		"run", "../main.go", "decrypt", "--token-label", "my-token", "--object-label", "my-rsa-key", "--key-type", "RSA", "--input-file", encOutputFile, "--output-file", decOutputFile,
	}

	_, err = runCommand(t, cmdDecryptPKCS11, argsDecryptPKCS11)
	if err != nil {
		t.Fatalf("PKCS11 Decryption failed: %v", err)
	}
}

func TestPKCS11KeyManagement(t *testing.T) {
	ensurePKCS11Settings(t)

	// Add RSA Key
	cmdAddRSAKey := "go"
	argsAddRSAKey := []string{"run", "../main.go", "add-key", "--token-label", "my-token", "--object-label", "my-rsa-key", "--key-type", "RSA", "--key-size", "2048"}

	_, err := runCommand(t, cmdAddRSAKey, argsAddRSAKey)
	if err != nil {
		t.Fatalf("Adding RSA Key to PKCS#11 failed: %v", err)
	}

	// List Objects
	cmdListObjects := "go"
	argsListObjects := []string{"run", "../main.go", "list-objects", "--token-label", "my-token"}

	_, err = runCommand(t, cmdListObjects, argsListObjects)
	if err != nil {
		t.Fatalf("Listing PKCS#11 objects failed: %v", err)
	}

	// Delete RSA Key
	cmdDeleteRSAKey := "go"
	argsDeleteRSAKey := []string{"run", "../main.go", "delete-object", "--token-label", "my-token", "--object-label", "my-rsa-key", "--object-type", "pubkey"}

	_, err = runCommand(t, cmdDeleteRSAKey, argsDeleteRSAKey)
	if err != nil {
		t.Fatalf("Deleting RSA Key from PKCS#11 failed: %v", err)
	}
}
