// Package main is the entry point for the crypto-vault-cli application.
// It initializes the root command and registers various sub-commands (AES, RSA, ECDSA, PKCS#11)
// for the CLI, then executes the command-line interface.
package main

import (
	"fmt"
	"log"
	"os"

	commands "crypto_vault_service/cmd/crypto-vault-cli/internal/commands"

	"github.com/spf13/cobra"
)

func main() {
	if err := run(); err != nil {
		log.Fatalf("Error: %v", err)
	}
}

func run() error {
	rootCmd := &cobra.Command{
		Use:   "crypto-vault-cli",
		Short: "Cryptographic operations CLI tool",
		Long: `crypto-vault-cli is a command-line tool for cryptographic operations.
Supports AES encryption/decryption, RSA and ECDSA key generation, signing, and verification.
Also provides PKCS#11 hardware token integration for secure key management.`,
	}

	// Initialize all command groups BEFORE executing
	if err := initializeCommands(rootCmd); err != nil {
		return fmt.Errorf("failed to initialize commands: %w", err)
	}

	// Execute root command ONCE after all commands are registered
	if err := rootCmd.Execute(); err != nil {
		return fmt.Errorf("command execution failed: %w", err)
	}

	return nil
}

// initializeCommands registers all command groups with the root command.
func initializeCommands(rootCmd *cobra.Command) error {
	// Register AES commands
	if err := commands.InitAESCommands(rootCmd); err != nil {
		return fmt.Errorf("failed to initialize AES commands: %w", err)
	}

	// Register RSA commands
	if err := commands.InitRSACommands(rootCmd); err != nil {
		return fmt.Errorf("failed to initialize RSA commands: %w", err)
	}

	// Register ECDSA commands
	if err := commands.InitECDSACommands(rootCmd); err != nil {
		return fmt.Errorf("failed to initialize ECDSA commands: %w", err)
	}

	// Attempt to register PKCS#11 commands (optional, requires environment config)
	if err := initializePKCS11Commands(rootCmd); err != nil {
		// PKCS#11 is optional; log warning but don't fail
		log.Printf("Warning: PKCS#11 commands disabled: %v", err)
	}

	return nil
}

// initializePKCS11Commands attempts to register PKCS#11 commands if configuration is available.
func initializePKCS11Commands(rootCmd *cobra.Command) error {
	// Check if PKCS#11 environment variables are set
	if _, err := commands.ReadPkcs11SettingsFromEnv(); err != nil {
		return fmt.Errorf("PKCS#11 configuration not available: %w", err)
	}

	// Initialize PKCS#11 commands
	if err := commands.InitPKCS11Commands(rootCmd); err != nil {
		return fmt.Errorf("failed to initialize PKCS#11 commands: %w", err)
	}

	return nil
}

// init sets up any necessary initialization before main runs.
func init() {
	// Set log flags for better error messages
	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)

	// Ensure proper exit codes on errors
	log.SetOutput(os.Stderr)
}
