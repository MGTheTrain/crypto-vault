# crypto-vault-cli

Command-line tool for cryptographic operations supporting AES, RSA, ECDSA encryption/decryption, signing/verification, and PKCS#11 hardware token integration.

## Quick Start

### AES (Symmetric Encryption)

```sh
# Generate key
go run main.go generate-aes-keys --key-size 16 --key-dir data

# Encrypt
go run main.go encrypt-aes \
  --input-file data/input.txt \
  --output-file data/output.enc \
  --symmetric-key data/<key-file>

# Decrypt
go run main.go decrypt-aes \
  --input-file data/output.enc \
  --output-file data/decrypted.txt \
  --symmetric-key data/<key-file>
```

### RSA (Asymmetric Encryption + Signing)

```sh
# Generate keys
go run main.go generate-rsa-keys --key-size 2048 --key-dir data

# Encrypt/Decrypt
go run main.go encrypt-rsa \
  --input-file data/input.txt \
  --output-file data/encrypted.bin \
  --public-key data/<public-key>

go run main.go decrypt-rsa \
  --input-file data/encrypted.bin \
  --output-file data/decrypted.txt \
  --private-key data/<private-key>

# Sign/Verify
go run main.go sign-rsa \
  --input-file data/input.txt \
  --output-file data/signature.bin \
  --private-key data/<private-key>

go run main.go verify-rsa \
  --input-file data/input.txt \
  --signature-file data/signature.bin \
  --public-key data/<public-key>
```

### ECDSA (Elliptic Curve Signing)

```sh
# Generate keys
go run main.go generate-ecc-keys --key-size 256 --key-dir data

# Sign/Verify
go run main.go sign-ecc \
  --input-file data/input.txt \
  --output-file data/signature.bin \
  --private-key data/<private-key>

go run main.go verify-ecc \
  --input-file data/input.txt \
  --signature-file data/signature.bin \
  --public-key data/<public-key>
```

## PKCS#11 Hardware Tokens

### Prerequisites

Set required environment variables:

```sh
export PKCS11_MODULE_PATH="/usr/lib/softhsm/libsofthsm2.so"
export PKCS11_SO_PIN="1234"
export PKCS11_USER_PIN="5678"
export PKCS11_SLOT_ID="0x0"
```

### Token Operations

```sh
# List available tokens
go run main.go list-slots

# Initialize token
go run main.go initialize-token --token-label my-token

# Add key (specify operation: signing or encryption)
go run main.go add-key \
  --token-label my-token \
  --object-label my-rsa-key \
  --key-type RSA \
  --key-size 2048 \
  --key-operation signing

# List objects in token
go run main.go list-objects --token-label my-token

# Delete key
go run main.go delete-object \
  --token-label my-token \
  --object-label my-rsa-key \
  --object-type privkey

go run main.go delete-object \
  --token-label my-token \
  --object-label my-rsa-key \
  --object-type pubkey
```

### Encryption/Decryption with Token

```sh
# Encrypt (RSA-PKCS only)
go run main.go encrypt \
  --token-label my-token \
  --object-label my-rsa-key \
  --key-type RSA \
  --input-file data/input.txt \
  --output-file data/encrypted.bin

# Decrypt
go run main.go decrypt \
  --token-label my-token \
  --object-label my-rsa-key \
  --key-type RSA \
  --input-file data/encrypted.bin \
  --output-file data/decrypted.txt
```

### Signing/Verification with Token

```sh
# Sign (supports RSA-PSS and ECDSA)
go run main.go sign \
  --token-label my-token \
  --object-label my-rsa-key \
  --key-type RSA \
  --data-file data/input.txt \
  --signature-file data/signature.sig

# Verify
go run main.go verify \
  --token-label my-token \
  --object-label my-rsa-key \
  --key-type RSA \
  --data-file data/input.txt \
  --signature-file data/signature.sig
```

## Supported Algorithms

| Operation | Algorithms | Key Sizes |
|-----------|-----------|-----------|
| Symmetric Encryption | AES | 128, 192, 256-bit |
| Asymmetric Encryption | RSA | 2048, 3072, 4096-bit |
| Digital Signature | RSA, ECDSA | RSA: 2048-4096 bit<br>ECDSA: P-224, P-256, P-384, P-521 |
| PKCS#11 | RSA, ECDSA | Same as above |

## Testing

End-to-end tests covering the complete flow are available at `../../test/e2e/e2e_test.go`.

## Help

```sh
# General help
go run main.go help

# Command-specific help
go run main.go <command> --help
```