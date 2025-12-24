# Using a Master Key to Encrypt Cryptographic Material

## Overview

In cryptographic systems, **master keys** (also called **Key Encryption Keys (KEK)**) are used to securely encrypt and protect other cryptographic keys, such as **data encryption keys (DEKs)**, which are in turn used to encrypt data (e.g., BLOBs or metadata). This hierarchical key management structure is essential for managing keys securely, especially in systems that handle large volumes of sensitive data.

### Key Concepts

- **Master Key (KEK)**: A key used to encrypt (wrap) other keys, ensuring that the actual data encryption keys (DEKs) are never exposed in plaintext.
- **Data Encryption Key (DEK)**: A key used for encrypting actual data (such as BLOBs or metadata). DEKs are often symmetric keys (e.g., AES-256).
- **Key Wrapping**: The process of encrypting one key (the DEK) using another key (the master key).

## Step-by-Step Process

### 1. **Generate a Master Key**

The **master key** is typically stored in a secure Key Management Service (KMS) like **AWS KMS**, **Azure Key Vault**, or **Google Cloud KMS**.

- **Key Type**: The master key can be **symmetric** (e.g., AES-256) or **asymmetric** (e.g., RSA, ECC).

### 2. **Generate Data Encryption Keys (DEKs)**

A **data encryption key** (DEK) is generated for each encryption operation. These DEKs are used to encrypt specific data, such as metadata or BLOBs.

- **Key Type**: DEKs are usually **symmetric** keys, commonly **AES** keys (e.g., AES-256).

### 3. **Wrap (Encrypt) the DEK with the Master Key**

The **master key** is used to **wrap** or **encrypt** the data encryption key (DEK).

- **Symmetric Key Wrapping**: The DEK is encrypted using the master key (AES).
- **Asymmetric Key Wrapping**: The DEK is encrypted using the master key's **private key** (RSA, ECC).

### 4. **Store the Encrypted Data and Wrapped DEK**

- **Encrypted Data**: The data (e.g., BLOBs or metadata) is encrypted using the DEK.
- **Wrapped DEK**: The DEK is stored in its encrypted (wrapped) form, never in plaintext, alongside or separately from the encrypted data.

### 5. **Decrypting the Data**

When you need to access the encrypted data, follow these steps:

1. **Retrieve the wrapped DEK** from storage.
2. **Unwrap** the DEK using the **master key**.
3. Use the DEK to decrypt the encrypted data (BLOBs or metadata).

### 6. **Key Rotation and Expiration**

To ensure long-term security, periodically rotate both the master key and the data encryption keys:

- **Master Key Rotation**: Replace the old master key with a new one. Rewrap the DEKs with the new master key.
- **DEK Rotation**: Generate new DEKs, encrypt new data with them, and wrap them with the master key.

## Example Use Case

### Master Key and DEK Management

1. **Master Key (KEK)**: AES-256 key stored in AWS KMS or Azure Key Vault.
2. **Data Encryption Key (DEK)**: AES-256 key generated to encrypt a specific BLOB.
3. **Process**:
   - **Wrap DEK**: Use the master key (AES-256) to encrypt the DEK.
   - **Encrypt Data**: Use the DEK to encrypt the data (BLOB or metadata).
   - **Store Data**: Store the encrypted data and the wrapped DEK in your storage system.

4. **Decryption**:
   - **Unwrap DEK**: Use the master key to unwrap (decrypt) the DEK.
   - **Decrypt Data**: Use the DEK to decrypt the BLOB.

## Advantages of Using a Master Key to Protect Other Cryptographic Material

1. **Separation of Duties**: The master key is securely stored in a key management system, while only the wrapped DEKs are exposed.
2. **Key Lifecycle Management**: Easier key rotation and management of DEKs without directly exposing them.
3. **Minimization of Key Exposure**: Only the wrapped keys are stored, reducing the risk of plaintext keys being exposed.
4. **Performance**: Symmetric encryption (AES) of DEKs is much more efficient for large volumes of data than using asymmetric encryption.
5. **Compliance and Security**: Ensures compliance with security standards like PCI DSS, GDPR, and HIPAA by keeping data and keys secure.

## Cloud Provider Support for Key Wrapping

### AWS Key Management Service (KMS)

- Supports **symmetric (AES)** and **asymmetric (RSA, ECC)** key wrapping.
- The `Encrypt` and `Decrypt` API calls are used to wrap and unwrap DEKs.

### Azure Key Vault

- Supports **symmetric (AES)** and **asymmetric (RSA, ECC)** key wrapping.
- The `wrapKey` and `unwrapKey` API calls are used for key wrapping.

### Google Cloud Key Management Service (KMS)

- Supports **symmetric (AES)** and **asymmetric (RSA)** key wrapping.
- The `Encrypt` and `Decrypt` API calls are used for key wrapping and unwrapping.

## Example: Key Wrapping and Encryption in AWS KMS

```bash
# Generate a DEK for data encryption
aws kms generate-data-key --key-id <MasterKeyId> --key-spec AES_256

# Encrypt data with the DEK (AES-256)
aws s3 cp <data-file> s3://<bucket-name>/<encrypted-file> --sse AES256 --sse-kms-key-id <DEK>

# Wrap the DEK using the master key (AES-256)
aws kms encrypt --key-id <MasterKeyId> --plaintext <DEK> --output text

# Store the wrapped DEK securely alongside the encrypted data
```
