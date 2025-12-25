# crypto-vault-grpc-api

## Summary

gRPC API for managing cryptographic keys and securing data at rest (metadata and binary objects).

## Getting Started

### Prerequisites

- Go 1.25+ installed
- Docker (optional, for containerized deployment)
- `grpcurl` (for testing gRPC endpoints)

### Development Setup

**Option 1: Local Development**

Set up your IDE with Go tooling (including `delve` debugger and `grpcurl`) or use the provided [devcontainer.json](../../.devcontainer/devcontainer.json).

**Option 2: Run Locally**

```bash
# From this directory
go run main.go --config ../../configs/grpc-app.yaml
```

Or set the config path via environment variable:

```bash
export CONFIG_PATH=../../configs/grpc-app.yaml
go run main.go
```

**Option 3: Docker Deployment**

```bash
# From project root
make compose-start
```

### Service Endpoints

Once running, two servers are available:

- **gRPC Server**: `localhost:50051` (default)
- **gRPC-Gateway (HTTP)**: `http://localhost:8090/api/v1/cvs` (default)

Ports may vary based on your configuration.

## gRPC Usage

### List Available Services

```bash
grpcurl -plaintext localhost:50051 list
```

Expected output:

```
grpc.reflection.v1.ServerReflection
grpc.reflection.v1alpha.ServerReflection
internal.BlobDownload
internal.BlobMetadata
internal.BlobUpload
internal.CryptoKeyDownload
internal.CryptoKeyMetadata
internal.CryptoKeyUpload
```

### Blob Operations

#### Upload Blob (via grpcurl)

**Note**: Multipart file uploads are not supported with grpc-gateway. Use grpcurl for uploads.

```bash
cd ../../  # Navigate to project root
echo "Test content" > test.tmp

grpcurl -import-path ./internal/api/grpc/v1/proto \
  -proto internal/api/grpc/v1/proto/internal/service.proto \
  -d "{
    \"file_name\": \"test.tmp\",
    \"file_content\": \"$(base64 -w 0 test.tmp)\"
  }" \
  -plaintext localhost:50051 internal.BlobUpload/Upload

rm test.tmp
```

#### List Blob Metadata

**Via HTTP Gateway**:

```bash
curl -X GET 'http://localhost:8090/api/v1/cvs/blobs' -H 'accept: application/json'
```

**Via grpcurl**:

```bash
grpcurl -import-path ./internal/api/grpc/v1/proto \
  -proto internal/api/grpc/v1/proto/internal/service.proto \
  -d '{}' \
  -plaintext localhost:50051 internal.BlobMetadata/ListMetadata
```

#### Get Blob Metadata by ID

**Via HTTP Gateway**:

```bash
curl -X GET 'http://localhost:8090/api/v1/cvs/blobs/<blob_id>' -H 'accept: application/json'
```

**Via grpcurl**:

```bash
grpcurl -import-path ./internal/api/grpc/v1/proto \
  -proto internal/api/grpc/v1/proto/internal/service.proto \
  -d '{"id": "<blob_id>"}' \
  -plaintext localhost:50051 internal.BlobMetadata/GetMetadataByID
```

#### Download Blob

**Via HTTP Gateway**:

```bash
curl -X GET 'http://localhost:8090/api/v1/cvs/blobs/<blob_id>/file' \
  -H 'accept: application/json' \
  --output downloaded_file.bin
```

**Via grpcurl**:

```bash
grpcurl -import-path ./internal/api/grpc/v1/proto \
  -proto internal/api/grpc/v1/proto/internal/service.proto \
  -d '{"id": "<blob_id>"}' \
  -plaintext localhost:50051 internal.BlobDownload/DownloadByID
```

#### Delete Blob

**Via HTTP Gateway**:

```bash
curl -X DELETE 'http://localhost:8090/api/v1/cvs/blobs/<blob_id>' \
  -H 'accept: application/json'
```

**Via grpcurl**:

```bash
grpcurl -import-path ./internal/api/grpc/v1/proto \
  -proto internal/api/grpc/v1/proto/internal/service.proto \
  -d '{"id": "<blob_id>"}' \
  -plaintext localhost:50051 internal.BlobMetadata/DeleteByID
```

### Cryptographic Key Operations

#### Generate and Upload Keys

```bash
grpcurl -import-path ./internal/api/grpc/v1/proto \
  -proto internal/api/grpc/v1/proto/internal/service.proto \
  -d '{
    "algorithm": "RSA",
    "key_size": "2048"
  }' \
  -plaintext localhost:50051 internal.CryptoKeyUpload/Upload
```

Supported algorithms: `AES`, `RSA`, `ECDSA`

#### List Key Metadata

```bash
grpcurl -import-path ./internal/api/grpc/v1/proto \
  -proto internal/api/grpc/v1/proto/internal/service.proto \
  -d '{}' \
  -plaintext localhost:50051 internal.CryptoKeyMetadata/ListMetadata
```

#### Get Key Metadata by ID

```bash
grpcurl -import-path ./internal/api/grpc/v1/proto \
  -proto internal/api/grpc/v1/proto/internal/service.proto \
  -d '{"id": "<key_id>"}' \
  -plaintext localhost:50051 internal.CryptoKeyMetadata/GetMetadataByID
```

#### Download Key

```bash
grpcurl -import-path ./internal/api/grpc/v1/proto \
  -proto internal/api/grpc/v1/proto/internal/service.proto \
  -d '{"id": "<key_id>"}' \
  -plaintext localhost:50051 internal.CryptoKeyDownload/DownloadByID
```

#### Delete Key

**Via HTTP Gateway**:

```bash
curl -X DELETE 'http://localhost:8090/api/v1/cvs/keys/<key_id>' \
  -H 'accept: application/json'
```

## Key Features

- **Dual Protocol Support**: gRPC for efficiency, HTTP/REST via gRPC-Gateway for compatibility
- **Cryptographic Operations**: Generate, store and manage AES, RSA and ECDSA keys
- **Blob Storage**: Secure upload/download with optional encryption and signing
- **Service Reflection**: Browse available services with `grpcurl`
- **Cloud Integration**: Azure Blob Storage and Key Vault support
- **Graceful Shutdown**: Handles termination signals properly

## Configuration

The service requires a YAML configuration file. See [configs/grpc-app.yaml](../../configs/grpc-app.yaml) for the template.

Key configuration options:

- gRPC server port (default: `50051`)
- gRPC-Gateway port (default: `8090`)
- Database connection (PostgreSQL/SQLite)
- Azure Blob Storage credentials
- Azure Key Vault settings
- Logging level

## Architecture

```
┌─────────────┐          ┌──────────────┐
│   Clients   │──gRPC───▶│  gRPC Server │
└─────────────┘          │  (port 50051)│
                         └──────┬───────┘
┌─────────────┐                 │
│   HTTP/REST │──HTTP───▶┌──────▼───────┐
│   Clients   │          │ gRPC-Gateway │
└─────────────┘          │  (port 8090) │
                         └──────────────┘
```

## Limitations

- **Multipart Uploads**: Binary file uploads not supported via gRPC-Gateway HTTP endpoints
- **Use grpcurl** for blob upload operations
- See: https://grpc-ecosystem.github.io/grpc-gateway/docs/mapping/binary_file_uploads/
