# crypto-vault-rest-api

## Summary

RESTful API for managing cryptographic keys and securing data at rest (metadata and binary objects).

## Getting Started

### Prerequisites

- Go 1.25+ installed
- Docker (optional, for containerized deployment)

### Development Setup

#### Local Development

Set up your IDE with Go tooling (including the `delve` debugger) or use the provided [devcontainer.json](../../.devcontainer/devcontainer.json) for a consistent development environment.

#### Run Locally

```bash
# From this directory
go run main.go --config ../../configs/rest-app.yaml
```

Or set the config path via environment variable:

```bash
export CONFIG_PATH=../../configs/rest-app.yaml
go run main.go
```

### API Documentation

Once the service is running, access the Swagger UI in a browser at:

```
make openapi-docs-serve
http://localhost:8080
```

The port may vary based on your configuration (default: `8080`).

### Key Features

- **API-First Design**: OpenAPI 3.0 specification drives all development
- **Cryptographic Key Management**: Generate, store and manage AES, RSA and ECDSA keys
- **Blob Storage**: Secure upload/download with optional encryption and signing
- **Cloud Integration**: Azure Blob Storage support
- **RESTful API**: Full OpenAPI/Swagger documentation
- **Graceful Shutdown**: Handles termination signals properly

### Configuration

The service requires a YAML configuration file. See [configs/rest-app.yaml](../../configs/rest-app.yaml) for the template.

Key configuration options:

- Database connection (PostgreSQL/SQLite)
- Azure Blob Storage credentials
- Azure Key Vault settings
- Server port and logging level
