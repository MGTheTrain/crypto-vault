#!/bin/bash

set -e # Exit on error
set -u # Exit on undefined variable

echo "Installing development tools..."

# System packages
echo "Installing system packages..."
apt-get update
apt-get install -y \
  openssl \
  opensc \
  jq \
  softhsm \
  libssl-dev \
  libengine-pkcs11-openssl \
  protobuf-compiler \
  bc \
  shfmt

# Go tools with pinned versions
echo "Installing Go tools..."

# Protocol Buffers compiler plugins
go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.36.11
go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.6.0
go install github.com/grpc-ecosystem/grpc-gateway/v2/protoc-gen-grpc-gateway@v2.73.3
go install github.com/grpc-ecosystem/grpc-gateway/v2/protoc-gen-openapiv2@v2.73.3

# gRPC tools
go install github.com/fullstorydev/grpcurl/cmd/grpcurl@v1.9.3

# Code formatting
go install golang.org/x/tools/cmd/goimports@v0.40.0

# Linting
go install github.com/golangci/golangci-lint/cmd/golangci-lint@v1.64.8

# Swagger/OpenAPI documentation
go install github.com/swaggo/swag/cmd/swag@v1.16.6

# Node.js tools
echo "Installing Node.js tools..."
npm install -g prettier@3.7.4

echo "Development tools installed successfully"

# Verify installations
echo ""
echo "Verifying installations..."
echo "protoc version: $(protoc --version)"
echo "protoc-gen-go version: $(protoc-gen-go --version)"
echo "protoc-gen-grpc-gateway version: $(protoc-gen-grpc-gateway --version)"
echo "protoc-gen-openapiv2 version: $(protoc-gen-openapiv2 --version)"
echo "grpcurl version: $(grpcurl -version)"
echo "golangci-lint version: $(golangci-lint --version)"
echo "swag version: $(swag --version)"
echo "shfmt version: $(shfmt --version)"
echo "prettier version: $(prettier --version)"
echo ""
echo "All tools installed successfully"
