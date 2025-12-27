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
  softhsm2 \
  libssl-dev \
  libengine-pkcs11-openssl \
  protobuf-compiler \
  bc

# Go tools with pinned versions
echo "Installing Go tools..."

# Protocol Buffers compiler plugins
go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.36.11
go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.6.0
go install github.com/grpc-ecosystem/grpc-gateway/v2/protoc-gen-grpc-gateway@v2.25.1
go install github.com/grpc-ecosystem/grpc-gateway/v2/protoc-gen-openapiv2@v2.25.1

# gRPC tools
go install github.com/fullstorydev/grpcurl/cmd/grpcurl@v1.9.3

# Linting
go install github.com/golangci/golangci-lint/cmd/golangci-lint@v1.64.8

# Code formatting
go install golang.org/x/tools/cmd/goimports@v0.40.0

# OpenAPI documentation
go install github.com/deepmap/oapi-codegen/v2/cmd/oapi-codegen@v2.2.0

# Node.js tools
echo "Installing Node.js tools..."
npm install -g prettier@3.7.4
npm install -g @redocly/cli@2.14.1

# Pre-commit framework
echo "Installing pre-commit..."
pip3 install pre-commit --break-system-packages

echo "Development tools installed successfully"
