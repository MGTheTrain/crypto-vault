#!/bin/bash

set -euo pipefail

SCRIPT_DIR=$(dirname "$BASH_SOURCE")
ROOT_PROJECT_DIR=$SCRIPT_DIR/..
INTERNAL_GRPC_PROTO_V1_DIR=$ROOT_PROJECT_DIR/api/proto/v1
INTERNAL_GRPC_SERVER_STUB_DIR=$ROOT_PROJECT_DIR/internal/api/grpc/v1/stub

BLUE='\033[0;34m'
NC='\033[0m'

echo "#####################################################################################################"
echo -e "$BLUE INFO: $NC About to generate Go gRPC server stubs from .proto files"

mkdir -vp ${INTERNAL_GRPC_SERVER_STUB_DIR}
protoc -I ${INTERNAL_GRPC_PROTO_V1_DIR} \
  --go_out=${INTERNAL_GRPC_SERVER_STUB_DIR} \
  --go-grpc_out=${INTERNAL_GRPC_SERVER_STUB_DIR} \
  --grpc-gateway_out=${INTERNAL_GRPC_SERVER_STUB_DIR} \
  ${INTERNAL_GRPC_PROTO_V1_DIR}/internal/service.proto

find ${INTERNAL_GRPC_SERVER_STUB_DIR} -type f -name '*.go' -exec sed -i 's/^package __/package stub/' {} \;
