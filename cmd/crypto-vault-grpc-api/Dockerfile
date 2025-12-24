# Build stage
FROM golang:1.25-alpine AS build

WORKDIR /app

RUN apk update
COPY . .
RUN go mod tidy
RUN go build -o crypto-vault-grpc-service ./cmd/crypto-vault-grpc-service/main.go

# Serve stage
FROM alpine:latest

WORKDIR /root/

RUN apk update && apk add --no-cache libc6-compat
COPY --from=build /app/crypto-vault-grpc-service .

EXPOSE 8090
EXPOSE 50051

ENTRYPOINT ["./crypto-vault-grpc-service"]
