# Build stage
FROM golang:1.25-alpine AS build

WORKDIR /app

RUN apk update
COPY . .
RUN go mod tidy
RUN go build -o crypto-vault-service ./cmd/crypto-vault-rest-service/main.go

# Serve stage
FROM alpine:latest

WORKDIR /root/

RUN apk update && apk add --no-cache libc6-compat
COPY --from=build /app/crypto-vault-service .

EXPOSE 8080

ENTRYPOINT ["./crypto-vault-service"]
