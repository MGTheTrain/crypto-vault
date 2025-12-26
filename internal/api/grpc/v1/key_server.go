package v1

import (
	"context"
	"fmt"

	"github.com/MGTheTrain/crypto-vault/internal/domain/crypto"
	"github.com/MGTheTrain/crypto-vault/internal/domain/keys"

	"github.com/MGTheTrain/crypto-vault/internal/api/grpc/v1/stub"

	"github.com/google/uuid"
	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// CryptoKeyUploadServer handles gRPC requests for uploading cryptographic keys
type CryptoKeyUploadServer struct {
	stub.UnimplementedCryptoKeyUploadServer
	cryptoKeyUploadService keys.CryptoKeyUploadService
}

// CryptoKeyDownloadServer handles gRPC requests for downloading cryptographic keys
type CryptoKeyDownloadServer struct {
	stub.UnimplementedCryptoKeyDownloadServer
	cryptoKeyDownloadService keys.CryptoKeyDownloadService
	cryptoKeyMetadataService keys.CryptoKeyMetadataService
}

// CryptoKeyMetadataServer handles gRPC requests for cryptographic key metadata
type CryptoKeyMetadataServer struct {
	stub.UnimplementedCryptoKeyMetadataServer
	cryptoKeyMetadataService keys.CryptoKeyMetadataService
}

// NewCryptoKeyUploadServer creates a new instance of CryptoKeyUploadServer.
func NewCryptoKeyUploadServer(cryptoKeyUploadService keys.CryptoKeyUploadService) (*CryptoKeyUploadServer, error) {
	return &CryptoKeyUploadServer{
		cryptoKeyUploadService: cryptoKeyUploadService,
	}, nil
}

// Upload generates and uploads cryptographic keys
func (s *CryptoKeyUploadServer) Upload(req *stub.UploadKeyRequest, stream stub.CryptoKeyUpload_UploadServer) error {
	userID := uuid.New().String() // TODO(MGTheTrain): extract user id from JWT

	cryptoKeyMetas, err := s.cryptoKeyUploadService.Upload(stream.Context(), userID, req.Algorithm, req.KeySize)
	if err != nil {
		return fmt.Errorf("failed to generate and upload crypto keys: %w", err)
	}

	for _, cryptoKeyMeta := range cryptoKeyMetas {
		cryptoKeyMetaResponse := &stub.CryptoKeyMetaResponse{
			Id:              cryptoKeyMeta.ID,
			DateTimeCreated: timestamppb.New(cryptoKeyMeta.DateTimeCreated),
			UserId:          cryptoKeyMeta.UserID,
			Algorithm:       cryptoKeyMeta.Algorithm,
			KeySize:         uint32(cryptoKeyMeta.KeySize),
			Type:            cryptoKeyMeta.Type,
		}

		// Send the metadata response to the client
		if err := stream.Send(cryptoKeyMetaResponse); err != nil {
			return fmt.Errorf("failed to send metadata response: %w", err)
		}
	}

	return nil
}

// NewCryptoKeyDownloadServer creates a new instance of CryptoKeyDownloadServer.
func NewCryptoKeyDownloadServer(cryptoKeyDownloadService keys.CryptoKeyDownloadService, cryptoKeyMetadataService keys.CryptoKeyMetadataService) (*CryptoKeyDownloadServer, error) {
	return &CryptoKeyDownloadServer{
		cryptoKeyDownloadService: cryptoKeyDownloadService,
		cryptoKeyMetadataService: cryptoKeyMetadataService,
	}, nil
}

// DownloadByID downloads a key by ID
func (s *CryptoKeyDownloadServer) DownloadByID(req *stub.KeyDownloadRequest, stream stub.CryptoKeyDownload_DownloadByIDServer) error {
	// Get key metadata to determine filename
	keyMeta, err := s.cryptoKeyMetadataService.GetByID(stream.Context(), req.Id)
	if err != nil {
		return fmt.Errorf("key with id %s not found", req.Id)
	}

	// Determine file extension and name based on key type
	switch keyMeta.Type {
	case crypto.KeyTypePublic:

	case crypto.KeyTypeSymmetric:

	case crypto.KeyTypePrivate:
		return fmt.Errorf("download forbidden for private keys")
	default:
		return fmt.Errorf("unknown key type for: %s", req.Id)
	}

	bytes, err := s.cryptoKeyDownloadService.DownloadByID(stream.Context(), req.Id)
	if err != nil {
		return fmt.Errorf("failed to download crypto key: %w", err)
	}

	// If no error, stream the blob content back in chunks
	chunkSize := 1024 * 1024 // 1MB chunk size, adjust as needed
	for i := 0; i < len(bytes); i += chunkSize {
		end := i + chunkSize
		if end > len(bytes) {
			end = len(bytes)
		}

		// Create the chunk of data to send
		chunk := &stub.KeyContent{
			Content: bytes[i:end],
		}

		// Send the chunk
		if err := stream.Send(chunk); err != nil {
			return fmt.Errorf("failed to send chunk: %w", err)
		}
	}

	return nil
}

// NewCryptoKeyMetadataServer creates a new instance of CryptoKeyMetadataServer.
func NewCryptoKeyMetadataServer(cryptoKeyMetadataService keys.CryptoKeyMetadataService) (*CryptoKeyMetadataServer, error) {
	return &CryptoKeyMetadataServer{
		cryptoKeyMetadataService: cryptoKeyMetadataService,
	}, nil
}

// ListMetadata lists cryptographic key metadata with optional query parameters
func (s *CryptoKeyMetadataServer) ListMetadata(req *stub.KeyMetadataQuery, stream stub.CryptoKeyMetadata_ListMetadataServer) error {
	query := keys.NewCryptoKeyQuery()
	if req.Algorithm != "" {
		query.Algorithm = req.Algorithm
	}
	if req.Type != "" {
		query.Type = req.Type
	}
	if req.DateTimeCreated != nil {
		query.DateTimeCreated = req.DateTimeCreated.AsTime()
	}
	if req.Limit > 0 {
		query.Limit = int(req.Limit)
	}
	if req.Offset > -1 {
		query.Offset = int(req.Offset)
	}

	cryptoKeyMetas, err := s.cryptoKeyMetadataService.List(stream.Context(), query)
	if err != nil {
		return fmt.Errorf("failed to list crypto key metadata: %w", err)
	}

	for _, cryptoKeyMeta := range cryptoKeyMetas {
		cryptoKeyMetaResponse := &stub.CryptoKeyMetaResponse{
			Id:              cryptoKeyMeta.ID,
			KeyPairId:       cryptoKeyMeta.KeyPairID,
			Algorithm:       cryptoKeyMeta.Algorithm,
			KeySize:         uint32(cryptoKeyMeta.KeySize),
			Type:            cryptoKeyMeta.Type,
			DateTimeCreated: timestamppb.New(cryptoKeyMeta.DateTimeCreated),
			UserId:          cryptoKeyMeta.UserID,
		}

		// Send the metadata response to the client
		if err := stream.Send(cryptoKeyMetaResponse); err != nil {
			return fmt.Errorf("failed to send metadata response: %w", err)
		}
	}

	return nil
}

// GetMetadataByID retrieves key metadata by ID
func (s *CryptoKeyMetadataServer) GetMetadataByID(ctx context.Context, req *stub.IdRequest) (*stub.CryptoKeyMetaResponse, error) {
	cryptoKeyMeta, err := s.cryptoKeyMetadataService.GetByID(ctx, req.Id)
	if err != nil {
		return nil, fmt.Errorf("failed to get crypto key metadata by ID: %w", err)
	}

	return &stub.CryptoKeyMetaResponse{
		Id:              cryptoKeyMeta.ID,
		KeyPairId:       cryptoKeyMeta.KeyPairID,
		Algorithm:       cryptoKeyMeta.Algorithm,
		KeySize:         uint32(cryptoKeyMeta.KeySize),
		Type:            cryptoKeyMeta.Type,
		DateTimeCreated: timestamppb.New(cryptoKeyMeta.DateTimeCreated),
		UserId:          cryptoKeyMeta.UserID,
	}, nil
}

// DeleteByID deletes a key by ID
func (s *CryptoKeyMetadataServer) DeleteByID(ctx context.Context, req *stub.IdRequest) (*stub.InfoResponse, error) {
	err := s.cryptoKeyMetadataService.DeleteByID(ctx, req.Id)
	if err != nil {
		return nil, fmt.Errorf("failed to delete crypto key: %w", err)
	}

	return &stub.InfoResponse{
		Message: fmt.Sprintf("crypto key with id %s deleted successfully", req.Id),
	}, nil
}

// Register gRPC handlers for each service

// RegisterCryptoKeyUploadServer registers the CryptoKeyUpload gRPC service
func RegisterCryptoKeyUploadServer(server *grpc.Server, cryptoKeyUploadServer *CryptoKeyUploadServer) {
	stub.RegisterCryptoKeyUploadServer(server, cryptoKeyUploadServer)
}

// RegisterCryptoKeyDownloadServer registers the CryptoKeyDownload gRPC service
func RegisterCryptoKeyDownloadServer(server *grpc.Server, cryptoKeyDownloadServer *CryptoKeyDownloadServer) {
	stub.RegisterCryptoKeyDownloadServer(server, cryptoKeyDownloadServer)
}

// RegisterCryptoKeyMetadataServer registers the CryptoKeyMetadata gRPC service
func RegisterCryptoKeyMetadataServer(server *grpc.Server, cryptoKeyMetadataServer *CryptoKeyMetadataServer) {
	stub.RegisterCryptoKeyMetadataServer(server, cryptoKeyMetadataServer)
}

// Register gRPC-Gateway handlers for each service

// RegisterCryptoKeyUploadGateway registers the CryptoKeyUpload HTTP gateway handler.
func RegisterCryptoKeyUploadGateway(ctx context.Context, gatewayTarget string, gwmux *runtime.ServeMux, _ *grpc.ClientConn, creds credentials.TransportCredentials) error {
	err := stub.RegisterCryptoKeyUploadHandlerFromEndpoint(ctx, gwmux, gatewayTarget, []grpc.DialOption{grpc.WithTransportCredentials(creds)})
	if err != nil {
		return fmt.Errorf("failed to register crypto key upload gateway: %w", err)
	}
	return nil
}

// RegisterCryptoKeyDownloadGateway registers the CryptoKeyDownload HTTP gateway handler.
func RegisterCryptoKeyDownloadGateway(ctx context.Context, gatewayTarget string, gwmux *runtime.ServeMux, _ *grpc.ClientConn, creds credentials.TransportCredentials) error {
	err := stub.RegisterCryptoKeyDownloadHandlerFromEndpoint(ctx, gwmux, gatewayTarget, []grpc.DialOption{grpc.WithTransportCredentials(creds)})
	if err != nil {
		return fmt.Errorf("failed to register crypto key download gateway: %w", err)
	}
	return nil
}

// RegisterCryptoKeyMetadataGateway registers the CryptoKeyMetadata HTTP gateway handler.
func RegisterCryptoKeyMetadataGateway(ctx context.Context, gatewayTarget string, gwmux *runtime.ServeMux, _ *grpc.ClientConn, creds credentials.TransportCredentials) error {
	err := stub.RegisterCryptoKeyMetadataHandlerFromEndpoint(ctx, gwmux, gatewayTarget, []grpc.DialOption{grpc.WithTransportCredentials(creds)})
	if err != nil {
		return fmt.Errorf("failed to register crypto key metadata gateway: %w", err)
	}
	return nil
}
