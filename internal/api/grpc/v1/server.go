package v1

import (
	"context"
	"crypto_vault_service/internal/domain/blobs"
	"crypto_vault_service/internal/domain/keys"
	"crypto_vault_service/internal/pkg/utils"
	"fmt"

	pb "proto"

	"github.com/google/uuid"
	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// BlobUploadServer handles gRPC requests for uploading blobs
type BlobUploadServer struct {
	pb.UnimplementedBlobUploadServer
	blobUploadService blobs.BlobUploadService
}

// BlobDownloadServer handles gRPC requests for downloading blobs
type BlobDownloadServer struct {
	pb.UnimplementedBlobDownloadServer
	blobDownloadService blobs.BlobDownloadService
}

// BlobMetadataServer handles gRPC requests for blob metadata operations
type BlobMetadataServer struct {
	pb.UnimplementedBlobMetadataServer
	blobMetadataService blobs.BlobMetadataService
}

// CryptoKeyUploadServer handles gRPC requests for uploading cryptographic keys
type CryptoKeyUploadServer struct {
	pb.UnimplementedCryptoKeyUploadServer
	cryptoKeyUploadService keys.CryptoKeyUploadService
}

// CryptoKeyDownloadServer handles gRPC requests for downloading cryptographic keys
type CryptoKeyDownloadServer struct {
	pb.UnimplementedCryptoKeyDownloadServer
	cryptoKeyDownloadService keys.CryptoKeyDownloadService
}

// CryptoKeyMetadataServer handles gRPC requests for cryptographic key metadata
type CryptoKeyMetadataServer struct {
	pb.UnimplementedCryptoKeyMetadataServer
	cryptoKeyMetadataService keys.CryptoKeyMetadataService
}

// NewBlobUploadServer creates a new instance of BlobUploadServer.
func NewBlobUploadServer(blobUploadService blobs.BlobUploadService) (*BlobUploadServer, error) {
	return &BlobUploadServer{
		blobUploadService: blobUploadService,
	}, nil
}

// Upload uploads blobs with optional encryption/signing
func (s BlobUploadServer) Upload(req *pb.BlobUploadRequest, stream pb.BlobUpload_UploadServer) error {
	fileContent := [][]byte{req.FileContent}
	fileNames := []string{req.FileName}

	var encryptionKeyID *string
	var signKeyID *string

	if len(req.EncryptionKeyId) > 0 {
		encryptionKeyID = &req.EncryptionKeyId
	}

	if len(req.SignKeyId) > 0 {
		signKeyID = &req.SignKeyId
	}

	userID := uuid.New().String() // TODO(MGTheTrain): extract user id from JWT
	form, err := utils.CreateMultipleFilesForm(fileContent, fileNames)
	if err != nil {
		return fmt.Errorf("failed to create multiple files form for files %v: %w", fileNames, err)
	}

	blobMetas, err := s.blobUploadService.Upload(stream.Context(), form, userID, encryptionKeyID, signKeyID)
	if err != nil {
		return fmt.Errorf("failed to upload blob: %w", err)
	}

	for _, blobMeta := range blobMetas {
		blobMetaResponse := &pb.BlobMetaResponse{
			Id:              blobMeta.ID,
			DateTimeCreated: timestamppb.New(blobMeta.DateTimeCreated),
			UserId:          blobMeta.UserID,
			Name:            blobMeta.Name,
			Size:            blobMeta.Size,
			Type:            blobMeta.Type,
			EncryptionKeyId: "",
			SignKeyId:       "",
		}

		if blobMeta.EncryptionKeyID != nil {
			blobMetaResponse.EncryptionKeyId = *blobMeta.EncryptionKeyID
		}
		if blobMeta.SignKeyID != nil {
			blobMetaResponse.SignKeyId = *blobMeta.SignKeyID
		}

		// Send the metadata response to the client
		if err := stream.Send(blobMetaResponse); err != nil {
			return fmt.Errorf("failed to send metadata response: %w", err)
		}
	}

	return nil
}

// NewBlobDownloadServer creates a new instance of BlobDownloadServer.
func NewBlobDownloadServer(blobDownloadService blobs.BlobDownloadService) (*BlobDownloadServer, error) {
	return &BlobDownloadServer{
		blobDownloadService: blobDownloadService,
	}, nil
}

// DownloadByID downloads a blob by ID
func (s *BlobDownloadServer) DownloadByID(req *pb.BlobDownloadRequest, stream pb.BlobDownload_DownloadByIDServer) error {
	id := req.Id
	var decryptionKeyID *string
	if len(req.DecryptionKeyId) > 0 {
		decryptionKeyID = &req.DecryptionKeyId
	}

	bytes, err := s.blobDownloadService.DownloadByID(stream.Context(), id, decryptionKeyID)
	if err != nil {
		return fmt.Errorf("could not download blob with id %s: %w", id, err)
	}

	// If no error, stream the blob content back in chunks
	chunkSize := 1024 * 1024 // 1MB chunk size, adjust as needed
	for i := 0; i < len(bytes); i += chunkSize {
		end := i + chunkSize
		if end > len(bytes) {
			end = len(bytes)
		}

		// Create the chunk of data to send
		chunk := &pb.BlobContent{
			Content: bytes[i:end],
		}

		// Send the chunk
		if err := stream.Send(chunk); err != nil {
			return fmt.Errorf("failed to send chunk: %w", err)
		}
	}
	return nil
}

// NewBlobMetadataServer creates a new instance of BlobMetadataServer.
func NewBlobMetadataServer(blobMetadataService blobs.BlobMetadataService) (*BlobMetadataServer, error) {
	return &BlobMetadataServer{
		blobMetadataService: blobMetadataService,
	}, nil
}

// ListMetadata fetches blobs metadata with optional query parameters
func (s *BlobMetadataServer) ListMetadata(req *pb.BlobMetaQuery, stream pb.BlobMetadata_ListMetadataServer) error {
	query := blobs.NewBlobMetaQuery()
	if len(req.Name) > 0 {
		query.Name = req.Name
	}
	if req.Size > 0 {
		query.Size = req.Size
	}
	if len(req.Type) > 0 {
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

	blobMetas, err := s.blobMetadataService.List(stream.Context(), query)
	if err != nil {
		return fmt.Errorf("failed to list metadata: %w", err)
	}

	for _, blobMeta := range blobMetas {
		blobMetaResponse := &pb.BlobMetaResponse{
			Id:              blobMeta.ID,
			DateTimeCreated: timestamppb.New(blobMeta.DateTimeCreated),
			UserId:          blobMeta.UserID,
			Name:            blobMeta.Name,
			Size:            blobMeta.Size,
			Type:            blobMeta.Type,
			EncryptionKeyId: "",
			SignKeyId:       "",
		}

		if blobMeta.EncryptionKeyID != nil {
			blobMetaResponse.EncryptionKeyId = *blobMeta.EncryptionKeyID
		}
		if blobMeta.SignKeyID != nil {
			blobMetaResponse.SignKeyId = *blobMeta.SignKeyID
		}

		// Send the metadata response to the client
		if err := stream.Send(blobMetaResponse); err != nil {
			return fmt.Errorf("failed to send metadata response: %w", err)
		}
	}

	return nil
}

// GetMetadataByID handles the GET request to fetch blob metadata by ID
func (s *BlobMetadataServer) GetMetadataByID(ctx context.Context, req *pb.IdRequest) (*pb.BlobMetaResponse, error) {
	blobMeta, err := s.blobMetadataService.GetByID(ctx, req.Id)
	if err != nil {
		return nil, fmt.Errorf("failed to get metadata by ID: %w", err)
	}

	blobMetaResponse := &pb.BlobMetaResponse{
		Id:              blobMeta.ID,
		DateTimeCreated: timestamppb.New(blobMeta.DateTimeCreated),
		UserId:          blobMeta.UserID,
		Name:            blobMeta.Name,
		Size:            blobMeta.Size,
		Type:            blobMeta.Type,
		EncryptionKeyId: "",
		SignKeyId:       "",
	}

	if blobMeta.EncryptionKeyID != nil {
		blobMetaResponse.EncryptionKeyId = *blobMeta.EncryptionKeyID
	}
	if blobMeta.SignKeyID != nil {
		blobMetaResponse.SignKeyId = *blobMeta.SignKeyID
	}
	return blobMetaResponse, nil
}

// DeleteByID handles the DELETE request to delete a blob by ID
func (s *BlobMetadataServer) DeleteByID(ctx context.Context, req *pb.IdRequest) (*pb.InfoResponse, error) {
	err := s.blobMetadataService.DeleteByID(ctx, req.Id)
	if err != nil {
		return nil, fmt.Errorf("failed to delete blob: %w", err)
	}

	return &pb.InfoResponse{
		Message: fmt.Sprintf("blob with id %s deleted successfully", req.Id),
	}, nil
}

// NewCryptoKeyUploadServer creates a new instance of CryptoKeyUploadServer.
func NewCryptoKeyUploadServer(cryptoKeyUploadService keys.CryptoKeyUploadService) (*CryptoKeyUploadServer, error) {
	return &CryptoKeyUploadServer{
		cryptoKeyUploadService: cryptoKeyUploadService,
	}, nil
}

// Upload generates and uploads cryptographic keys
func (s *CryptoKeyUploadServer) Upload(req *pb.UploadKeyRequest, stream pb.CryptoKeyUpload_UploadServer) error {
	userID := uuid.New().String() // TODO(MGTheTrain): extract user id from JWT

	cryptoKeyMetas, err := s.cryptoKeyUploadService.Upload(stream.Context(), userID, req.Algorithm, req.KeySize)
	if err != nil {
		return fmt.Errorf("failed to generate and upload crypto keys: %w", err)
	}

	for _, cryptoKeyMeta := range cryptoKeyMetas {
		cryptoKeyMetaResponse := &pb.CryptoKeyMetaResponse{
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
func NewCryptoKeyDownloadServer(cryptoKeyDownloadService keys.CryptoKeyDownloadService) (*CryptoKeyDownloadServer, error) {
	return &CryptoKeyDownloadServer{
		cryptoKeyDownloadService: cryptoKeyDownloadService,
	}, nil
}

// DownloadByID downloads a key by ID
func (s *CryptoKeyDownloadServer) DownloadByID(req *pb.KeyDownloadRequest, stream pb.CryptoKeyDownload_DownloadByIDServer) error {
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
		chunk := &pb.KeyContent{
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
func (s *CryptoKeyMetadataServer) ListMetadata(req *pb.KeyMetadataQuery, stream pb.CryptoKeyMetadata_ListMetadataServer) error {
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
		cryptoKeyMetaResponse := &pb.CryptoKeyMetaResponse{
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

// GetMetadataByID handles the GET request to retrieve key metadata by ID
func (s *CryptoKeyMetadataServer) GetMetadataByID(ctx context.Context, req *pb.IdRequest) (*pb.CryptoKeyMetaResponse, error) {
	cryptoKeyMeta, err := s.cryptoKeyMetadataService.GetByID(ctx, req.Id)
	if err != nil {
		return nil, fmt.Errorf("failed to get crypto key metadata by ID: %w", err)
	}

	return &pb.CryptoKeyMetaResponse{
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
func (s *CryptoKeyMetadataServer) DeleteByID(ctx context.Context, req *pb.IdRequest) (*pb.InfoResponse, error) {
	err := s.cryptoKeyMetadataService.DeleteByID(ctx, req.Id)
	if err != nil {
		return nil, fmt.Errorf("failed to delete crypto key: %w", err)
	}

	return &pb.InfoResponse{
		Message: fmt.Sprintf("crypto key with id %s deleted successfully", req.Id),
	}, nil
}

// Register gRPC handlers for each service

// RegisterBlobUploadServer registers the BlobUpload gRPC service with the server
func RegisterBlobUploadServer(server *grpc.Server, blobUploadServer *BlobUploadServer) {
	pb.RegisterBlobUploadServer(server, blobUploadServer)
}

// RegisterBlobDownloadServer registers the BlobDownload gRPC service with the server
func RegisterBlobDownloadServer(server *grpc.Server, blobDownloadServer *BlobDownloadServer) {
	pb.RegisterBlobDownloadServer(server, blobDownloadServer)
}

// RegisterBlobMetadataServer registers the BlobMetadata gRPC service with the server
func RegisterBlobMetadataServer(server *grpc.Server, blobMetadataServer *BlobMetadataServer) {
	pb.RegisterBlobMetadataServer(server, blobMetadataServer)
}

// RegisterCryptoKeyUploadServer registers the CryptoKeyUpload gRPC service with the server
func RegisterCryptoKeyUploadServer(server *grpc.Server, cryptoKeyUploadServer *CryptoKeyUploadServer) {
	pb.RegisterCryptoKeyUploadServer(server, cryptoKeyUploadServer)
}

// RegisterCryptoKeyDownloadServer registers the CryptoKeyDownload gRPC service with the server
func RegisterCryptoKeyDownloadServer(server *grpc.Server, cryptoKeyDownloadServer *CryptoKeyDownloadServer) {
	pb.RegisterCryptoKeyDownloadServer(server, cryptoKeyDownloadServer)
}

// RegisterCryptoKeyMetadataServer registers the CryptoKeyMetadata gRPC service with the server
func RegisterCryptoKeyMetadataServer(server *grpc.Server, cryptoKeyMetadataServer *CryptoKeyMetadataServer) {
	pb.RegisterCryptoKeyMetadataServer(server, cryptoKeyMetadataServer)
}

// Register gRPC-Gateway handlers for each service

// Multipart file uploads are not supported with grpc-gateway. For more details,
// see: https://grpc-ecosystem.github.io/grpc-gateway/docs/mapping/binary_file_uploads/. As a result, subsequent code can be commented.
// func RegisterBlobUploadGateway(ctx context.Context, gatewayTarget string, gwmux *runtime.ServeMux, _ *grpc.ClientConn, creds credentials.TransportCredentials) error {
// 	// Register the handler from the endpoint (this works with gRPC-Gateway)
// 	err := pb.RegisterBlobUploadHandlerFromEndpoint(ctx, gwmux, gatewayTarget, []grpc.DialOption{grpc.WithTransportCredentials(creds)})
// 	if err != nil {
// 		return fmt.Errorf("failed to register blob upload gateway: %w", err)// 	}
// 	return nil
// }

// RegisterBlobDownloadGateway registers the BlobDownload HTTP gateway handler.
func RegisterBlobDownloadGateway(ctx context.Context, gatewayTarget string, gwmux *runtime.ServeMux, _ *grpc.ClientConn, creds credentials.TransportCredentials) error {
	err := pb.RegisterBlobDownloadHandlerFromEndpoint(ctx, gwmux, gatewayTarget, []grpc.DialOption{grpc.WithTransportCredentials(creds)})
	if err != nil {
		return fmt.Errorf("failed to register blob download gateway: %w", err)
	}
	return nil
}

// RegisterBlobMetadataGateway registers the BlobMetadata HTTP gateway handler.
func RegisterBlobMetadataGateway(ctx context.Context, gatewayTarget string, gwmux *runtime.ServeMux, _ *grpc.ClientConn, creds credentials.TransportCredentials) error {
	err := pb.RegisterBlobMetadataHandlerFromEndpoint(ctx, gwmux, gatewayTarget, []grpc.DialOption{grpc.WithTransportCredentials(creds)})
	if err != nil {
		return fmt.Errorf("failed to register blob metadata gateway: %w", err)
	}
	return nil
}

// RegisterCryptoKeyUploadGateway registers the CryptoKeyUpload HTTP gateway handler.
func RegisterCryptoKeyUploadGateway(ctx context.Context, gatewayTarget string, gwmux *runtime.ServeMux, _ *grpc.ClientConn, creds credentials.TransportCredentials) error {
	err := pb.RegisterCryptoKeyUploadHandlerFromEndpoint(ctx, gwmux, gatewayTarget, []grpc.DialOption{grpc.WithTransportCredentials(creds)})
	if err != nil {
		return fmt.Errorf("failed to register crypto key upload gateway: %w", err)
	}
	return nil
}

// RegisterCryptoKeyDownloadGateway registers the CryptoKeyDownload HTTP gateway handler.
func RegisterCryptoKeyDownloadGateway(ctx context.Context, gatewayTarget string, gwmux *runtime.ServeMux, _ *grpc.ClientConn, creds credentials.TransportCredentials) error {
	err := pb.RegisterCryptoKeyDownloadHandlerFromEndpoint(ctx, gwmux, gatewayTarget, []grpc.DialOption{grpc.WithTransportCredentials(creds)})
	if err != nil {
		return fmt.Errorf("failed to register crypto key download gateway: %w", err)
	}
	return nil
}

// RegisterCryptoKeyMetadataGateway registers the CryptoKeyMetadata HTTP gateway handler.
func RegisterCryptoKeyMetadataGateway(ctx context.Context, gatewayTarget string, gwmux *runtime.ServeMux, _ *grpc.ClientConn, creds credentials.TransportCredentials) error {
	err := pb.RegisterCryptoKeyMetadataHandlerFromEndpoint(ctx, gwmux, gatewayTarget, []grpc.DialOption{grpc.WithTransportCredentials(creds)})
	if err != nil {
		return fmt.Errorf("failed to register crypto key metadata gateway: %w", err)
	}
	return nil
}
