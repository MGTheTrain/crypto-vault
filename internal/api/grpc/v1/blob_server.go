package v1

import (
	"context"
	"fmt"

	"github.com/MGTheTrain/crypto-vault/internal/api/grpc/v1/stub"
	"github.com/MGTheTrain/crypto-vault/internal/domain/blobs"
	"github.com/MGTheTrain/crypto-vault/internal/pkg/utils"

	"github.com/google/uuid"
	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// BlobUploadServer handles gRPC requests for uploading blobs
type BlobUploadServer struct {
	stub.UnimplementedBlobUploadServer
	blobUploadService blobs.BlobUploadService
}

// BlobDownloadServer handles gRPC requests for downloading blobs
type BlobDownloadServer struct {
	stub.UnimplementedBlobDownloadServer
	blobDownloadService blobs.BlobDownloadService
	blobMetadataService blobs.BlobMetadataService
}

// BlobMetadataServer handles gRPC requests for blob metadata operations
type BlobMetadataServer struct {
	stub.UnimplementedBlobMetadataServer
	blobMetadataService blobs.BlobMetadataService
}

// NewBlobUploadServer creates a new instance of BlobUploadServer.
func NewBlobUploadServer(blobUploadService blobs.BlobUploadService) (*BlobUploadServer, error) {
	return &BlobUploadServer{
		blobUploadService: blobUploadService,
	}, nil
}

// Upload uploads blobs with optional encryption/signing
func (s BlobUploadServer) Upload(req *stub.BlobUploadRequest, stream stub.BlobUpload_UploadServer) error {
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
		return status.Errorf(codes.Internal, "failed to create multiple files form for files %v: %v", fileNames, err)
	}

	blobMetas, err := s.blobUploadService.Upload(stream.Context(), form, userID, encryptionKeyID, signKeyID)
	if err != nil {
		return status.Errorf(codes.Internal, "failed to upload blob: %v", err)
	}

	for _, blobMeta := range blobMetas {
		blobMetaResponse := &stub.BlobMetaResponse{
			Id:                blobMeta.ID,
			DateTimeCreated:   timestamppb.New(blobMeta.DateTimeCreated),
			UserId:            blobMeta.UserID,
			Name:              blobMeta.Name,
			Size:              blobMeta.Size,
			Type:              blobMeta.Type,
			EncryptionKeyId:   "",
			SignKeyId:         "",
			SignatureBlobId:   "",
			SignatureFileName: "",
		}

		if blobMeta.EncryptionKeyID != nil {
			blobMetaResponse.EncryptionKeyId = *blobMeta.EncryptionKeyID
		}
		if blobMeta.SignKeyID != nil {
			blobMetaResponse.SignKeyId = *blobMeta.SignKeyID
		}
		if blobMeta.SignatureBlobID != nil {
			blobMetaResponse.SignatureBlobId = *blobMeta.SignatureBlobID
		}
		if blobMeta.SignatureFileName != nil {
			blobMetaResponse.SignatureFileName = *blobMeta.SignatureFileName
		}

		// Send the metadata response to the client
		if err := stream.Send(blobMetaResponse); err != nil {
			return status.Errorf(codes.Internal, "failed to send metadata response: %v", err)
		}
	}

	return nil
}

// NewBlobDownloadServer creates a new instance of BlobDownloadServer.
func NewBlobDownloadServer(blobDownloadService blobs.BlobDownloadService, blobMetadataService blobs.BlobMetadataService) (*BlobDownloadServer, error) {
	return &BlobDownloadServer{
		blobDownloadService: blobDownloadService,
		blobMetadataService: blobMetadataService,
	}, nil
}

// DownloadByID downloads a blob by ID
func (s *BlobDownloadServer) DownloadByID(req *stub.BlobDownloadRequest, stream stub.BlobDownload_DownloadByIDServer) error {
	id := req.Id
	var decryptionKeyID *string
	if len(req.DecryptionKeyId) > 0 {
		decryptionKeyID = &req.DecryptionKeyId
	}

	bytes, err := s.blobDownloadService.DownloadByID(stream.Context(), id, decryptionKeyID)
	if err != nil {
		return status.Errorf(codes.NotFound, "could not download blob with id %s: %v", id, err)
	}

	// Stream the blob content back in chunks
	chunkSize := 1024 * 1024 // 1MB chunk size
	for i := 0; i < len(bytes); i += chunkSize {
		end := i + chunkSize
		if end > len(bytes) {
			end = len(bytes)
		}

		chunk := &stub.BlobContent{
			Content: bytes[i:end],
		}

		if err := stream.Send(chunk); err != nil {
			return status.Errorf(codes.Internal, "failed to send chunk: %v", err)
		}
	}
	return nil
}

// DownloadSignatureByID downloads a blob's signature by blob ID
func (s *BlobDownloadServer) DownloadSignatureByID(req *stub.BlobSignatureDownloadRequest, stream stub.BlobDownload_DownloadSignatureByIDServer) error {
	blobID := req.Id

	// Get blob metadata to find signature blob ID
	blobMeta, err := s.blobMetadataService.GetByID(stream.Context(), blobID)
	if err != nil {
		return status.Errorf(codes.NotFound, "blob with id %s not found: %v", blobID, err)
	}

	// Check if signature exists
	if blobMeta.SignatureBlobID == nil {
		return status.Errorf(codes.NotFound, "no signature found for blob %s", blobID)
	}

	// Download signature blob (no decryption needed for signatures)
	signatureBytes, err := s.blobDownloadService.DownloadByID(stream.Context(), *blobMeta.SignatureBlobID, nil)
	if err != nil {
		return status.Errorf(codes.Internal, "could not download signature: %v", err)
	}

	// Stream the signature content back in chunks
	chunkSize := 1024 * 1024 // 1MB chunk size
	for i := 0; i < len(signatureBytes); i += chunkSize {
		end := i + chunkSize
		if end > len(signatureBytes) {
			end = len(signatureBytes)
		}

		chunk := &stub.SignatureContent{
			Content: signatureBytes[i:end],
		}

		if err := stream.Send(chunk); err != nil {
			return status.Errorf(codes.Internal, "failed to send signature chunk: %v", err)
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
func (s *BlobMetadataServer) ListMetadata(req *stub.BlobMetaQuery, stream stub.BlobMetadata_ListMetadataServer) error {
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
		blobMetaResponse := &stub.BlobMetaResponse{
			Id:                blobMeta.ID,
			DateTimeCreated:   timestamppb.New(blobMeta.DateTimeCreated),
			UserId:            blobMeta.UserID,
			Name:              blobMeta.Name,
			Size:              blobMeta.Size,
			Type:              blobMeta.Type,
			EncryptionKeyId:   "",
			SignKeyId:         "",
			SignatureBlobId:   "",
			SignatureFileName: "",
		}

		if blobMeta.EncryptionKeyID != nil {
			blobMetaResponse.EncryptionKeyId = *blobMeta.EncryptionKeyID
		}
		if blobMeta.SignKeyID != nil {
			blobMetaResponse.SignKeyId = *blobMeta.SignKeyID
		}
		if blobMeta.SignatureBlobID != nil {
			blobMetaResponse.SignatureBlobId = *blobMeta.SignatureBlobID
		}
		if blobMeta.SignatureFileName != nil {
			blobMetaResponse.SignatureFileName = *blobMeta.SignatureFileName
		}

		// Send the metadata response to the client
		if err := stream.Send(blobMetaResponse); err != nil {
			return fmt.Errorf("failed to send metadata response: %w", err)
		}
	}

	return nil
}

// GetMetadataByID fetches blob metadata by ID
func (s *BlobMetadataServer) GetMetadataByID(ctx context.Context, req *stub.IdRequest) (*stub.BlobMetaResponse, error) {
	blobMeta, err := s.blobMetadataService.GetByID(ctx, req.Id)
	if err != nil {
		return nil, fmt.Errorf("failed to get metadata by ID: %w", err)
	}

	blobMetaResponse := &stub.BlobMetaResponse{
		Id:                blobMeta.ID,
		DateTimeCreated:   timestamppb.New(blobMeta.DateTimeCreated),
		UserId:            blobMeta.UserID,
		Name:              blobMeta.Name,
		Size:              blobMeta.Size,
		Type:              blobMeta.Type,
		EncryptionKeyId:   "",
		SignKeyId:         "",
		SignatureBlobId:   "",
		SignatureFileName: "",
	}

	if blobMeta.EncryptionKeyID != nil {
		blobMetaResponse.EncryptionKeyId = *blobMeta.EncryptionKeyID
	}
	if blobMeta.SignKeyID != nil {
		blobMetaResponse.SignKeyId = *blobMeta.SignKeyID
	}
	if blobMeta.SignatureBlobID != nil {
		blobMetaResponse.SignatureBlobId = *blobMeta.SignatureBlobID
	}
	if blobMeta.SignatureFileName != nil {
		blobMetaResponse.SignatureFileName = *blobMeta.SignatureFileName
	}

	return blobMetaResponse, nil
}

// DeleteByID deletes a blob by ID
func (s *BlobMetadataServer) DeleteByID(ctx context.Context, req *stub.IdRequest) (*stub.InfoResponse, error) {
	err := s.blobMetadataService.DeleteByID(ctx, req.Id)
	if err != nil {
		return nil, fmt.Errorf("failed to delete blob: %w", err)
	}

	return &stub.InfoResponse{
		Message: fmt.Sprintf("blob with id %s deleted successfully", req.Id),
	}, nil
}

// Register gRPC handlers for each service

// RegisterBlobUploadServer registers the BlobUpload gRPC service
func RegisterBlobUploadServer(server *grpc.Server, blobUploadServer *BlobUploadServer) {
	stub.RegisterBlobUploadServer(server, blobUploadServer)
}

// RegisterBlobDownloadServer registers the BlobDownload gRPC service
func RegisterBlobDownloadServer(server *grpc.Server, blobDownloadServer *BlobDownloadServer) {
	stub.RegisterBlobDownloadServer(server, blobDownloadServer)
}

// RegisterBlobMetadataServer registers the BlobMetadata gRPC service
func RegisterBlobMetadataServer(server *grpc.Server, blobMetadataServer *BlobMetadataServer) {
	stub.RegisterBlobMetadataServer(server, blobMetadataServer)
}

// Register gRPC-Gateway handlers for each service

// Multipart file uploads are not supported with grpc-gateway. For more details,
// see: https://grpc-ecosystem.github.io/grpc-gateway/docs/mapping/binary_file_uploads/. As a result, subsequent code can be commented.
// func RegisterBlobUploadGateway(ctx context.Context, gatewayTarget string, gwmux *runtime.ServeMux, _ *grpc.ClientConn, creds credentials.TransportCredentials) error {
// 	// Register the handler from the endpoint (this works with gRPC-Gateway)
// 	err := stub.RegisterBlobUploadHandlerFromEndpoint(ctx, gwmux, gatewayTarget, []grpc.DialOption{grpc.WithTransportCredentials(creds)})
// 	if err != nil {
// 		return fmt.Errorf("failed to register blob upload gateway: %w", err)// 	}
// 	return nil
// }

// RegisterBlobDownloadGateway registers the BlobDownload HTTP gateway handler.
func RegisterBlobDownloadGateway(ctx context.Context, gatewayTarget string, gwmux *runtime.ServeMux, _ *grpc.ClientConn, creds credentials.TransportCredentials) error {
	err := stub.RegisterBlobDownloadHandlerFromEndpoint(ctx, gwmux, gatewayTarget, []grpc.DialOption{grpc.WithTransportCredentials(creds)})
	if err != nil {
		return fmt.Errorf("failed to register blob download gateway: %w", err)
	}
	return nil
}

// RegisterBlobMetadataGateway registers the BlobMetadata HTTP gateway handler.
func RegisterBlobMetadataGateway(ctx context.Context, gatewayTarget string, gwmux *runtime.ServeMux, _ *grpc.ClientConn, creds credentials.TransportCredentials) error {
	err := stub.RegisterBlobMetadataHandlerFromEndpoint(ctx, gwmux, gatewayTarget, []grpc.DialOption{grpc.WithTransportCredentials(creds)})
	if err != nil {
		return fmt.Errorf("failed to register blob metadata gateway: %w", err)
	}
	return nil
}
