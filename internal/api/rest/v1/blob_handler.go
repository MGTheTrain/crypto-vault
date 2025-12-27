package v1

import (
	"fmt"
	"mime/multipart"
	"net/http"
	"time"

	"github.com/MGTheTrain/crypto-vault/internal/api/rest/v1/stub"
	"github.com/MGTheTrain/crypto-vault/internal/domain/blobs"
	"github.com/MGTheTrain/crypto-vault/internal/domain/keys"
	"github.com/MGTheTrain/crypto-vault/internal/pkg/strutil"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// BlobHandler defines the interface for handling blob-related operations
type BlobHandler interface {
	Upload(ctx *gin.Context)
	ListMetadata(ctx *gin.Context)
	GetMetadataByID(ctx *gin.Context)
	DownloadByID(ctx *gin.Context)
	DownloadSignatureByID(ctx *gin.Context)
	DeleteByID(ctx *gin.Context)
}

// BlobHandler struct holds the services
type blobHandler struct {
	blobUploadService      blobs.BlobUploadService
	blobMetadataService    blobs.BlobMetadataService
	blobDownloadService    blobs.BlobDownloadService
	cryptoKeyUploadService keys.CryptoKeyUploadService
}

// NewBlobHandler creates a new BlobHandler
func NewBlobHandler(blobUploadService blobs.BlobUploadService, blobDownloadService blobs.BlobDownloadService, blobMetadataService blobs.BlobMetadataService, cryptoKeyUploadService keys.CryptoKeyUploadService) BlobHandler {
	return &blobHandler{
		blobUploadService:      blobUploadService,
		blobDownloadService:    blobDownloadService,
		blobMetadataService:    blobMetadataService,
		cryptoKeyUploadService: cryptoKeyUploadService,
	}
}

// Upload uploads a blob with optional encryption/signing
func (handler *blobHandler) Upload(ctx *gin.Context) {
	var form *multipart.Form
	var encryptionKeyID *string
	var signKeyID *string
	userID := uuid.New().String() // TODO(MGTheTrain): extract user id from JWT

	form, err := ctx.MultipartForm()
	if err != nil {
		var errorResponse stub.ErrorResponse
		errorMessage := "invalid form data"
		errorResponse.Message = &errorMessage
		ctx.JSON(http.StatusBadRequest, errorResponse)
		return
	}

	if encryptionKeys := form.Value["encryption_key_id"]; len(encryptionKeys) > 0 {
		encryptionKeyID = &encryptionKeys[0]
	}

	if signKeys := form.Value["sign_key_id"]; len(signKeys) > 0 {
		signKeyID = &signKeys[0]
	}

	blobMetas, err := handler.blobUploadService.Upload(ctx, form, userID, encryptionKeyID, signKeyID)
	if err != nil {
		var errorResponse stub.ErrorResponse
		errorMessage := fmt.Sprintf("error uploading blob: %v", err.Error())
		errorResponse.Message = &errorMessage
		ctx.JSON(http.StatusBadRequest, errorResponse)
		return
	}

	var blobMetadataResponses []stub.BlobMetaResponse
	for _, blobMeta := range blobMetas {
		blobMetadataResponse := stub.BlobMetaResponse{
			Id:              blobMeta.ID,
			DateTimeCreated: blobMeta.DateTimeCreated,
			UserID:          blobMeta.UserID,
			Name:            blobMeta.Name,
			Size:            blobMeta.Size,
			Type:            blobMeta.Type,
			EncryptionKeyID: nil,
			SignKeyID:       nil,
		}
		if blobMeta.EncryptionKeyID != nil {
			blobMetadataResponse.EncryptionKeyID = blobMeta.EncryptionKeyID
		}
		if blobMeta.SignKeyID != nil {
			blobMetadataResponse.SignKeyID = blobMeta.SignKeyID
		}
		if blobMeta.SignatureBlobID != nil {
			blobMetadataResponse.SignatureBlobID = blobMeta.SignatureBlobID
		}
		if blobMeta.SignatureFileName != nil {
			blobMetadataResponse.SignatureFileName = blobMeta.SignatureFileName
		}
		blobMetadataResponses = append(blobMetadataResponses, blobMetadataResponse)
	}

	ctx.JSON(http.StatusCreated, blobMetadataResponses)
}

// ListMetadata fetches blobs metadata optionally with query parameters
func (handler *blobHandler) ListMetadata(ctx *gin.Context) {
	query := blobs.NewBlobMetaQuery()

	if blobName := ctx.Query("name"); len(blobName) > 0 {
		query.Name = blobName
	}

	if blobSize := ctx.Query("size"); len(blobSize) > 0 {
		query.Size = strutil.ConvertToInt64(blobSize)
	}

	if blobType := ctx.Query("type"); len(blobType) > 0 {
		query.Type = blobType
	}

	if dateTimeCreated := ctx.Query("dateTimeCreated"); len(dateTimeCreated) > 0 {
		parsedTime, err := time.Parse(time.RFC3339, dateTimeCreated)
		if err == nil {
			query.DateTimeCreated = parsedTime
		}
	}

	if limit := ctx.Query("limit"); len(limit) > 0 {
		query.Limit = strutil.ConvertToInt(limit)
	}

	if offset := ctx.Query("offset"); len(offset) > 0 {
		query.Offset = strutil.ConvertToInt(offset)
	}

	if sortBy := ctx.Query("sortBy"); len(sortBy) > 0 {
		query.SortBy = sortBy
	}

	if sortOrder := ctx.Query("sortOrder"); len(sortOrder) > 0 {
		query.SortOrder = sortOrder
	}

	if err := query.Validate(); err != nil {
		var errorResponse stub.ErrorResponse
		errorMessage := fmt.Sprintf("validation failed: %v", err.Error())
		errorResponse.Message = &errorMessage
		ctx.JSON(400, errorResponse)
		return
	}

	blobMetas, err := handler.blobMetadataService.List(ctx, query)
	if err != nil {
		var errorResponse stub.ErrorResponse
		errorMessage := fmt.Sprintf("list query failed: %v", err.Error())
		errorResponse.Message = &errorMessage
		ctx.JSON(http.StatusNotFound, errorResponse)
		return
	}

	var listResponse = []stub.BlobMetaResponse{}
	for _, blobMeta := range blobMetas {
		blobMetadataResponse := stub.BlobMetaResponse{
			Id:              blobMeta.ID,
			DateTimeCreated: blobMeta.DateTimeCreated,
			UserID:          blobMeta.UserID,
			Name:            blobMeta.Name,
			Size:            blobMeta.Size,
			Type:            blobMeta.Type,
			EncryptionKeyID: nil,
			SignKeyID:       nil,
		}
		if blobMeta.EncryptionKeyID != nil {
			blobMetadataResponse.EncryptionKeyID = blobMeta.EncryptionKeyID
		}
		if blobMeta.SignKeyID != nil {
			blobMetadataResponse.SignKeyID = blobMeta.SignKeyID
		}
		if blobMeta.SignatureBlobID != nil {
			blobMetadataResponse.SignatureBlobID = blobMeta.SignatureBlobID
		}
		if blobMeta.SignatureFileName != nil {
			blobMetadataResponse.SignatureFileName = blobMeta.SignatureFileName
		}
		listResponse = append(listResponse, blobMetadataResponse)
	}

	ctx.JSON(http.StatusOK, listResponse)
}

// GetMetadataByID fetches blob metadata by ID
func (handler *blobHandler) GetMetadataByID(ctx *gin.Context) {
	blobID := ctx.Param("id")

	blobMeta, err := handler.blobMetadataService.GetByID(ctx, blobID)
	if err != nil {
		var errorResponse stub.ErrorResponse
		errorMessage := fmt.Sprintf("blob with id %s not found", blobID)
		errorResponse.Message = &errorMessage
		ctx.JSON(http.StatusNotFound, errorResponse)
		return
	}

	blobMetadataResponse := stub.BlobMetaResponse{
		Id:              blobMeta.ID,
		DateTimeCreated: blobMeta.DateTimeCreated,
		UserID:          blobMeta.UserID,
		Name:            blobMeta.Name,
		Size:            blobMeta.Size,
		Type:            blobMeta.Type,
		EncryptionKeyID: nil,
		SignKeyID:       nil,
	}

	if blobMeta.EncryptionKeyID != nil {
		blobMetadataResponse.EncryptionKeyID = blobMeta.EncryptionKeyID
	}
	if blobMeta.SignKeyID != nil {
		blobMetadataResponse.SignKeyID = blobMeta.SignKeyID
	}
	if blobMeta.SignatureBlobID != nil {
		blobMetadataResponse.SignatureBlobID = blobMeta.SignatureBlobID
	}
	if blobMeta.SignatureFileName != nil {
		blobMetadataResponse.SignatureFileName = blobMeta.SignatureFileName
	}

	ctx.JSON(http.StatusOK, blobMetadataResponse)
}

// DownloadByID downloads a blob by ID
func (handler *blobHandler) DownloadByID(ctx *gin.Context) {
	blobID := ctx.Param("id")

	var decryptionKeyID *string
	if decryptionKeyQuery := ctx.Query("decryption_key_id"); len(decryptionKeyQuery) > 0 {
		decryptionKeyID = &decryptionKeyQuery
	}

	bytes, err := handler.blobDownloadService.DownloadByID(ctx, blobID, decryptionKeyID)
	if err != nil {
		var errorResponse stub.ErrorResponse
		errorMessage := fmt.Sprintf("could not download blob with id %s: %v", blobID, err.Error())
		errorResponse.Message = &errorMessage
		ctx.JSON(http.StatusBadRequest, errorResponse)
		return
	}

	blobMeta, err := handler.blobMetadataService.GetByID(ctx, blobID)
	if err != nil {
		var errorResponse stub.ErrorResponse
		errorMessage := fmt.Sprintf("blob with id %s not found", blobID)
		errorResponse.Message = &errorMessage
		ctx.JSON(http.StatusNotFound, errorResponse)
		return
	}

	ctx.Writer.WriteHeader(http.StatusOK)
	ctx.Writer.Header().Set("Content-Type", "application/octet-stream; charset=utf-8")
	ctx.Writer.Header().Set("Content-Disposition", "attachment; filename="+blobMeta.Name)
	_, err = ctx.Writer.Write(bytes)

	if err != nil {
		var errorResponse stub.ErrorResponse
		errorMessage := fmt.Sprintf("could not write bytes: %v", err.Error())
		errorResponse.Message = &errorMessage
		ctx.JSON(http.StatusBadRequest, errorResponse)
		return
	}
}

// DownloadSignatureByID downloads a blob's signature
func (handler *blobHandler) DownloadSignatureByID(ctx *gin.Context) {
	blobID := ctx.Param("id")

	// Get blob metadata
	blobMeta, err := handler.blobMetadataService.GetByID(ctx, blobID)
	if err != nil {
		errorMessage := fmt.Sprintf("blob with id %s not found", blobID)
		ctx.JSON(http.StatusNotFound, stub.ErrorResponse{
			Message: &errorMessage,
		})
		return
	}

	// Check if signature exists
	if blobMeta.SignatureBlobID == nil {
		errorMessage := fmt.Sprintf("no signature found for blob %s", blobID)
		ctx.JSON(http.StatusNotFound, stub.ErrorResponse{
			Message: &errorMessage,
		})
		return
	}

	// Download signature blob
	signatureBytes, err := handler.blobDownloadService.DownloadByID(ctx, *blobMeta.SignatureBlobID, nil)
	if err != nil {
		errorMessage := fmt.Sprintf("could not download signature: %v", err)
		ctx.JSON(http.StatusBadRequest, stub.ErrorResponse{
			Message: &errorMessage,
		})
		return
	}

	// Return signature file
	filename := "signature.sig"
	if blobMeta.SignatureFileName != nil {
		filename = *blobMeta.SignatureFileName
	}

	ctx.Writer.WriteHeader(http.StatusOK)
	ctx.Writer.Header().Set("Content-Type", "application/octet-stream")
	ctx.Writer.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s", filename))

	if _, err := ctx.Writer.Write(signatureBytes); err != nil {
		errorMessage := fmt.Sprintf("failed to write signature: %v", err)
		ctx.JSON(http.StatusInternalServerError, stub.ErrorResponse{
			Message: &errorMessage,
		})
	}
}

// DeleteByID deletes a blob by ID
func (handler *blobHandler) DeleteByID(ctx *gin.Context) {
	blobID := ctx.Param("id")

	if err := handler.blobMetadataService.DeleteByID(ctx, blobID); err != nil {
		var errorResponse stub.ErrorResponse
		errorMessage := fmt.Sprintf("blob with id %s not found", blobID)
		errorResponse.Message = &errorMessage
		ctx.JSON(http.StatusNotFound, errorResponse)
		return
	}

	var infoResponse stub.InfoResponse
	infoMessage := fmt.Sprintf("deleted blob with id %s", blobID)
	infoResponse.Message = &infoMessage
	ctx.JSON(http.StatusNoContent, infoResponse)
}
