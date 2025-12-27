package v1

import (
	"fmt"
	"net/http"
	"time"

	"github.com/MGTheTrain/crypto-vault/internal/api/rest/v1/stub"
	"github.com/MGTheTrain/crypto-vault/internal/domain/cryptoalg"
	"github.com/MGTheTrain/crypto-vault/internal/domain/keys"
	"github.com/MGTheTrain/crypto-vault/internal/pkg/strutil"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// KeyHandler defines the interface for handling key-related operations
type KeyHandler interface {
	UploadKeys(ctx *gin.Context)
	ListMetadata(ctx *gin.Context)
	GetMetadataByID(ctx *gin.Context)
	DownloadByID(ctx *gin.Context)
	DeleteByID(ctx *gin.Context)
}

// KeyHandler struct holds the services
type keyHandler struct {
	cryptoKeyUploadService   keys.CryptoKeyUploadService
	cryptoKeyDownloadService keys.CryptoKeyDownloadService
	cryptoKeyMetadataService keys.CryptoKeyMetadataService
}

// NewKeyHandler creates a new KeyHandler
func NewKeyHandler(cryptoKeyUploadService keys.CryptoKeyUploadService, cryptoKeyDownloadService keys.CryptoKeyDownloadService, cryptoKeyMetadataService keys.CryptoKeyMetadataService) KeyHandler {
	return &keyHandler{
		cryptoKeyUploadService:   cryptoKeyUploadService,
		cryptoKeyDownloadService: cryptoKeyDownloadService,
		cryptoKeyMetadataService: cryptoKeyMetadataService,
	}
}

// UploadKeys generates and uploads cryptographic keys
func (handler *keyHandler) UploadKeys(ctx *gin.Context) {

	var request stub.UploadKeyRequest

	if err := ctx.ShouldBindJSON(&request); err != nil {
		var errorResponse stub.ErrorResponse
		errorMessage := fmt.Sprintf("invalid key data: %v", err.Error())
		errorResponse.Message = &errorMessage
		ctx.JSON(http.StatusBadRequest, errorResponse)
		return
	}

	userID := uuid.New().String() // TODO(MGTheTrain): extract user id from JWT

	// nolint:gosec,G115
	cryptoKeyMetas, err := handler.cryptoKeyUploadService.Upload(ctx, userID, string(request.Algorithm), uint32(request.KeySize))
	if err != nil {
		var errorResponse stub.ErrorResponse
		errorMessage := fmt.Sprintf("error uploading key: %v", err.Error())
		errorResponse.Message = &errorMessage
		ctx.JSON(http.StatusBadRequest, errorResponse)
		return
	}

	var listResponse = []stub.CryptoKeyMetaResponse{}
	for _, cryptoKeyMeta := range cryptoKeyMetas {
		cryptoKeyMetadataResponse := stub.CryptoKeyMetaResponse{
			Id:              cryptoKeyMeta.ID,
			KeyPairID:       cryptoKeyMeta.KeyPairID,
			Algorithm:       stub.CryptoKeyMetaResponseAlgorithm(cryptoKeyMeta.Algorithm),
			KeySize:         cryptoKeyMeta.KeySize,
			Type:            stub.CryptoKeyMetaResponseType(cryptoKeyMeta.Type),
			DateTimeCreated: cryptoKeyMeta.DateTimeCreated,
			UserID:          cryptoKeyMeta.UserID,
		}
		listResponse = append(listResponse, cryptoKeyMetadataResponse)
	}

	ctx.JSON(http.StatusCreated, listResponse)
}

// ListMetadata lists cryptographic key metadata with optional query parameters
func (handler *keyHandler) ListMetadata(ctx *gin.Context) {
	query := keys.NewCryptoKeyQuery()

	if keyAlgorithm := ctx.Query("algorithm"); len(keyAlgorithm) > 0 {
		query.Algorithm = keyAlgorithm
	}

	if keyType := ctx.Query("type"); len(keyType) > 0 {
		query.Type = keyType
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

	cryptoKeyMetas, err := handler.cryptoKeyMetadataService.List(ctx, query)
	if err != nil {
		var errorResponse stub.ErrorResponse
		errorMessage := fmt.Sprintf("list query failed: %v", err.Error())
		errorResponse.Message = &errorMessage
		ctx.JSON(http.StatusNotFound, errorResponse)
		return
	}

	var listResponse = []stub.CryptoKeyMetaResponse{}
	for _, cryptoKeyMeta := range cryptoKeyMetas {
		cryptoKeyMetadataResponse := stub.CryptoKeyMetaResponse{
			Id:              cryptoKeyMeta.ID,
			KeyPairID:       cryptoKeyMeta.KeyPairID,
			Algorithm:       stub.CryptoKeyMetaResponseAlgorithm(cryptoKeyMeta.Algorithm),
			KeySize:         cryptoKeyMeta.KeySize,
			Type:            stub.CryptoKeyMetaResponseType(cryptoKeyMeta.Type),
			DateTimeCreated: cryptoKeyMeta.DateTimeCreated,
			UserID:          cryptoKeyMeta.UserID,
		}
		listResponse = append(listResponse, cryptoKeyMetadataResponse)
	}

	ctx.JSON(http.StatusOK, listResponse)
}

// GetMetadataByID retrieves crypto key metadata by ID
func (handler *keyHandler) GetMetadataByID(ctx *gin.Context) {
	keyID := ctx.Param("id")

	cryptoKeyMeta, err := handler.cryptoKeyMetadataService.GetByID(ctx, keyID)
	if err != nil {
		var errorResponse stub.ErrorResponse
		errorMessage := fmt.Sprintf("key with id %s not found", keyID)
		errorResponse.Message = &errorMessage
		ctx.JSON(http.StatusNotFound, errorResponse)
		return
	}

	cryptoKeyMetadataResponse := stub.CryptoKeyMetaResponse{
		Id:              cryptoKeyMeta.ID,
		KeyPairID:       cryptoKeyMeta.KeyPairID,
		Algorithm:       stub.CryptoKeyMetaResponseAlgorithm(cryptoKeyMeta.Algorithm),
		KeySize:         cryptoKeyMeta.KeySize,
		Type:            stub.CryptoKeyMetaResponseType(cryptoKeyMeta.Type),
		DateTimeCreated: cryptoKeyMeta.DateTimeCreated,
		UserID:          cryptoKeyMeta.UserID,
	}

	ctx.JSON(http.StatusOK, cryptoKeyMetadataResponse)
}

// DownloadByID downloads a cryptographic key by ID
func (handler *keyHandler) DownloadByID(ctx *gin.Context) {
	keyID := ctx.Param("id")

	// Get key metadata to determine filename
	keyMeta, err := handler.cryptoKeyMetadataService.GetByID(ctx, keyID)
	if err != nil {
		errorMessage := fmt.Sprintf("key with id %s not found", keyID)
		ctx.JSON(http.StatusNotFound, stub.ErrorResponse{
			Message: &errorMessage,
		})
		return
	}

	// Determine file extension and name based on key type
	var filename string
	switch keyMeta.Type {
	case cryptoalg.KeyTypePublic:
		filename = fmt.Sprintf("%s-public-key.pem", keyID)
	case cryptoalg.KeyTypeSymmetric:
		filename = fmt.Sprintf("%s-symmetrics-key.pem", keyID)
	case cryptoalg.KeyTypePrivate:
		var errorResponse stub.ErrorResponse
		errorMessage := "download forbidden for private keys"
		errorResponse.Message = &errorMessage
		ctx.JSON(http.StatusBadRequest, errorResponse)
		return
	default:
		var errorResponse stub.ErrorResponse
		errorMessage := fmt.Sprintf("unknown key type for %s", keyID)
		errorResponse.Message = &errorMessage
		ctx.JSON(http.StatusBadRequest, errorResponse)
		return
	}

	// Download key bytes (already in PEM format from service)
	pemBytes, err := handler.cryptoKeyDownloadService.DownloadByID(ctx, keyID)
	if err != nil {
		errorMessage := fmt.Sprintf("could not download key with id %s: %v", keyID, err.Error())
		ctx.JSON(http.StatusBadRequest, stub.ErrorResponse{
			Message: &errorMessage,
		})
		return
	}

	// Set headers for PEM file download
	ctx.Writer.Header().Set("Content-Type", "application/x-pem-file")
	ctx.Writer.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s", filename))
	ctx.Writer.WriteHeader(http.StatusOK)

	if _, err := ctx.Writer.Write(pemBytes); err != nil {
		var errorResponse stub.ErrorResponse
		errorMessage := fmt.Sprintf("failed to write PEM bytes to response with ID %s, error: %s", keyID, err)
		errorResponse.Message = &errorMessage
		ctx.JSON(http.StatusBadRequest, errorResponse)
		return
	}

	var infoResponse stub.InfoResponse
	infoMessage := fmt.Sprintf("key downloaded successfully %s", keyID)
	infoResponse.Message = &infoMessage
	ctx.JSON(http.StatusNoContent, infoResponse)
}

// DeleteByID deletes a key by ID
func (handler *keyHandler) DeleteByID(ctx *gin.Context) {
	keyID := ctx.Param("id")

	if err := handler.cryptoKeyMetadataService.DeleteByID(ctx, keyID); err != nil {
		var errorResponse stub.ErrorResponse
		errorMessage := fmt.Sprintf("error deleting key with id %s", keyID)
		errorResponse.Message = &errorMessage
		ctx.JSON(http.StatusNotFound, errorResponse)
		return
	}

	var infoResponse stub.InfoResponse
	infoMessage := fmt.Sprintf("deleted key with id %s", keyID)
	infoResponse.Message = &infoMessage
	ctx.JSON(http.StatusNoContent, infoResponse)
}
