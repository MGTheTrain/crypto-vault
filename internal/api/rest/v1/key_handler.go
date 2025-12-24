package v1

import (
	"crypto_vault_service/internal/domain/keys"
	"crypto_vault_service/internal/pkg/utils"
	"fmt"
	"net/http"
	"time"

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

// UploadKeys handles the POST request to generate and upload cryptographic keys
// @Summary Upload cryptographic keys and metadata
// @Description Generate cryptographic keys based on provided parameters and upload them to the system.
// @Tags Key
// @Accept json
// @Produce json
// @Param requestBody body UploadKeyRequest true "Cryptographic Key Data"
// @Success 201 {array} CryptoKeyMetaResponse
// @Failure 400 {object} ErrorResponse
// @Router /keys [post]
func (handler *keyHandler) UploadKeys(ctx *gin.Context) {

	var request UploadKeyRequest

	if err := ctx.ShouldBindJSON(&request); err != nil {
		var errorResponse ErrorResponse
		errorResponse.Message = fmt.Sprintf("invalid key data: %v", err.Error())
		ctx.JSON(http.StatusBadRequest, errorResponse)
		return
	}

	if err := request.Validate(); err != nil {
		var errorResponse ErrorResponse
		errorResponse.Message = fmt.Sprintf("validation failed: %v", err.Error())
		ctx.JSON(400, errorResponse)
		return
	}

	userID := uuid.New().String() // TODO(MGTheTrain): extract user id from JWT

	cryptoKeyMetas, err := handler.cryptoKeyUploadService.Upload(ctx, userID, request.Algorithm, request.KeySize)
	if err != nil {
		var errorResponse ErrorResponse
		errorResponse.Message = fmt.Sprintf("error uploading key: %v", err.Error())
		ctx.JSON(http.StatusBadRequest, errorResponse)
		return
	}

	var listResponse = []CryptoKeyMetaResponse{}
	for _, cryptoKeyMeta := range cryptoKeyMetas {
		cryptoKeyMetadataResponse := CryptoKeyMetaResponse{
			ID:              cryptoKeyMeta.ID,
			KeyPairID:       cryptoKeyMeta.KeyPairID,
			Algorithm:       cryptoKeyMeta.Algorithm,
			KeySize:         cryptoKeyMeta.KeySize,
			Type:            cryptoKeyMeta.Type,
			DateTimeCreated: cryptoKeyMeta.DateTimeCreated,
			UserID:          cryptoKeyMeta.UserID,
		}
		listResponse = append(listResponse, cryptoKeyMetadataResponse)
	}

	ctx.JSON(http.StatusCreated, listResponse)
}

// ListMetadata handles the GET request to list cryptographic key metadata with optional query parameters
// @Summary List cryptographic key metadata based on query parameters
// @Description Fetch a list of cryptographic key metadata based on filters like algorithm, type and creation date, with pagination and sorting options.
// @Tags Key
// @Accept json
// @Produce json
// @Param algorithm query string false "Cryptographic Algorithm"
// @Param type query string false "Key Type"
// @Param dateTimeCreated query string false "Key Creation Date (RFC3339)"
// @Param limit query int false "Limit the number of results"
// @Param offset query int false "Offset the results"
// @Param sortBy query string false "Sort by a specific field"
// @Param sortOrder query string false "Sort order (asc/desc)"
// @Success 200 {array} CryptoKeyMetaResponse
// @Failure 400 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Router /keys [get]
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
		query.Limit = utils.ConvertToInt(limit)
	}

	if offset := ctx.Query("offset"); len(offset) > 0 {
		query.Offset = utils.ConvertToInt(offset)
	}

	if sortBy := ctx.Query("sortBy"); len(sortBy) > 0 {
		query.SortBy = sortBy
	}

	if sortOrder := ctx.Query("sortOrder"); len(sortOrder) > 0 {
		query.SortOrder = sortOrder
	}

	if err := query.Validate(); err != nil {
		var errorResponse ErrorResponse
		errorResponse.Message = fmt.Sprintf("validation failed: %v", err.Error())
		ctx.JSON(400, errorResponse)
		return
	}

	cryptoKeyMetas, err := handler.cryptoKeyMetadataService.List(ctx, query)
	if err != nil {
		var errorResponse ErrorResponse
		errorResponse.Message = fmt.Sprintf("list query failed: %v", err.Error())
		ctx.JSON(http.StatusNotFound, errorResponse)
		return
	}

	var listResponse = []CryptoKeyMetaResponse{}
	for _, cryptoKeyMeta := range cryptoKeyMetas {
		cryptoKeyMetadataResponse := CryptoKeyMetaResponse{
			ID:              cryptoKeyMeta.ID,
			KeyPairID:       cryptoKeyMeta.KeyPairID,
			Algorithm:       cryptoKeyMeta.Algorithm,
			KeySize:         cryptoKeyMeta.KeySize,
			Type:            cryptoKeyMeta.Type,
			DateTimeCreated: cryptoKeyMeta.DateTimeCreated,
			UserID:          cryptoKeyMeta.UserID,
		}
		listResponse = append(listResponse, cryptoKeyMetadataResponse)
	}

	ctx.JSON(http.StatusOK, listResponse)
}

// GetMetadataByID handles the GET request to retrieve crypto key metadata by ID
// @Summary Retrieve crypto key metadata by ID
// @Description Fetch the crypto key metadata by ID, including algorithm, key size and creation date.
// @Tags Key
// @Accept json
// @Produce json
// @Param id path string true "Key ID"
// @Success 200 {object} CryptoKeyMetaResponse
// @Failure 404 {object} ErrorResponse
// @Router /keys/{id} [get]
func (handler *keyHandler) GetMetadataByID(ctx *gin.Context) {
	keyID := ctx.Param("id")

	cryptoKeyMeta, err := handler.cryptoKeyMetadataService.GetByID(ctx, keyID)
	if err != nil {
		var errorResponse ErrorResponse
		errorResponse.Message = fmt.Sprintf("key with id %s not found", keyID)
		ctx.JSON(http.StatusNotFound, errorResponse)
		return
	}

	cryptoKeyMetadataResponse := CryptoKeyMetaResponse{
		ID:              cryptoKeyMeta.ID,
		KeyPairID:       cryptoKeyMeta.KeyPairID,
		Algorithm:       cryptoKeyMeta.Algorithm,
		KeySize:         cryptoKeyMeta.KeySize,
		Type:            cryptoKeyMeta.Type,
		DateTimeCreated: cryptoKeyMeta.DateTimeCreated,
		UserID:          cryptoKeyMeta.UserID,
	}

	ctx.JSON(http.StatusOK, cryptoKeyMetadataResponse)
}

// DownloadByID handles the GET request to download a key by ID
// @Summary Download a cryptographic key by ID
// @Description Download the content of a specific cryptographic key by ID.
// @Tags Key
// @Accept json
// @Produce octet-stream
// @Param id path string true "Key ID"
// @Success 200 {file} file "Cryptographic key content"
// @Failure 404 {object} ErrorResponse
// @Router /keys/{id}/file [get]
func (handler *keyHandler) DownloadByID(ctx *gin.Context) {
	keyID := ctx.Param("id")

	bytes, err := handler.cryptoKeyDownloadService.DownloadByID(ctx, keyID)
	if err != nil {
		var errorResponse ErrorResponse
		errorResponse.Message = fmt.Sprintf("could not download key with id %s: %v", keyID, err.Error())
		ctx.JSON(http.StatusBadRequest, errorResponse)
		return
	}

	ctx.Writer.WriteHeader(http.StatusOK)
	ctx.Writer.Header().Set("Content-Type", "application/octet-stream; charset=utf-8")
	ctx.Writer.Header().Set("Content-Disposition", "attachment; filename="+keyID)
	_, err = ctx.Writer.Write(bytes)

	if err != nil {
		var errorResponse ErrorResponse
		errorResponse.Message = fmt.Sprintf("could not write bytes: %v", err.Error())
		ctx.JSON(http.StatusBadRequest, errorResponse)
		return
	}
}

// DeleteByID handles the DELETE request to delete a key by ID
// @Summary Delete a cryptographic key by ID
// @Description Delete a specific cryptographic key and associated metadata by ID.
// @Tags Key
// @Accept json
// @Produce json
// @Param id path string true "Key ID"
// @Success 204 {object} InfoResponse
// @Failure 404 {object} ErrorResponse
// @Router /keys/{id} [delete]
func (handler *keyHandler) DeleteByID(ctx *gin.Context) {
	keyID := ctx.Param("id")

	if err := handler.cryptoKeyMetadataService.DeleteByID(ctx, keyID); err != nil {
		var errorResponse ErrorResponse
		errorResponse.Message = fmt.Sprintf("error deleting key with id %s", keyID)
		ctx.JSON(http.StatusNotFound, errorResponse)
		return
	}

	var infoResponse InfoResponse
	infoResponse.Message = fmt.Sprintf("deleted key with id %s", keyID)
	ctx.JSON(http.StatusNoContent, infoResponse)
}
