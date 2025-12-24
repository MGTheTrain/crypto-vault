// Package main is the entry point for the crypto-vault-rest-api application.
// It sets up and starts the RESTful API server using the Gin framework.
package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	v1 "crypto_vault_service/internal/api/rest/v1"
	"crypto_vault_service/internal/app"
	"crypto_vault_service/internal/domain/blobs"
	"crypto_vault_service/internal/domain/crypto"
	"crypto_vault_service/internal/domain/keys"
	"crypto_vault_service/internal/infrastructure/connector"
	"crypto_vault_service/internal/infrastructure/cryptography"
	"crypto_vault_service/internal/infrastructure/persistence"
	"crypto_vault_service/internal/pkg/config"
	"crypto_vault_service/internal/pkg/logger"

	"github.com/gin-gonic/gin"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"

	"crypto_vault_service/cmd/crypto-vault-rest-api/docs"
)

// @title CryptoVault Service API
// @version v1
// @description Service capable of managing cryptographic keys and securing data at rest
// @contact.name MGTheTrain
// @license.name MIT license
// @license.url https://github.com/MGTheTrain/crypto-vault-service/blob/main/LICENSE
// @BasePath /api/v1/cvs
// @securityDefinitions.basic BasicAuth
// @securityDefinitions.apikey ApiKeyAuth
// @in header
// @name Authorization
func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "Application error: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	// Parse configuration
	configPath := os.Getenv("CONFIG_PATH")
	if configPath == "" {
		configPath = "../../configs/rest-app.yaml"
	}

	restConfig, err := config.InitializeRestConfig(configPath)
	if err != nil {
		return fmt.Errorf("failed to initialize config: %w", err)
	}

	// Initialize logger
	if err := logger.InitLogger(&restConfig.Logger); err != nil {
		return fmt.Errorf("failed to initialize logger: %w", err)
	}

	log, err := logger.GetLogger()
	if err != nil {
		return fmt.Errorf("failed to get logger: %w", err)
	}

	// Initialize application dependencies
	deps, err := initializeDependencies(restConfig, log)
	if err != nil {
		return fmt.Errorf("failed to initialize dependencies: %w", err)
	}

	// Setup and start server with graceful shutdown
	return startServerWithGracefulShutdown(restConfig, deps, log)
}

// appDependencies holds all initialized application components
type appDependencies struct {
	services   *appServices
	processors *cryptoProcessors
}

type cryptoProcessors struct {
	aes crypto.AESProcessor
	ec  crypto.ECProcessor
	rsa crypto.RSAProcessor
}

type appServices struct {
	blobUpload        blobs.BlobUploadService
	blobDownload      blobs.BlobDownloadService
	blobMetadata      blobs.BlobMetadataService
	cryptoKeyUpload   keys.CryptoKeyUploadService
	cryptoKeyDownload keys.CryptoKeyDownloadService
	cryptoKeyMetadata keys.CryptoKeyMetadataService
}

// initializeDependencies sets up all application components
func initializeDependencies(cfg *config.RestConfig, log logger.Logger) (*appDependencies, error) {
	// Initialize database
	db, err := persistence.NewDBConnection(cfg.Database)
	if err != nil {
		return nil, fmt.Errorf("failed to create db connection: %w", err)
	}

	// Run migrations
	if err := db.AutoMigrate(&blobs.BlobMeta{}, &keys.CryptoKeyMeta{}); err != nil {
		return nil, fmt.Errorf("failed to migrate schema: %w", err)
	}
	log.Info("Database migrations completed successfully")

	// Initialize repositories
	blobRepo, err := persistence.NewGormBlobRepository(db, log)
	if err != nil {
		return nil, fmt.Errorf("failed to create blob repository: %w", err)
	}

	cryptoKeyRepo, err := persistence.NewGormCryptoKeyRepository(db, log)
	if err != nil {
		return nil, fmt.Errorf("failed to create crypto key repository: %w", err)
	}

	// Initialize connectors
	ctx := context.Background()
	blobConnector, vaultConnector, err := initializeAzureConnectors(ctx, cfg, log)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize connectors: %w", err)
	}

	// Initialize cryptographic processors
	processors, err := initializeCryptoProcessors(log)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize processors: %w", err)
	}

	// Initialize services
	services, err := initializeApplicationServices(
		blobConnector, vaultConnector,
		blobRepo, cryptoKeyRepo,
		processors, log,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize services: %w", err)
	}

	return &appDependencies{
		services:   services,
		processors: processors,
	}, nil
}

// startServerWithGracefulShutdown starts the HTTP server and handles graceful shutdown
func startServerWithGracefulShutdown(cfg *config.RestConfig, deps *appDependencies, log logger.Logger) error {
	// Setup router
	r := gin.Default()
	v1.SetupRoutes(r,
		deps.services.blobUpload,
		deps.services.blobDownload,
		deps.services.blobMetadata,
		deps.services.cryptoKeyUpload,
		deps.services.cryptoKeyDownload,
		deps.services.cryptoKeyMetadata,
	)

	// Setup Swagger
	docs.SwaggerInfo.Version = v1.Version
	docs.SwaggerInfo.BasePath = v1.BasePath
	swaggerRoute := fmt.Sprintf("/api/%s/cvs/swagger/*any", v1.Version)
	r.GET(swaggerRoute, ginSwagger.WrapHandler(swaggerFiles.Handler))

	// Create HTTP server
	srv := &http.Server{
		Addr:              ":" + cfg.Port,
		Handler:           r,
		ReadHeaderTimeout: 10 * time.Second, // Prevent Slowloris attack
	}

	// Channel to listen for errors from the server
	serverErrors := make(chan error, 1)

	// Start server in goroutine
	go func() {
		log.Info("Starting server on port ", cfg.Port)
		log.Info("Swagger UI available at: http://localhost:", cfg.Port, "/api/v1/cvs/swagger/index.html")
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serverErrors <- fmt.Errorf("server failed to start: %w", err)
		}
	}()

	// Channel to listen for interrupt signals
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	// Block until we receive a signal or server error
	select {
	case err := <-serverErrors:
		return err
	case sig := <-quit:
		log.Info("Received signal %v, initiating graceful shutdown", sig)
	}

	// Graceful shutdown with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	log.Info("Shutting down server...")
	if err := srv.Shutdown(ctx); err != nil {
		return fmt.Errorf("server forced to shutdown: %w", err)
	}

	log.Info("Server stopped gracefully")
	return nil
}

// initializeAzureConnectors sets up Azure blob and vault connectors
func initializeAzureConnectors(ctx context.Context, cfg *config.RestConfig, log logger.Logger) (blobs.BlobConnector, keys.VaultConnector, error) {
	if cfg.BlobConnector.CloudProvider != config.AzureCloudProvider {
		return nil, nil, fmt.Errorf("unsupported cloud provider: %s (only Azure is supported)", cfg.BlobConnector.CloudProvider)
	}

	blobConnector, err := connector.NewAzureBlobConnector(ctx, &cfg.BlobConnector, log)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create Azure blob connector: %w", err)
	}

	vaultConnector, err := connector.NewAzureVaultConnector(ctx, &cfg.KeyConnector, log)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create Azure vault connector: %w", err)
	}

	log.Info("Azure connectors initialized successfully")
	return blobConnector, vaultConnector, nil
}

// initializeCryptoProcessors sets up all cryptographic processors
func initializeCryptoProcessors(log logger.Logger) (*cryptoProcessors, error) {
	aesProcessor, err := cryptography.NewAESProcessor(log)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES processor: %w", err)
	}

	ecProcessor, err := cryptography.NewECProcessor(log)
	if err != nil {
		return nil, fmt.Errorf("failed to create EC processor: %w", err)
	}

	rsaProcessor, err := cryptography.NewRSAProcessor(log)
	if err != nil {
		return nil, fmt.Errorf("failed to create RSA processor: %w", err)
	}

	log.Info("Cryptographic processors initialized successfully")
	return &cryptoProcessors{
		aes: aesProcessor,
		ec:  ecProcessor,
		rsa: rsaProcessor,
	}, nil
}

// initializeApplicationServices sets up all application services
func initializeApplicationServices(
	blobConn blobs.BlobConnector,
	vaultConn keys.VaultConnector,
	blobRepo blobs.BlobRepository,
	keyRepo keys.CryptoKeyRepository,
	processors *cryptoProcessors,
	log logger.Logger,
) (*appServices, error) {
	blobUploadService, err := app.NewBlobUploadService(
		blobConn, blobRepo, vaultConn, keyRepo,
		processors.aes, processors.ec, processors.rsa, log,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create blob upload service: %w", err)
	}

	blobDownloadService, err := app.NewBlobDownloadService(
		blobConn, blobRepo, vaultConn, keyRepo,
		processors.aes, processors.rsa, log,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create blob download service: %w", err)
	}

	blobMetadataService, err := app.NewBlobMetadataService(blobRepo, blobConn, log)
	if err != nil {
		return nil, fmt.Errorf("failed to create blob metadata service: %w", err)
	}

	cryptoKeyUploadService, err := app.NewCryptoKeyUploadService(
		vaultConn, keyRepo,
		processors.aes, processors.ec, processors.rsa, log,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create crypto key upload service: %w", err)
	}

	cryptoKeyDownloadService, err := app.NewCryptoKeyDownloadService(vaultConn, keyRepo, log)
	if err != nil {
		return nil, fmt.Errorf("failed to create crypto key download service: %w", err)
	}

	cryptoKeyMetadataService, err := app.NewCryptoKeyMetadataService(vaultConn, keyRepo, log)
	if err != nil {
		return nil, fmt.Errorf("failed to create crypto key metadata service: %w", err)
	}

	log.Info("Application services initialized successfully")
	return &appServices{
		blobUpload:        blobUploadService,
		blobDownload:      blobDownloadService,
		blobMetadata:      blobMetadataService,
		cryptoKeyUpload:   cryptoKeyUploadService,
		cryptoKeyDownload: cryptoKeyDownloadService,
		cryptoKeyMetadata: cryptoKeyMetadataService,
	}, nil
}
