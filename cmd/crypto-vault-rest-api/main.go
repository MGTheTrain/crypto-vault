// cmd/crypto-vault-rest-api/main.go
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

	v1 "github.com/MGTheTrain/crypto-vault/internal/api/rest/v1"
	"github.com/MGTheTrain/crypto-vault/internal/app"
	"github.com/MGTheTrain/crypto-vault/internal/domain/blobs"
	"github.com/MGTheTrain/crypto-vault/internal/domain/cryptoalg"
	"github.com/MGTheTrain/crypto-vault/internal/domain/keys"
	"github.com/MGTheTrain/crypto-vault/internal/infrastructure/connector"
	"github.com/MGTheTrain/crypto-vault/internal/infrastructure/cryptography"
	"github.com/MGTheTrain/crypto-vault/internal/infrastructure/persistence"
	"github.com/MGTheTrain/crypto-vault/internal/infrastructure/persistence/models"
	"github.com/MGTheTrain/crypto-vault/internal/pkg/config"
	"github.com/MGTheTrain/crypto-vault/internal/pkg/logger"
	"github.com/gin-contrib/cors"

	"github.com/gin-gonic/gin"
)

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
	aes cryptoalg.AESProcessor
	ec  cryptoalg.ECDSAProcessor
	rsa cryptoalg.RSAProcessor
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
	if err := db.AutoMigrate(&models.BlobModel{}, &models.CryptoKeyModel{}); err != nil {
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

	// Configure CORS
	r.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"*"},
		AllowMethods:     []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Accept", "Authorization"},
		ExposeHeaders:    []string{"Content-Length", "Content-Type"},
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
	}))

	// Setup API routes
	v1.SetupRoutes(r,
		deps.services.blobUpload,
		deps.services.blobDownload,
		deps.services.blobMetadata,
		deps.services.cryptoKeyUpload,
		deps.services.cryptoKeyDownload,
		deps.services.cryptoKeyMetadata,
	)

	// Serve OpenAPI spec (replaces Swagger)
	r.GET("/api/v1/cvs/openapi.yaml", func(c *gin.Context) {
		c.File("./api/openapi/v1/crypto-vault.yaml")
	})

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

	ecdsaProcessor, err := cryptography.NewECDSAProcessor(log)
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
		ec:  ecdsaProcessor,
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
