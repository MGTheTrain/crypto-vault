// Package main is the entry point for the crypto-vault-grpc-api application.
// It sets up and starts both a gRPC server and a gRPC-Gateway server.
package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	v1 "crypto_vault_service/internal/api/grpc/v1"
	"crypto_vault_service/internal/app"
	"crypto_vault_service/internal/domain/blobs"
	"crypto_vault_service/internal/domain/crypto"
	"crypto_vault_service/internal/domain/keys"
	"crypto_vault_service/internal/infrastructure/connector"
	"crypto_vault_service/internal/infrastructure/cryptography"
	"crypto_vault_service/internal/infrastructure/persistence"
	"crypto_vault_service/internal/pkg/config"
	"crypto_vault_service/internal/pkg/logger"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/reflection"
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
		configPath = "../../configs/grpc-app.yaml"
	}

	grpcConfig, err := config.InitializeGrpcConfig(configPath)
	if err != nil {
		return fmt.Errorf("failed to initialize config: %w", err)
	}

	// Initialize logger
	if err := logger.InitLogger(&grpcConfig.Logger); err != nil {
		return fmt.Errorf("failed to initialize logger: %w", err)
	}

	log, err := logger.GetLogger()
	if err != nil {
		return fmt.Errorf("failed to get logger: %w", err)
	}

	// Initialize application dependencies
	deps, err := initializeDependencies(grpcConfig, log)
	if err != nil {
		return fmt.Errorf("failed to initialize dependencies: %w", err)
	}

	// Start servers with graceful shutdown
	return startServersWithGracefulShutdown(grpcConfig, deps, log)
}

// appDependencies holds all initialized application components
type appDependencies struct {
	grpcServers *grpcServers
	services    *appServices
	processors  *cryptoProcessors
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

type grpcServers struct {
	blobUpload        *v1.BlobUploadServer
	blobDownload      *v1.BlobDownloadServer
	blobMetadata      *v1.BlobMetadataServer
	cryptoKeyUpload   *v1.CryptoKeyUploadServer
	cryptoKeyDownload *v1.CryptoKeyDownloadServer
	cryptoKeyMetadata *v1.CryptoKeyMetadataServer
}

// initializeDependencies sets up all application components
func initializeDependencies(cfg *config.GrpcConfig, log logger.Logger) (*appDependencies, error) {
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

	// Initialize gRPC servers
	grpcServers, err := initializeGRPCServers(services, log)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize gRPC servers: %w", err)
	}

	return &appDependencies{
		grpcServers: grpcServers,
		services:    services,
		processors:  processors,
	}, nil
}

// startServersWithGracefulShutdown starts both gRPC and gateway servers with graceful shutdown
func startServersWithGracefulShutdown(cfg *config.GrpcConfig, deps *appDependencies, log logger.Logger) error {
	// Create gRPC server
	grpcServer := grpc.NewServer()

	// Register services
	v1.RegisterBlobUploadServer(grpcServer, deps.grpcServers.blobUpload)
	v1.RegisterBlobDownloadServer(grpcServer, deps.grpcServers.blobDownload)
	v1.RegisterBlobMetadataServer(grpcServer, deps.grpcServers.blobMetadata)
	v1.RegisterCryptoKeyUploadServer(grpcServer, deps.grpcServers.cryptoKeyUpload)
	v1.RegisterCryptoKeyDownloadServer(grpcServer, deps.grpcServers.cryptoKeyDownload)
	v1.RegisterCryptoKeyMetadataServer(grpcServer, deps.grpcServers.cryptoKeyMetadata)

	// Enable reflection for grpcurl
	reflection.Register(grpcServer)

	// Start gRPC server
	lis, err := net.Listen("tcp", ":"+cfg.Port)
	if err != nil {
		return fmt.Errorf("failed to listen on port %s: %w", cfg.Port, err)
	}

	grpcErrors := make(chan error, 1)
	go func() {
		log.Info("gRPC server starting on port ", cfg.Port)
		log.Info("Use 'grpcurl -plaintext localhost: ", cfg.Port, " list' to see available services")
		if err := grpcServer.Serve(lis); err != nil {
			grpcErrors <- fmt.Errorf("gRPC server failed: %w", err)
		}
	}()

	// Setup gRPC-Gateway
	gwServer, err := setupGatewayServer(cfg, log)
	if err != nil {
		return fmt.Errorf("failed to setup gateway server: %w", err)
	}

	gatewayErrors := make(chan error, 1)
	go func() {
		log.Info("gRPC-Gateway server starting on port ", cfg.GatewayPort)
		log.Info("Gateway available at: http://localhost:", cfg.GatewayPort, "/api/v1/cvs")
		if err := gwServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			gatewayErrors <- fmt.Errorf("gateway server failed: %w", err)
		}
	}()

	// Wait for interrupt signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	// Block until error or signal
	select {
	case err := <-grpcErrors:
		return err
	case err := <-gatewayErrors:
		return err
	case sig := <-quit:
		log.Info("Received signal ", sig, "initiating graceful shutdown")
	}

	// Graceful shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	log.Info("Shutting down servers...")

	// Shutdown gateway
	if err := gwServer.Shutdown(ctx); err != nil {
		log.Error("Gateway shutdown error: %v", err)
	}

	// Graceful stop gRPC
	grpcServer.GracefulStop()

	log.Info("Servers stopped gracefully")
	return nil
}

// setupGatewayServer creates and configures the gRPC-Gateway HTTP server
func setupGatewayServer(cfg *config.GrpcConfig, log logger.Logger) (*http.Server, error) {
	gwmux := runtime.NewServeMux()
	gatewayTarget := "0.0.0.0:" + cfg.Port

	conn, err := grpc.NewClient(gatewayTarget, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, fmt.Errorf("failed to dial gRPC server: %w", err)
	}

	creds := insecure.NewCredentials()

	// Register gateway handlers
	// Note: BlobUpload not registered due to multipart upload limitations
	// See: https://grpc-ecosystem.github.io/grpc-gateway/docs/mapping/binary_file_uploads/

	if err := v1.RegisterBlobDownloadGateway(context.Background(), gatewayTarget, gwmux, conn, creds); err != nil {
		return nil, fmt.Errorf("failed to register blob download gateway: %w", err)
	}

	if err := v1.RegisterBlobMetadataGateway(context.Background(), gatewayTarget, gwmux, conn, creds); err != nil {
		return nil, fmt.Errorf("failed to register blob metadata gateway: %w", err)
	}

	if err := v1.RegisterCryptoKeyUploadGateway(context.Background(), gatewayTarget, gwmux, conn, creds); err != nil {
		return nil, fmt.Errorf("failed to register crypto key upload gateway: %w", err)
	}

	if err := v1.RegisterCryptoKeyDownloadGateway(context.Background(), gatewayTarget, gwmux, conn, creds); err != nil {
		return nil, fmt.Errorf("failed to register crypto key download gateway: %w", err)
	}

	if err := v1.RegisterCryptoKeyMetadataGateway(context.Background(), gatewayTarget, gwmux, conn, creds); err != nil {
		return nil, fmt.Errorf("failed to register crypto key metadata gateway: %w", err)
	}

	log.Info("gRPC-Gateway handlers registered successfully")

	return &http.Server{
		Addr:              ":" + cfg.GatewayPort,
		Handler:           gwmux,
		ReadHeaderTimeout: 10 * time.Second,
	}, nil
}

// initializeAzureConnectors sets up Azure blob and vault connectors
func initializeAzureConnectors(ctx context.Context, cfg *config.GrpcConfig, log logger.Logger) (blobs.BlobConnector, keys.VaultConnector, error) {
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

// initializeGRPCServers creates all gRPC server implementations
func initializeGRPCServers(services *appServices, log logger.Logger) (*grpcServers, error) {
	blobUploadServer, err := v1.NewBlobUploadServer(services.blobUpload)
	if err != nil {
		return nil, fmt.Errorf("failed to create blob upload server: %w", err)
	}

	blobDownloadServer, err := v1.NewBlobDownloadServer(services.blobDownload)
	if err != nil {
		return nil, fmt.Errorf("failed to create blob download server: %w", err)
	}

	blobMetadataServer, err := v1.NewBlobMetadataServer(services.blobMetadata)
	if err != nil {
		return nil, fmt.Errorf("failed to create blob metadata server: %w", err)
	}

	cryptoKeyUploadServer, err := v1.NewCryptoKeyUploadServer(services.cryptoKeyUpload)
	if err != nil {
		return nil, fmt.Errorf("failed to create crypto key upload server: %w", err)
	}

	cryptoKeyDownloadServer, err := v1.NewCryptoKeyDownloadServer(services.cryptoKeyDownload)
	if err != nil {
		return nil, fmt.Errorf("failed to create crypto key download server: %w", err)
	}

	cryptoKeyMetadataServer, err := v1.NewCryptoKeyMetadataServer(services.cryptoKeyMetadata)
	if err != nil {
		return nil, fmt.Errorf("failed to create crypto key metadata server: %w", err)
	}

	log.Info("gRPC servers initialized successfully")
	return &grpcServers{
		blobUpload:        blobUploadServer,
		blobDownload:      blobDownloadServer,
		blobMetadata:      blobMetadataServer,
		cryptoKeyUpload:   cryptoKeyUploadServer,
		cryptoKeyDownload: cryptoKeyDownloadServer,
		cryptoKeyMetadata: cryptoKeyMetadataServer,
	}, nil
}
