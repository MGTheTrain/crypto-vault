package config

import (
	"fmt"
	"strings"

	"github.com/spf13/viper"
)

// GrpcConfig struct holds the overall configuration with separate settings for Blob, Key, Logger, and PKCS#11
type GrpcConfig struct {
	Database      DatabaseSettings      `mapstructure:"database"`
	BlobConnector BlobConnectorSettings `mapstructure:"blob_connector"`
	KeyConnector  KeyConnectorSettings  `mapstructure:"key_connector"`
	Logger        LoggerSettings        `mapstructure:"logger"`
	PKCS11        PKCS11Settings        `mapstructure:"pkcs11"`
	Port          string                `mapstructure:"port"`
	GatewayPort   string                `mapstructure:"gateway_port"`
}

// InitializeGrpcConfig function to read the config, prioritize environment variables and fall back to config file
func InitializeGrpcConfig(path string) (*GrpcConfig, error) {
	viper.SetConfigFile(path)
	viper.AutomaticEnv()
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

	config := GrpcConfig{}

	if port := viper.GetString("PORT"); port != "" {
		// Prioritize environment variables. viper.Unmarshal(...) does not work with environment variables set manually; therefore, this workaround is applied.
		config.Port = port

		if gatewayPort := viper.GetString("GATEWAY_PORT"); gatewayPort != "" {
			config.GatewayPort = gatewayPort
		}

		if dbType := viper.GetString("DATABASE_TYPE"); dbType != "" {
			config.Database.Type = dbType
		}
		if dbDSN := viper.GetString("DATABASE_DSN"); dbDSN != "" {
			config.Database.DSN = dbDSN
		}
		if dbName := viper.GetString("DATABASE_NAME"); dbName != "" {
			config.Database.DBName = dbName
		}

		if blobCloudProvider := viper.GetString("BLOB_CONNECTOR_CLOUD_PROVIDER"); blobCloudProvider != "" {
			config.BlobConnector.CloudProvider = blobCloudProvider
		}
		if blobConnectionString := viper.GetString("BLOB_CONNECTOR_CONNECTION_STRING"); blobConnectionString != "" {
			config.BlobConnector.ConnectionString = blobConnectionString
		}
		if blobContainerName := viper.GetString("BLOB_CONNECTOR_CONTAINER_NAME"); blobContainerName != "" {
			config.BlobConnector.ContainerName = blobContainerName
		}

		if keyCloudProvider := viper.GetString("KEY_CONNECTOR_CLOUD_PROVIDER"); keyCloudProvider != "" {
			config.KeyConnector.CloudProvider = keyCloudProvider
		}
		if keyConnectionString := viper.GetString("KEY_CONNECTOR_CONNECTION_STRING"); keyConnectionString != "" {
			config.KeyConnector.ConnectionString = keyConnectionString
		}
		if keyContainerName := viper.GetString("KEY_CONNECTOR_CONTAINER_NAME"); keyContainerName != "" {
			config.KeyConnector.ContainerName = keyContainerName
		}

		if logLevel := viper.GetString("LOGGER_LOG_LEVEL"); logLevel != "" {
			config.Logger.LogLevel = logLevel
		}
		if logType := viper.GetString("LOGGER_LOG_TYPE"); logType != "" {
			config.Logger.LogType = logType
		}
		if logFilePath := viper.GetString("LOGGER_FILE_PATH"); logFilePath != "" {
			config.Logger.FilePath = logFilePath
		}

		if pkcs11ModulePath := viper.GetString("PKCS11_MODULE_PATH"); pkcs11ModulePath != "" {
			config.PKCS11.ModulePath = pkcs11ModulePath
		}
		if pkcs11SoPin := viper.GetString("PKCS11_SO_PIN"); pkcs11SoPin != "" {
			config.PKCS11.SOPin = pkcs11SoPin
		}
		if pkcs11UserPin := viper.GetString("PKCS11_USER_PIN"); pkcs11UserPin != "" {
			config.PKCS11.UserPin = pkcs11UserPin
		}
		if pkcs11SlotID := viper.GetString("PKCS11_SLOT_ID"); pkcs11SlotID != "" {
			config.PKCS11.SlotID = pkcs11SlotID
		}
	} else {
		if err := viper.ReadInConfig(); err != nil {
			return nil, fmt.Errorf("unable to read config file, %w", err)
		}

		err := viper.Unmarshal(&config)
		if err != nil {
			return nil, fmt.Errorf("unable to decode config into struct, %w", err)
		}
	}

	return &config, nil
}
