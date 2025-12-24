//go:build unit
// +build unit

package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInitializeGrpcConfig(t *testing.T) {
	tests := []struct {
		name           string
		envVars        map[string]string
		configFile     string
		expectedConfig *GrpcConfig
		expectedError  bool
	}{
		{
			name: "valid environment variables",
			envVars: map[string]string{
				"PORT":                             "8080",
				"GATEWAY_PORT":                     "9090",
				"DATABASE_TYPE":                    "postgres",
				"DATABASE_DSN":                     "user:password@tcp(localhost:5432)/dbname",
				"DATABASE_NAME":                    "mydb",
				"BLOB_CONNECTOR_CLOUD_PROVIDER":    "aws",
				"BLOB_CONNECTOR_CONNECTION_STRING": "connection-string",
				"BLOB_CONNECTOR_CONTAINER_NAME":    "container",
				"KEY_CONNECTOR_CLOUD_PROVIDER":     "azure",
				"KEY_CONNECTOR_CONNECTION_STRING":  "key-connection-string",
				"KEY_CONNECTOR_CONTAINER_NAME":     "key-container",
				"LOGGER_LOG_LEVEL":                 "info",
				"LOGGER_LOG_TYPE":                  "console",
				"PKCS11_MODULE_PATH":               "/path/to/module",
				"PKCS11_SO_PIN":                    "so-pin",
				"PKCS11_USER_PIN":                  "user-pin",
				"PKCS11_SLOT_ID":                   "1",
			},
			expectedConfig: &GrpcConfig{
				Port:        "8080",
				GatewayPort: "9090",
				Database: DatabaseSettings{
					Type:   "postgres",
					DSN:    "user:password@tcp(localhost:5432)/dbname",
					DBName: "mydb",
				},
				BlobConnector: BlobConnectorSettings{
					CloudProvider:    "aws",
					ConnectionString: "connection-string",
					ContainerName:    "container",
				},
				KeyConnector: KeyConnectorSettings{
					CloudProvider:    "azure",
					ConnectionString: "key-connection-string",
					ContainerName:    "key-container",
				},
				Logger: LoggerSettings{
					LogLevel: "info",
					LogType:  "console",
				},
				PKCS11: PKCS11Settings{
					ModulePath: "/path/to/module",
					SOPin:      "so-pin",
					UserPin:    "user-pin",
					SlotID:     "1",
				},
			},
		},
		{
			name:          "error when config file is missing",
			expectedError: true,
			configFile:    "non_existent_config.yaml",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set environment variables
			for key, value := range tt.envVars {
				t.Setenv(key, value)
			}

			// Create a temporary config file if required
			if tt.configFile != "" {
				t.Setenv("CONFIG_FILE_PATH", tt.configFile)
				// You may need to create a temporary config file here or mock it for test purposes
			}

			// Initialize GrpcConfig
			config, err := InitializeGrpcConfig(tt.configFile)

			// Check for expected errors or successful config
			if tt.expectedError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expectedConfig, config)
			}
		})
	}
}
