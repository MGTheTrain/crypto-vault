package config

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBlobConnectorSettingsValidation(t *testing.T) {
	tests := []struct {
		name          string
		settings      *BlobConnectorSettings
		expectedError bool
	}{
		{
			name: "valid settings",
			settings: &BlobConnectorSettings{
				CloudProvider:    "aws",
				ConnectionString: "some_connection_string",
				ContainerName:    "container_name",
			},
			expectedError: false,
		},
		{
			name: "missing cloud provider",
			settings: &BlobConnectorSettings{
				ConnectionString: "some_connection_string",
				ContainerName:    "container_name",
			},
			expectedError: true,
		},
		{
			name: "missing connection string",
			settings: &BlobConnectorSettings{
				CloudProvider: "aws",
				ContainerName: "container_name",
			},
			expectedError: true,
		},
		{
			name: "missing container name",
			settings: &BlobConnectorSettings{
				CloudProvider:    "aws",
				ConnectionString: "some_connection_string",
			},
			expectedError: true,
		},
		{
			name: "empty fields",
			settings: &BlobConnectorSettings{
				CloudProvider:    "",
				ConnectionString: "",
				ContainerName:    "",
			},
			expectedError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Validate the struct
			err := tt.settings.Validate()

			if tt.expectedError {
				// Expect an error when validation fails
				require.Error(t, err)
			} else {
				// Expect no error when validation passes
				require.NoError(t, err)
			}
		})
	}
}
