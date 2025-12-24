//go:build unit
// +build unit

package config

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDatabaseSettingsValidation(t *testing.T) {
	tests := []struct {
		name          string
		settings      *DatabaseSettings
		expectedError bool
	}{
		{
			name: "valid settings",
			settings: &DatabaseSettings{
				Type:   "postgres",
				DSN:    "user:password@tcp(localhost:3306)/dbname",
				DBName: "mydb",
			},
			expectedError: false,
		},
		{
			name: "missing type",
			settings: &DatabaseSettings{
				DSN:    "user:password@tcp(localhost:3306)/dbname",
				DBName: "mydb",
			},
			expectedError: true,
		},
		{
			name: "missing DSN",
			settings: &DatabaseSettings{
				Type:   "mysql",
				DBName: "mydb",
			},
			expectedError: true,
		},
		{
			name: "missing name",
			settings: &DatabaseSettings{
				Type: "mysql",
				DSN:  "user:password@tcp(localhost:3306)/dbname",
			},
			expectedError: true,
		},
		{
			name: "empty fields",
			settings: &DatabaseSettings{
				Type:   "",
				DSN:    "",
				DBName: "",
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
