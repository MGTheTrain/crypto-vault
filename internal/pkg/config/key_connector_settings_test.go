//go:build unit
// +build unit

package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestKeyConnectorSettings_Validate(t *testing.T) {
	tests := []struct {
		name    string
		setting *KeyConnectorSettings
		wantErr bool
	}{
		{
			name: "valid settings",
			setting: &KeyConnectorSettings{
				CloudProvider:    "AWS",
				ConnectionString: "my-connection-string",
				ContainerName:    "my-container",
			},
			wantErr: false,
		},
		{
			name: "missing CloudProvider",
			setting: &KeyConnectorSettings{
				CloudProvider:    "",
				ConnectionString: "my-connection-string",
				ContainerName:    "my-container",
			},
			wantErr: true,
		},
		{
			name: "missing ConnectionString",
			setting: &KeyConnectorSettings{
				CloudProvider:    "AWS",
				ConnectionString: "",
				ContainerName:    "my-container",
			},
			wantErr: true,
		},
		{
			name: "missing ContainerName",
			setting: &KeyConnectorSettings{
				CloudProvider:    "AWS",
				ConnectionString: "my-connection-string",
				ContainerName:    "",
			},
			wantErr: true,
		},
		{
			name:    "all fields missing",
			setting: &KeyConnectorSettings{},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.setting.Validate()
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
