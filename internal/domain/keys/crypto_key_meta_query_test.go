//go:build unit
// +build unit

package keys

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewCryptoKeyQuery_Defaults(t *testing.T) {
	query := NewCryptoKeyQuery()

	require.Equal(t, 10, query.Limit)
	require.Equal(t, 0, query.Offset)
	require.Equal(t, "date_time_created", query.SortBy)
	require.Equal(t, "asc", query.SortOrder)
	require.NoError(t, query.Validate(), "expected default query to be valid")
}

func TestCryptoKeyQuery_ValidCases(t *testing.T) {
	validCases := []CryptoKeyQuery{
		{Algorithm: "AES", Type: "private", Limit: 5, Offset: 0, SortBy: "ID", SortOrder: "desc"},
		{Algorithm: "RSA", Type: "public", SortBy: "type", SortOrder: "asc"},
		{Algorithm: "ECDSA", Limit: 1, Offset: 0},
	}

	for _, tc := range validCases {
		err := tc.Validate()
		require.NoError(t, err, "expected valid CryptoKeyQuery to pass validation")
	}
}

func TestCryptoKeyQuery_InvalidCases(t *testing.T) {
	invalidCases := []struct {
		name  string
		query CryptoKeyQuery
	}{
		{
			name:  "invalid algorithm",
			query: CryptoKeyQuery{Algorithm: "DSA"},
		},
		{
			name:  "invalid type",
			query: CryptoKeyQuery{Type: "unknown"},
		},
		{
			name:  "invalid sortBy",
			query: CryptoKeyQuery{SortBy: "created_at"},
		},
		{
			name:  "invalid sortOrder",
			query: CryptoKeyQuery{SortOrder: "ascending"},
		},
		{
			name:  "offset negative",
			query: CryptoKeyQuery{Offset: -5},
		},
	}

	for _, tc := range invalidCases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.query.Validate()
			require.Error(t, err, "expected validation to fail for case: %s", tc.name)
		})
	}
}
