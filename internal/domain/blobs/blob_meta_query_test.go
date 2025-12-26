//go:build unit
// +build unit

package blobs

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestNewBlobMetaQuery_Defaults(t *testing.T) {
	query := NewBlobMetaQuery()

	require.Equal(t, 10, query.Limit)
	require.Equal(t, 0, query.Offset)
	require.Equal(t, "date_time_created", query.SortBy)
	require.Equal(t, "asc", query.SortOrder)
	require.NoError(t, query.Validate(), "expected default query to be valid")
}

func TestBlobMetaQuery_ValidCases(t *testing.T) {
	validCases := []BlobMetaQuery{
		{Name: "test-file", Size: 100, Type: "pdf", Limit: 5, Offset: 0, SortBy: "ID", SortOrder: "desc"},
		{Name: "file", Type: "json", Limit: 1},
		{SortBy: "type", SortOrder: "asc"},
		{DateTimeCreated: time.Now(), Size: 1, SortBy: "date_time_created"},
	}

	for _, tc := range validCases {
		err := tc.Validate()
		require.NoError(t, err, "expected valid BlobMetaQuery to pass validation")
	}
}

func TestBlobMetaQuery_InvalidCases(t *testing.T) {
	invalidCases := []struct {
		name  string
		query BlobMetaQuery
	}{
		{
			name:  "invalid sortBy value",
			query: BlobMetaQuery{SortBy: "invalid_field"},
		},
		{
			name:  "invalid sortOrder value",
			query: BlobMetaQuery{SortOrder: "ascending"},
		},
		{
			name:  "offset negative",
			query: BlobMetaQuery{Offset: -1},
		},
		{
			name:  "name too long",
			query: BlobMetaQuery{Name: string(make([]byte, 256))},
		},
		{
			name:  "type too long",
			query: BlobMetaQuery{Type: string(make([]byte, 51))},
		},
	}

	for _, tc := range invalidCases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.query.Validate()
			require.Error(t, err, "expected validation to fail for case: %s", tc.name)
		})
	}
}
