package export

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFileExporter_Export(t *testing.T) {
	tests := []struct {
		name    string
		content string
		path    string
		wantErr bool
	}{
		{
			name:    "successful export",
			content: "test content",
			path:    filepath.Join(os.TempDir(), "test_output.md"),
			wantErr: false,
		},
		{
			name:    "invalid path",
			content: "test content",
			path:    "/nonexistent/path/test_output.md",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := NewFileExporter()
			err := e.Export(context.Background(), tt.content, tt.path)

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				content, err := os.ReadFile(tt.path)
				assert.NoError(t, err)
				assert.Equal(t, tt.content, string(content))
				_ = os.Remove(tt.path) //nolint:errcheck // Test cleanup
			}
		})
	}
}
