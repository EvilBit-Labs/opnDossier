package converter

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/unclesp1d3r/opnFocus/internal/model"
)

func TestJSONConverter_ToJSON(t *testing.T) {
	tests := []struct {
		name      string
		opnsense  *model.OpnSenseDocument
		wantErr   bool
		errType   error
		checkJSON bool
	}{
		{
			name:     "nil opnsense",
			opnsense: nil,
			wantErr:  true,
			errType:  ErrNilOpnSenseDocument,
		},
		{
			name: "valid opnsense",
			opnsense: &model.OpnSenseDocument{
				Version: "1.0.0",
				System: model.System{
					Hostname: "test-host",
					Domain:   "test.local",
				},
			},
			wantErr:   false,
			checkJSON: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := NewJSONConverter()
			result, err := c.ToJSON(context.Background(), tt.opnsense)

			if tt.wantErr {
				assert.Error(t, err)
				if tt.errType != nil {
					assert.ErrorIs(t, err, tt.errType)
				}
				return
			}

			require.NoError(t, err)
			assert.NotEmpty(t, result)

			if tt.checkJSON {
				// Verify the result is valid JSON
				var parsed map[string]any
				err := json.Unmarshal([]byte(result), &parsed)
				assert.NoError(t, err, "Result should be valid JSON")
			}
		})
	}
}
