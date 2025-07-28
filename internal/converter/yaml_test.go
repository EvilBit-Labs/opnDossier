package converter

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/unclesp1d3r/opnFocus/internal/model"
	"gopkg.in/yaml.v3"
)

func TestYAMLConverter_ToYAML(t *testing.T) {
	tests := []struct {
		name      string
		opnsense  *model.OpnSenseDocument
		wantErr   bool
		errType   error
		checkYAML bool
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
			checkYAML: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := NewYAMLConverter()
			result, err := c.ToYAML(context.Background(), tt.opnsense)

			if tt.wantErr {
				assert.Error(t, err)
				if tt.errType != nil {
					assert.ErrorIs(t, err, tt.errType)
				}
				return
			}

			require.NoError(t, err)
			assert.NotEmpty(t, result)

			if tt.checkYAML {
				// Verify the result is valid YAML
				var parsed map[string]interface{}
				err := yaml.Unmarshal([]byte(result), &parsed)
				assert.NoError(t, err, "Result should be valid YAML")
			}
		})
	}
}
