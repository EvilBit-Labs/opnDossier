package converter

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/unclesp1d3r/opnFocus/internal/model"
)

// TestCase represents a test case for converter tests.
type TestCase struct {
	Name        string
	OpnSense    *model.OpnSenseDocument
	WantErr     bool
	ErrType     error
	ValidateOut func(t *testing.T, result string) // Function to validate the output format
}

// GetCommonTestCases returns common test cases for both JSON and YAML converters.
func GetCommonTestCases() []TestCase {
	return []TestCase{
		{
			Name:     "nil opnsense",
			OpnSense: nil,
			WantErr:  true,
			ErrType:  ErrNilOpnSenseDocument,
		},
		{
			Name: "valid opnsense",
			OpnSense: &model.OpnSenseDocument{
				Version: "1.0.0",
				System: model.System{
					Hostname: "test-host",
					Domain:   "test.local",
				},
			},
			WantErr: false,
		},
	}
}

// RunConverterTests runs the standard converter test suite.
func RunConverterTests(
	t *testing.T,
	tests []TestCase,
	convertFunc func(context.Context, *model.OpnSenseDocument) (string, error),
) {
	t.Helper()
	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			result, err := convertFunc(context.Background(), tt.OpnSense)

			if tt.WantErr {
				require.Error(t, err)

				if tt.ErrType != nil {
					require.ErrorIs(t, err, tt.ErrType)
				}

				return
			}

			require.NoError(t, err)
			assert.NotEmpty(t, result)

			if tt.ValidateOut != nil {
				tt.ValidateOut(t, result)
			}
		})
	}
}
