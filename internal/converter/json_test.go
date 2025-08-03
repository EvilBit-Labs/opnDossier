package converter

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/model"
	"github.com/stretchr/testify/require"
)

func TestJSONConverter_ToJSON(t *testing.T) {
	tests := GetCommonTestCases()
	for i := range tests {
		if tests[i].Name == "valid opnsense" {
			tests[i].ValidateOut = func(t *testing.T, result string) {
				t.Helper()
				var parsed map[string]any
				err := json.Unmarshal([]byte(result), &parsed)
				require.NoError(t, err, "Result should be valid JSON")
			}
		}
	}

	c := NewJSONConverter()
	convertFunc := func(ctx context.Context, opnsense *model.OpnSenseDocument) (string, error) {
		return c.ToJSON(ctx, opnsense)
	}
	RunConverterTests(t, tests, convertFunc)
}
