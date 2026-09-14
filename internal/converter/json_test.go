package converter

import (
	"context"
	"encoding/json"
	"testing"

	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
	"github.com/stretchr/testify/require"
)

func TestJSONHandler_Generate(t *testing.T) {
	tests := GetCommonTestCases()
	for i := range tests {
		if tests[i].Name == "valid device" {
			tests[i].ValidateOut = func(t *testing.T, result string) {
				t.Helper()
				var parsed map[string]any
				err := json.Unmarshal([]byte(result), &parsed)
				require.NoError(t, err, "Result should be valid JSON")
			}
		}
	}

	gen := newTestGenerator(t)
	opts := DefaultOptions()
	opts.Format = FormatJSON

	convertFunc := func(ctx context.Context, data *common.CommonDevice) (string, error) {
		return gen.Generate(ctx, data, opts)
	}
	RunConverterTests(t, tests, convertFunc)
}
