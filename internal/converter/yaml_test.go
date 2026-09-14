package converter

import (
	"context"
	"testing"

	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestYAMLHandler_Generate(t *testing.T) {
	tests := GetCommonTestCases()
	for i := range tests {
		if tests[i].Name == "valid device" {
			tests[i].ValidateOut = func(t *testing.T, result string) {
				t.Helper()
				var parsed map[string]any
				err := yaml.Unmarshal([]byte(result), &parsed)
				require.NoError(t, err, "Result should be valid YAML")
			}
		}
	}

	gen := newTestGenerator(t)
	opts := DefaultOptions()
	opts.Format = FormatYAML

	convertFunc := func(ctx context.Context, data *common.CommonDevice) (string, error) {
		return gen.Generate(ctx, data, opts)
	}
	RunConverterTests(t, tests, convertFunc)
}
