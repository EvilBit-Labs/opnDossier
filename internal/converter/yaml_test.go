package converter

import (
	"context"
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/model"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestYAMLConverter_ToYAML(t *testing.T) {
	tests := GetCommonTestCases()
	for i := range tests {
		if tests[i].Name == "valid opnsense" {
			tests[i].ValidateOut = func(t *testing.T, result string) {
				t.Helper()
				var parsed map[string]any
				err := yaml.Unmarshal([]byte(result), &parsed)
				require.NoError(t, err, "Result should be valid YAML")
			}
		}
	}

	c := NewYAMLConverter()
	convertFunc := func(ctx context.Context, opnsense *model.OpnSenseDocument) (string, error) {
		return c.ToYAML(ctx, opnsense)
	}
	RunConverterTests(t, tests, convertFunc)
}
