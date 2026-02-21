package converter

import (
	"context"
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/model/common"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestYAMLConverter_ToYAML(t *testing.T) {
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

	c := NewYAMLConverter()
	convertFunc := func(ctx context.Context, data *common.CommonDevice) (string, error) {
		return c.ToYAML(ctx, data)
	}
	RunConverterTests(t, tests, convertFunc)
}
