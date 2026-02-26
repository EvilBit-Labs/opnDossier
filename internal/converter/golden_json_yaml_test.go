package converter

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/sebdah/goldie/v2"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// jsonYAMLGoldenTestCase defines a test case for JSON/YAML golden file testing.
type jsonYAMLGoldenTestCase struct {
	name     string
	dataFile string
}

// jsonYAMLGoldenTestCases returns all test cases for JSON and YAML golden file testing.
func jsonYAMLGoldenTestCases() []jsonYAMLGoldenTestCase {
	return []jsonYAMLGoldenTestCase{
		{
			name:     "minimal_unredacted",
			dataFile: "minimal.json",
		},
		{
			name:     "complete_unredacted",
			dataFile: "complete.json",
		},
		{
			name:     "edge_cases_unredacted",
			dataFile: "edge_cases.json",
		},
	}
}

// jsonYAMLRedactedTestCases returns all test cases for JSON and YAML golden file testing with redaction enabled.
func jsonYAMLRedactedTestCases() []jsonYAMLGoldenTestCase {
	return []jsonYAMLGoldenTestCase{
		{
			name:     "minimal_redacted",
			dataFile: "minimal.json",
		},
		{
			name:     "complete_redacted",
			dataFile: "complete.json",
		},
		{
			name:     "edge_cases_redacted",
			dataFile: "edge_cases.json",
		},
	}
}

// newJSONGoldie creates a goldie instance configured for JSON golden files.
func newJSONGoldie(t *testing.T) *goldie.Goldie {
	t.Helper()

	return goldie.New(
		t,
		goldie.WithFixtureDir("testdata/golden"),
		goldie.WithNameSuffix(".golden.json"),
		goldie.WithDiffEngine(goldie.ColoredDiff),
		goldie.WithEqualFn(normalizedBytesEqual),
	)
}

// newYAMLGoldie creates a goldie instance configured for YAML golden files.
func newYAMLGoldie(t *testing.T) *goldie.Goldie {
	t.Helper()

	return goldie.New(
		t,
		goldie.WithFixtureDir("testdata/golden"),
		goldie.WithNameSuffix(".golden.yaml"),
		goldie.WithDiffEngine(goldie.ColoredDiff),
		goldie.WithEqualFn(normalizedBytesEqual),
	)
}

// normalizedBytesEqual compares actual and expected content after trailing whitespace normalization.
func normalizedBytesEqual(actual, expected []byte) bool {
	return bytes.Equal(normalizeSerializedOutput(actual), normalizeSerializedOutput(expected))
}

// normalizeSerializedOutput trims trailing whitespace and newlines from serialized output.
// No timestamp normalization is needed because prepareForExport does not inject
// time-based values into JSON/YAML output.
func normalizeSerializedOutput(output []byte) []byte {
	result := strings.TrimRight(string(output), "\n\t ")

	return []byte(result)
}

// TestGolden_JSONRedacted tests that JSON export produces expected output for redacted mode.
//
// To update: go test ./internal/converter -run TestGolden_JSONRedacted -update.
func TestGolden_JSONRedacted(t *testing.T) {
	t.Parallel()

	for _, tc := range jsonYAMLRedactedTestCases() {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			testData := loadTestDataFromFile(t, tc.dataFile)
			require.NotNil(t, testData, "Test data should load successfully")

			target := prepareForExport(testData, true)

			output, err := json.MarshalIndent(target, "", "  ")
			require.NoError(t, err, "JSON marshalling should not fail")
			require.NotEmpty(t, output, "JSON output should not be empty")

			g := newJSONGoldie(t)
			g.Assert(t, tc.name, output)
		})
	}
}

// TestGolden_YAMLRedacted tests that YAML export produces expected output for redacted mode.
//
// To update: go test ./internal/converter -run TestGolden_YAMLRedacted -update.
func TestGolden_YAMLRedacted(t *testing.T) {
	t.Parallel()

	for _, tc := range jsonYAMLRedactedTestCases() {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			testData := loadTestDataFromFile(t, tc.dataFile)
			require.NotNil(t, testData, "Test data should load successfully")

			target := prepareForExport(testData, true)

			output, err := yaml.Marshal(target)
			require.NoError(t, err, "YAML marshalling should not fail")
			require.NotEmpty(t, output, "YAML output should not be empty")

			g := newYAMLGoldie(t)
			g.Assert(t, tc.name, output)
		})
	}
}

// TestGolden_JSONUnredacted tests that JSON export produces expected output for unredacted mode.
//
// To update: go test ./internal/converter -run TestGolden_JSONUnredacted -update.
func TestGolden_JSONUnredacted(t *testing.T) {
	t.Parallel()

	for _, tc := range jsonYAMLGoldenTestCases() {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			testData := loadTestDataFromFile(t, tc.dataFile)
			require.NotNil(t, testData, "Test data should load successfully")

			target := prepareForExport(testData, false)

			output, err := json.MarshalIndent(target, "", "  ")
			require.NoError(t, err, "JSON marshalling should not fail")
			require.NotEmpty(t, output, "JSON output should not be empty")

			g := newJSONGoldie(t)
			g.Assert(t, tc.name, output)
		})
	}
}

// TestGolden_YAMLUnredacted tests that YAML export produces expected output for unredacted mode.
//
// To update: go test ./internal/converter -run TestGolden_YAMLUnredacted -update.
func TestGolden_YAMLUnredacted(t *testing.T) {
	t.Parallel()

	for _, tc := range jsonYAMLGoldenTestCases() {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			testData := loadTestDataFromFile(t, tc.dataFile)
			require.NotNil(t, testData, "Test data should load successfully")

			target := prepareForExport(testData, false)

			output, err := yaml.Marshal(target)
			require.NoError(t, err, "YAML marshalling should not fail")
			require.NotEmpty(t, output, "YAML output should not be empty")

			g := newYAMLGoldie(t)
			g.Assert(t, tc.name, output)
		})
	}
}
