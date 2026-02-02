package converter

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/EvilBit-Labs/opnDossier/internal/converter/builder"
	"github.com/EvilBit-Labs/opnDossier/internal/log"
	"github.com/sebdah/goldie/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// goldenTestCase defines a test case for golden file testing.
type goldenTestCase struct {
	name          string
	dataFile      string
	comprehensive bool
	goldenFile    string
}

// goldenTestCases defines all golden file test cases for programmatic report generation.
func goldenTestCases() []goldenTestCase {
	return []goldenTestCase{
		{
			name:          "minimal_standard_report",
			dataFile:      "minimal.json",
			comprehensive: false,
			goldenFile:    "minimal_standard",
		},
		{
			name:          "minimal_comprehensive_report",
			dataFile:      "minimal.json",
			comprehensive: true,
			goldenFile:    "minimal_comprehensive",
		},
		{
			name:          "complete_standard_report",
			dataFile:      "complete.json",
			comprehensive: false,
			goldenFile:    "complete_standard",
		},
		{
			name:          "complete_comprehensive_report",
			dataFile:      "complete.json",
			comprehensive: true,
			goldenFile:    "complete_comprehensive",
		},
		{
			name:          "edge_cases_standard_report",
			dataFile:      "edge_cases.json",
			comprehensive: false,
			goldenFile:    "edge_cases_standard",
		},
		{
			name:          "edge_cases_comprehensive_report",
			dataFile:      "edge_cases.json",
			comprehensive: true,
			goldenFile:    "edge_cases_comprehensive",
		},
	}
}

// newGoldie creates a goldie instance with custom normalizer and options.
// The normalizer handles dynamic content (timestamps, versions) for deterministic comparisons.
func newGoldie(t *testing.T) *goldie.Goldie {
	t.Helper()
	return goldie.New(
		t,
		goldie.WithFixtureDir("testdata/golden"),
		goldie.WithNameSuffix(".golden.md"),
		goldie.WithDiffEngine(goldie.ColoredDiff),
		goldie.WithEqualFn(normalizedEqual),
	)
}

// normalizedEqual compares actual and expected content after normalization.
// This allows dynamic content (timestamps, versions) to be ignored in comparisons.
func normalizedEqual(actual, expected []byte) bool {
	return bytes.Equal(normalizeGoldenOutput(actual), normalizeGoldenOutput(expected))
}

// normalizeGoldenOutput removes or normalizes dynamic content from the output
// to ensure deterministic comparisons.
//
// GOLDEN FILE MAINTENANCE NOTE:
// Golden files should contain ACTUAL timestamp and version values (e.g., "2026-02-01 18:56:25"
// and "v1.0.0"), NOT placeholder strings like "[TIMESTAMP]" or "[VERSION]".
// This function normalizes both actual output AND golden file content before comparison,
// converting dynamic values to placeholders. This approach allows:
//   - Golden files to be human-readable with real example values
//   - Tests to pass regardless of when they run or what version is installed
//   - Easy manual inspection of golden files
//
// When updating golden files with `go test -update`, the test framework writes
// the actual generated output (with real timestamps/versions), which is correct.
func normalizeGoldenOutput(output []byte) []byte {
	lines := strings.Split(string(output), "\n")
	var normalized []string

	for _, line := range lines {
		// Normalize generated timestamp
		if strings.Contains(line, "**Generated On**:") {
			line = "- **Generated On**: [TIMESTAMP]"
		}

		// Normalize tool version
		if strings.Contains(line, "**Parsed By**:") {
			line = "- **Parsed By**: opnDossier v[VERSION]"
		}

		normalized = append(normalized, line)
	}

	// Normalize trailing whitespace and newlines
	result := strings.Join(normalized, "\n")
	result = strings.TrimRight(result, "\n\t ")

	return []byte(result)
}

// TestGolden_ProgrammaticReportGeneration tests that programmatic report generation
// produces expected output. This establishes a baseline before template removal.
//
// To update golden files when output changes intentionally, run:
//
//	go test -v ./internal/converter -run TestGolden -update
func TestGolden_ProgrammaticReportGeneration(t *testing.T) {
	testCases := goldenTestCases()

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Load test data
			testData := loadTestDataFromFile(t, tc.dataFile)
			require.NotNil(t, testData, "Test data should load successfully")

			// Create a deterministic builder for golden tests
			mdBuilder := createDeterministicBuilder(t)

			// Generate report using programmatic builder
			var output string
			var err error
			if tc.comprehensive {
				output, err = mdBuilder.BuildComprehensiveReport(testData)
			} else {
				output, err = mdBuilder.BuildStandardReport(testData)
			}
			require.NoError(t, err, "Report generation should not fail")
			require.NotEmpty(t, output, "Generated report should not be empty")

			// Use goldie for assertion (handles -update flag automatically)
			g := newGoldie(t)
			g.Assert(t, tc.goldenFile, []byte(output))
		})
	}
}

// TestGolden_HybridGeneratorProgrammaticMode tests that HybridGenerator in programmatic mode
// produces output consistent with the direct builder usage.
func TestGolden_HybridGeneratorProgrammaticMode(t *testing.T) {
	testCases := []struct {
		name          string
		dataFile      string
		comprehensive bool
	}{
		{"minimal_standard", "minimal.json", false},
		{"minimal_comprehensive", "minimal.json", true},
		{"complete_standard", "complete.json", false},
		{"complete_comprehensive", "complete.json", true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Load test data
			testData := loadTestDataFromFile(t, tc.dataFile)
			require.NotNil(t, testData, "Test data should load successfully")

			// Create deterministic builder
			mdBuilder := createDeterministicBuilder(t)

			// Create HybridGenerator with the builder
			logger, err := log.New(log.Config{Level: "error"})
			require.NoError(t, err)

			hybridGen, err := NewHybridGenerator(mdBuilder, logger)
			require.NoError(t, err)

			// Configure options for programmatic mode (no template flags)
			opts := DefaultOptions().
				WithComprehensive(tc.comprehensive).
				WithSuppressWarnings(true)

			// Generate via HybridGenerator
			hybridOutput, err := hybridGen.Generate(context.Background(), testData, opts)
			require.NoError(t, err)

			// Generate directly via builder
			var directOutput string
			if tc.comprehensive {
				directOutput, err = mdBuilder.BuildComprehensiveReport(testData)
			} else {
				directOutput, err = mdBuilder.BuildStandardReport(testData)
			}
			require.NoError(t, err)

			// Normalize both outputs for comparison
			normalizedHybrid := string(normalizeGoldenOutput([]byte(hybridOutput)))
			normalizedDirect := string(normalizeGoldenOutput([]byte(directOutput)))

			// They should be identical
			assert.Equal(t, normalizedDirect, normalizedHybrid,
				"HybridGenerator programmatic output should match direct builder output")
		})
	}
}

// TestGolden_ReportStructureIntegrity verifies that generated reports have
// the expected structure regardless of the specific content.
func TestGolden_ReportStructureIntegrity(t *testing.T) {
	testCases := goldenTestCases()

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Load test data
			testData := loadTestDataFromFile(t, tc.dataFile)
			require.NotNil(t, testData)

			// Generate report
			mdBuilder := createDeterministicBuilder(t)
			var output string
			var err error
			if tc.comprehensive {
				output, err = mdBuilder.BuildComprehensiveReport(testData)
			} else {
				output, err = mdBuilder.BuildStandardReport(testData)
			}
			require.NoError(t, err)

			// Verify essential structure elements
			verifyReportStructure(t, output, tc.comprehensive)
		})
	}
}

// verifyReportStructure checks that a report has the expected structural elements.
func verifyReportStructure(t *testing.T, output string, comprehensive bool) {
	t.Helper()

	// All reports should have these elements
	requiredElements := []string{
		"# OPNsense Configuration Summary",
		"## System Information",
		"## Table of Contents",
	}

	// Check required elements
	for _, elem := range requiredElements {
		assert.Contains(t, output, elem, "Report should contain: %s", elem)
	}

	// Check for proper markdown heading hierarchy
	assert.Contains(t, output, "# ", "Should have H1 headings")
	assert.Contains(t, output, "## ", "Should have H2 headings")

	// Check table of contents links
	tocLinks := []string{
		"[System Configuration]",
		"[Interfaces]",
		"[Firewall Rules]",
		"[NAT Configuration]",
	}
	for _, link := range tocLinks {
		assert.Contains(t, output, link, "TOC should contain: %s", link)
	}

	// Comprehensive reports should have additional sections
	if comprehensive {
		assert.Contains(t, output, "[System Groups]", "Comprehensive report should have System Groups in TOC")
	}
}

// createDeterministicBuilder creates a MarkdownBuilder with deterministic output
// by overriding time-sensitive values.
func createDeterministicBuilder(t *testing.T) *builder.MarkdownBuilder {
	t.Helper()

	// Create a builder and configure it for deterministic output
	mdBuilder := builder.NewMarkdownBuilder()
	// The builder uses time.Now() and constants.Version internally,
	// which we'll normalize in normalizeGoldenOutput
	return mdBuilder
}

// TestGolden_ConsistencyAcrossRuns ensures that multiple runs produce identical output.
func TestGolden_ConsistencyAcrossRuns(t *testing.T) {
	testData := loadTestDataFromFile(t, "complete.json")
	require.NotNil(t, testData)

	mdBuilder := createDeterministicBuilder(t)

	// Generate the same report multiple times
	outputs := make([]string, 5)
	for i := range 5 {
		output, err := mdBuilder.BuildStandardReport(testData)
		require.NoError(t, err)
		outputs[i] = string(normalizeGoldenOutput([]byte(output)))

		// Small sleep to ensure any time-based variations would appear
		time.Sleep(10 * time.Millisecond)
	}

	// All outputs should be identical
	for i := 1; i < len(outputs); i++ {
		assert.Equal(t, outputs[0], outputs[i],
			"Output from run %d should match run 1", i+1)
	}
}
