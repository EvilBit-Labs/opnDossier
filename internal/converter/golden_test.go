package converter

import (
	"context"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/EvilBit-Labs/opnDossier/internal/converter/builder"
	"github.com/EvilBit-Labs/opnDossier/internal/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// updateGolden is a flag to regenerate golden files when running tests with -update.
var updateGolden = flag.Bool("update", false, "update golden files")

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
			goldenFile:    "minimal_standard.golden.md",
		},
		{
			name:          "minimal_comprehensive_report",
			dataFile:      "minimal.json",
			comprehensive: true,
			goldenFile:    "minimal_comprehensive.golden.md",
		},
		{
			name:          "complete_standard_report",
			dataFile:      "complete.json",
			comprehensive: false,
			goldenFile:    "complete_standard.golden.md",
		},
		{
			name:          "complete_comprehensive_report",
			dataFile:      "complete.json",
			comprehensive: true,
			goldenFile:    "complete_comprehensive.golden.md",
		},
		{
			name:          "edge_cases_standard_report",
			dataFile:      "edge_cases.json",
			comprehensive: false,
			goldenFile:    "edge_cases_standard.golden.md",
		},
		{
			name:          "edge_cases_comprehensive_report",
			dataFile:      "edge_cases.json",
			comprehensive: true,
			goldenFile:    "edge_cases_comprehensive.golden.md",
		},
	}
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

			// Normalize output to handle dynamic content
			normalizedOutput := normalizeGoldenOutput(output)

			goldenPath := filepath.Join("testdata", "golden", tc.goldenFile)

			if *updateGolden {
				// Update the golden file
				updateGoldenFile(t, goldenPath, normalizedOutput)
				t.Logf("Updated golden file: %s", goldenPath)
				return
			}

			// Compare against golden file
			expected := loadGoldenFile(t, goldenPath)
			normalizedExpected := normalizeGoldenOutput(expected)

			if normalizedOutput != normalizedExpected {
				// Find first difference for better error reporting
				diffStart, diffEnd := findDifferenceLocation(normalizedExpected, normalizedOutput)
				t.Errorf(
					"Output does not match golden file %s\n"+
						"Difference starts around line %d\n"+
						"Expected snippet:\n%s\n\n"+
						"Actual snippet:\n%s\n\n"+
						"Run with -update flag to regenerate golden files if this change is intentional",
					tc.goldenFile,
					diffStart,
					getSnippetAroundLine(normalizedExpected, diffStart, 3),
					getSnippetAroundLine(normalizedOutput, diffEnd, 3),
				)
			}
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

			// Normalize both outputs
			normalizedHybrid := normalizeGoldenOutput(hybridOutput)
			normalizedDirect := normalizeGoldenOutput(directOutput)

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

// normalizeGoldenOutput removes or normalizes dynamic content from the output
// to ensure deterministic comparisons.
func normalizeGoldenOutput(output string) string {
	lines := strings.Split(output, "\n")
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

	return result
}

// loadGoldenFile loads a golden file from the testdata/golden directory.
func loadGoldenFile(t *testing.T, path string) string {
	t.Helper()

	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		t.Fatalf("Golden file not found: %s\nRun with -update flag to create it", path)
	}
	require.NoError(t, err, "Failed to read golden file: %s", path)

	return string(data)
}

// updateGoldenFile writes the output to a golden file.
func updateGoldenFile(t *testing.T, path, content string) {
	t.Helper()

	// Ensure the directory exists
	dir := filepath.Dir(path)
	err := os.MkdirAll(dir, 0o755)
	require.NoError(t, err, "Failed to create golden file directory")

	// Write the file with restrictive permissions (test data, not sensitive)
	err = os.WriteFile(path, []byte(content), 0o600)
	require.NoError(t, err, "Failed to write golden file: %s", path)
}

// findDifferenceLocation finds approximately where two strings start to differ.
// Returns the line numbers (expectedLineNum, actualLineNum) in both strings.
//
//nolint:gocritic // unnamedResult conflicts with nonamedreturns, return semantics clear from docstring
func findDifferenceLocation(expected, actual string) (int, int) {
	expectedLines := strings.Split(expected, "\n")
	actualLines := strings.Split(actual, "\n")

	maxLines := max(len(expectedLines), len(actualLines))

	for i := range maxLines {
		expectedLine := ""
		actualLine := ""

		if i < len(expectedLines) {
			expectedLine = expectedLines[i]
		}
		if i < len(actualLines) {
			actualLine = actualLines[i]
		}

		if expectedLine != actualLine {
			return i + 1, i + 1
		}
	}

	return len(expectedLines), len(actualLines)
}

// getSnippetAroundLine returns a few lines around the specified line number.
func getSnippetAroundLine(content string, lineNum, contextLines int) string {
	lines := strings.Split(content, "\n")

	start := max(lineNum-contextLines-1, 0)
	end := min(lineNum+contextLines, len(lines))

	var snippet []string
	for i := start; i < end; i++ {
		prefix := "  "
		if i == lineNum-1 {
			prefix = "> "
		}
		snippet = append(snippet, prefix+lines[i])
	}

	return strings.Join(snippet, "\n")
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
		outputs[i] = normalizeGoldenOutput(output)

		// Small sleep to ensure any time-based variations would appear
		time.Sleep(10 * time.Millisecond)
	}

	// All outputs should be identical
	for i := 1; i < len(outputs); i++ {
		assert.Equal(t, outputs[0], outputs[i],
			"Output from run %d should match run 1", i+1)
	}
}
