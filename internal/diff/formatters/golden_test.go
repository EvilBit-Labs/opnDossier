package formatters

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/EvilBit-Labs/opnDossier/internal/diff"
	"github.com/sebdah/goldie/v2"
	"github.com/stretchr/testify/require"
)

// goldenDiffTestCase defines a test case for diff formatter golden file testing.
type goldenDiffTestCase struct {
	name       string
	goldenFile string
	result     *diff.Result
}

// goldenDiffTestCases returns all golden file test cases for diff formatters.
// Each case uses deterministic, fixed metadata to ensure reproducible output.
func goldenDiffTestCases() []goldenDiffTestCase {
	return []goldenDiffTestCase{
		{
			name:       "no_changes",
			goldenFile: "no_changes",
			result:     buildNoChangesResult(),
		},
		{
			name:       "single_section",
			goldenFile: "single_section",
			result:     buildSingleSectionResult(),
		},
		{
			name:       "multi_section_with_security",
			goldenFile: "multi_section_with_security",
			result:     buildMultiSectionResult(),
		},
	}
}

// buildNoChangesResult creates a diff result with metadata but no changes.
func buildNoChangesResult() *diff.Result {
	result := diff.NewResult()
	result.Metadata = diff.Metadata{
		OldFile:     "old-config.xml",
		NewFile:     "new-config.xml",
		ComparedAt:  time.Date(2026, 1, 15, 10, 30, 0, 0, time.UTC),
		ToolVersion: "1.0.0",
	}
	result.DeviceType = diff.DeviceTypeInfo{Old: "opnsense", New: "opnsense"}
	return result
}

// buildSingleSectionResult creates a diff result with changes in a single section.
func buildSingleSectionResult() *diff.Result {
	result := diff.NewResult()
	result.Metadata = diff.Metadata{
		OldFile:     "baseline.xml",
		NewFile:     "updated.xml",
		ComparedAt:  time.Date(2026, 1, 15, 10, 30, 0, 0, time.UTC),
		ToolVersion: "1.0.0",
	}
	result.DeviceType = diff.DeviceTypeInfo{Old: "opnsense", New: "opnsense"}
	result.AddChange(diff.Change{
		Type:        diff.ChangeModified,
		Section:     diff.SectionSystem,
		Path:        "system.hostname",
		Description: "Hostname changed",
		OldValue:    "fw-prod-01",
		NewValue:    "fw-prod-02",
	})
	result.AddChange(diff.Change{
		Type:        diff.ChangeModified,
		Section:     diff.SectionSystem,
		Path:        "system.timezone",
		Description: "Timezone changed",
		OldValue:    "America/New_York",
		NewValue:    "UTC",
	})
	return result
}

// buildMultiSectionResult creates a diff result with changes across multiple
// sections including all security impact levels.
func buildMultiSectionResult() *diff.Result {
	result := diff.NewResult()
	result.Metadata = diff.Metadata{
		OldFile:     "prod-config-v1.xml",
		NewFile:     "prod-config-v2.xml",
		ComparedAt:  time.Date(2026, 1, 15, 10, 30, 0, 0, time.UTC),
		ToolVersion: "1.0.0",
	}
	result.DeviceType = diff.DeviceTypeInfo{Old: "opnsense", New: "opnsense"}

	// Firewall changes with security impacts
	result.AddChange(diff.Change{
		Type:           diff.ChangeAdded,
		Section:        diff.SectionFirewall,
		Path:           "filter.rule[uuid=abc-123]",
		Description:    "Added rule: Allow HTTP",
		NewValue:       "type=pass, src=any, dst=any:80",
		SecurityImpact: "high",
	})
	result.AddChange(diff.Change{
		Type:           diff.ChangeRemoved,
		Section:        diff.SectionFirewall,
		Path:           "filter.rule[uuid=def-456]",
		Description:    "Removed rule: Legacy FTP",
		OldValue:       "type=pass, proto=tcp, dst=any:21",
		SecurityImpact: "medium",
	})
	result.AddChange(diff.Change{
		Type:           diff.ChangeModified,
		Section:        diff.SectionFirewall,
		Path:           "filter.rule[uuid=ghi-789]",
		Description:    "Modified rule: SSH access restricted",
		OldValue:       "src=any",
		NewValue:       "src=10.0.0.0/8",
		SecurityImpact: "low",
	})

	// System changes
	result.AddChange(diff.Change{
		Type:        diff.ChangeModified,
		Section:     diff.SectionSystem,
		Path:        "system.hostname",
		Description: "Hostname changed",
		OldValue:    "fw-old",
		NewValue:    "fw-new",
	})

	// Interface changes
	result.AddChange(diff.Change{
		Type:        diff.ChangeAdded,
		Section:     diff.SectionInterfaces,
		Path:        "interfaces.opt1",
		Description: "Added interface: opt1 (DMZ)",
		NewValue:    "enable=1, if=igb2, descr=DMZ",
	})

	return result
}

// newHTMLGoldie creates a goldie instance for HTML golden file tests.
func newHTMLGoldie(t *testing.T) *goldie.Goldie {
	t.Helper()
	return goldie.New(
		t,
		goldie.WithFixtureDir("testdata/golden"),
		goldie.WithNameSuffix(".golden.html"),
		goldie.WithDiffEngine(goldie.ColoredDiff),
		goldie.WithEqualFn(normalizedHTMLEqual),
	)
}

// newMarkdownGoldie creates a goldie instance for markdown golden file tests.
func newMarkdownGoldie(t *testing.T) *goldie.Goldie {
	t.Helper()
	return goldie.New(
		t,
		goldie.WithFixtureDir("testdata/golden"),
		goldie.WithNameSuffix(".golden.md"),
		goldie.WithDiffEngine(goldie.ColoredDiff),
		goldie.WithEqualFn(normalizedTextEqual),
	)
}

// newJSONGoldie creates a goldie instance for JSON golden file tests.
func newJSONGoldie(t *testing.T) *goldie.Goldie {
	t.Helper()
	return goldie.New(
		t,
		goldie.WithFixtureDir("testdata/golden"),
		goldie.WithNameSuffix(".golden.json"),
		goldie.WithDiffEngine(goldie.ColoredDiff),
		goldie.WithEqualFn(normalizedTextEqual),
	)
}

// normalizedHTMLEqual compares actual and expected HTML content after normalization.
func normalizedHTMLEqual(actual, expected []byte) bool {
	return bytes.Equal(normalizeOutput(actual), normalizeOutput(expected))
}

// normalizedTextEqual compares actual and expected text content after normalization.
func normalizedTextEqual(actual, expected []byte) bool {
	return bytes.Equal(normalizeOutput(actual), normalizeOutput(expected))
}

// normalizeOutput normalizes trailing whitespace and newlines for deterministic comparisons.
func normalizeOutput(output []byte) []byte {
	result := strings.TrimRight(string(output), "\n\t ")
	return []byte(result)
}

// TestGolden_HTMLFormatter tests that the HTML formatter produces expected output.
//
// To update golden files when output changes intentionally, run:
//
//	go test -v ./internal/diff/formatters -run TestGolden_HTMLFormatter -update
func TestGolden_HTMLFormatter(t *testing.T) {
	testCases := goldenDiffTestCases()

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			formatter := NewHTMLFormatter(&buf)

			err := formatter.Format(tc.result)
			require.NoError(t, err, "HTML formatter should not fail")

			output := buf.String()
			require.NotEmpty(t, output, "HTML output should not be empty")

			g := newHTMLGoldie(t)
			g.Assert(t, "html_"+tc.goldenFile, []byte(output))
		})
	}
}

// TestGolden_MarkdownFormatter tests that the markdown formatter produces expected output.
//
// To update golden files when output changes intentionally, run:
//
//	go test -v ./internal/diff/formatters -run TestGolden_MarkdownFormatter -update
func TestGolden_MarkdownFormatter(t *testing.T) {
	testCases := goldenDiffTestCases()

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			formatter := NewMarkdownFormatter(&buf)

			err := formatter.Format(tc.result)
			require.NoError(t, err, "Markdown formatter should not fail")

			output := buf.String()
			require.NotEmpty(t, output, "Markdown output should not be empty")

			g := newMarkdownGoldie(t)
			g.Assert(t, "markdown_"+tc.goldenFile, []byte(output))
		})
	}
}

// TestGolden_JSONFormatter tests that the JSON formatter produces expected output.
//
// To update golden files when output changes intentionally, run:
//
//	go test -v ./internal/diff/formatters -run TestGolden_JSONFormatter -update
func TestGolden_JSONFormatter(t *testing.T) {
	testCases := goldenDiffTestCases()

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			formatter := NewJSONFormatter(&buf)

			err := formatter.Format(tc.result)
			require.NoError(t, err, "JSON formatter should not fail")

			output := buf.String()
			require.NotEmpty(t, output, "JSON output should not be empty")

			g := newJSONGoldie(t)
			g.Assert(t, "json_"+tc.goldenFile, []byte(output))
		})
	}
}
