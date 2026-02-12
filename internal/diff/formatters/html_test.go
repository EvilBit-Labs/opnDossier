package formatters

import (
	"bytes"
	"testing"
	"time"

	"github.com/EvilBit-Labs/opnDossier/internal/diff"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewHTMLFormatter(t *testing.T) {
	var buf bytes.Buffer
	formatter := NewHTMLFormatter(&buf)
	assert.NotNil(t, formatter)
}

func TestHTMLFormatter_Format_NoChanges(t *testing.T) {
	var buf bytes.Buffer
	formatter := NewHTMLFormatter(&buf)

	result := diff.NewResult()
	err := formatter.Format(result)
	require.NoError(t, err)

	output := buf.String()
	assert.Contains(t, output, "<!DOCTYPE html>")
	assert.Contains(t, output, "No changes detected")
	assert.Contains(t, output, "</html>")
}

func TestHTMLFormatter_Format_WithChanges(t *testing.T) {
	var buf bytes.Buffer
	formatter := NewHTMLFormatter(&buf)

	result := diff.NewResult()
	result.Metadata = diff.Metadata{
		OldFile:     "old-config.xml",
		NewFile:     "new-config.xml",
		ComparedAt:  time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		ToolVersion: "1.0.0",
	}
	result.AddChange(diff.Change{
		Type:           diff.ChangeAdded,
		Section:        diff.SectionFirewall,
		Path:           "filter.rule[uuid=abc]",
		Description:    "Added rule: Allow HTTP",
		NewValue:       "type=pass, src=any, dst=any:80",
		SecurityImpact: "high",
	})
	result.AddChange(diff.Change{
		Type:        diff.ChangeModified,
		Section:     diff.SectionSystem,
		Path:        "system.hostname",
		Description: "Hostname changed",
		OldValue:    "old-host",
		NewValue:    "new-host",
	})

	err := formatter.Format(result)
	require.NoError(t, err)

	output := buf.String()

	// Verify HTML structure
	assert.Contains(t, output, "<!DOCTYPE html>")
	assert.Contains(t, output, "</html>")

	// Verify metadata
	assert.Contains(t, output, "old-config.xml")
	assert.Contains(t, output, "new-config.xml")

	// Verify summary counts
	assert.Contains(t, output, "Added")
	assert.Contains(t, output, "Modified")

	// Verify change content
	assert.Contains(t, output, "Added rule: Allow HTTP")
	assert.Contains(t, output, "Hostname changed")
	assert.Contains(t, output, "old-host")
	assert.Contains(t, output, "new-host")

	// Verify security badge
	assert.Contains(t, output, "badge-high")

	// Verify CSS is embedded
	assert.Contains(t, output, "<style>")
	assert.Contains(t, output, "--bg:")

	// Verify JS is embedded
	assert.Contains(t, output, "<script>")
	assert.Contains(t, output, "toggle-all")
}

func TestHTMLFormatter_Format_SecurityBadges(t *testing.T) {
	tests := []struct {
		name     string
		impact   string
		badgeCSS string
	}{
		{"high", "high", "badge-high"},
		{"medium", "medium", "badge-medium"},
		{"low", "low", "badge-low"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			formatter := NewHTMLFormatter(&buf)

			result := diff.NewResult()
			result.AddChange(diff.Change{
				Type:           diff.ChangeModified,
				Section:        diff.SectionSystem,
				Path:           "test",
				Description:    "Test change",
				SecurityImpact: tt.impact,
			})

			err := formatter.Format(result)
			require.NoError(t, err)
			assert.Contains(t, buf.String(), tt.badgeCSS)
		})
	}
}

func TestHTMLFormatter_Format_RiskSummary(t *testing.T) {
	var buf bytes.Buffer
	formatter := NewHTMLFormatter(&buf)

	result := diff.NewResult()
	result.AddChange(diff.Change{
		Type:           diff.ChangeAdded,
		Section:        diff.SectionFirewall,
		Path:           "test",
		Description:    "Test",
		SecurityImpact: "high",
	})
	result.RiskSummary = diff.RiskSummary{
		Score:  10,
		High:   1,
		Medium: 0,
		Low:    0,
	}

	err := formatter.Format(result)
	require.NoError(t, err)

	output := buf.String()
	assert.Contains(t, output, "Security Risk Score")
	assert.Contains(t, output, "1 High")
}

func TestHTMLFormatter_InterfaceCompliance(_ *testing.T) {
	var buf bytes.Buffer
	var _ Formatter = NewHTMLFormatter(&buf)
}

func TestHTMLFormatter_Format_EmbeddedAssets(t *testing.T) {
	// Verify embedded assets are not empty
	assert.NotEmpty(t, reportTemplate, "report template should not be empty")
	assert.NotEmpty(t, stylesCSS, "CSS should not be empty")
	assert.NotEmpty(t, scriptsJS, "JS should not be empty")
}

func TestHTMLFormatter_Format_SelfContained(t *testing.T) {
	var buf bytes.Buffer
	formatter := NewHTMLFormatter(&buf)

	result := diff.NewResult()
	result.AddChange(diff.Change{
		Type:    diff.ChangeAdded,
		Section: diff.SectionSystem,
		Path:    "test",
	})

	err := formatter.Format(result)
	require.NoError(t, err)

	output := buf.String()

	// Must NOT contain external resource references
	assert.NotContains(t, output, "href=\"http", "should not reference external CSS")
	assert.NotContains(t, output, "src=\"http", "should not reference external JS")
	assert.NotContains(t, output, "cdn", "should not reference CDN")
}
