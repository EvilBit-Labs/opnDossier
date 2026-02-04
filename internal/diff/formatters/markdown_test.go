package formatters

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/EvilBit-Labs/opnDossier/internal/diff"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewMarkdownFormatter(t *testing.T) {
	var buf bytes.Buffer
	formatter := NewMarkdownFormatter(&buf)

	assert.NotNil(t, formatter)
	assert.Equal(t, &buf, formatter.writer)
}

func TestMarkdownFormatter_Format_NoChanges(t *testing.T) {
	var buf bytes.Buffer
	formatter := NewMarkdownFormatter(&buf)

	result := diff.NewResult()

	err := formatter.Format(result)
	require.NoError(t, err)

	output := buf.String()
	assert.Contains(t, output, "# Configuration Diff")
	assert.Contains(t, output, "## Summary")
	assert.Contains(t, output, "*No changes detected.*")
}

func TestMarkdownFormatter_Format_WithChanges(t *testing.T) {
	var buf bytes.Buffer
	formatter := NewMarkdownFormatter(&buf)

	result := diff.NewResult()
	result.Metadata.OldFile = "old.xml"
	result.Metadata.NewFile = "new.xml"
	result.Metadata.ComparedAt = time.Date(2024, 1, 15, 10, 30, 0, 0, time.UTC)
	result.Metadata.ToolVersion = "1.0.0"

	result.AddChange(diff.Change{
		Type:           diff.ChangeAdded,
		Section:        diff.SectionFirewall,
		Path:           "filter.rule[uuid=123]",
		Description:    "Added rule: Allow SSH",
		NewValue:       "type=pass, proto=tcp, dst=any:22",
		SecurityImpact: "medium",
	})

	err := formatter.Format(result)
	require.NoError(t, err)

	output := buf.String()

	// Check header
	assert.Contains(t, output, "# Configuration Diff")

	// Check metadata
	assert.Contains(t, output, "old.xml")
	assert.Contains(t, output, "new.xml")
	assert.Contains(t, output, "2024-01-15")
	assert.Contains(t, output, "1.0.0")

	// Check summary table
	assert.Contains(t, output, "| Added | 1 |")
	assert.Contains(t, output, "| **Total** | **1** |")

	// Check section
	assert.Contains(t, output, "## Firewall")

	// Check change
	assert.Contains(t, output, "Allow SSH")
	assert.Contains(t, output, "MEDIUM")
}

func TestMarkdownFormatter_Format_MultipleSections(t *testing.T) {
	var buf bytes.Buffer
	formatter := NewMarkdownFormatter(&buf)

	result := diff.NewResult()
	result.AddChange(diff.Change{
		Type:        diff.ChangeAdded,
		Section:     diff.SectionInterfaces,
		Path:        "interfaces.opt1",
		Description: "Added interface: opt1",
	})
	result.AddChange(diff.Change{
		Type:        diff.ChangeModified,
		Section:     diff.SectionSystem,
		Path:        "system.hostname",
		Description: "Hostname changed",
	})

	err := formatter.Format(result)
	require.NoError(t, err)

	output := buf.String()

	// Both sections should appear
	assert.Contains(t, output, "## Interfaces")
	assert.Contains(t, output, "## System")

	// Sections should be sorted alphabetically
	interfacesIdx := strings.Index(output, "## Interfaces")
	systemIdx := strings.Index(output, "## System")
	assert.Less(t, interfacesIdx, systemIdx)
}

func TestMarkdownFormatter_Format_SecurityBadges(t *testing.T) {
	tests := []struct {
		name   string
		impact string
		want   string
	}{
		{name: "high", impact: "high", want: "HIGH"},
		{name: "medium", impact: "medium", want: "MEDIUM"},
		{name: "low", impact: "low", want: "LOW"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			formatter := NewMarkdownFormatter(&buf)

			result := diff.NewResult()
			result.AddChange(diff.Change{
				Type:           diff.ChangeAdded,
				Section:        diff.SectionFirewall,
				Path:           "test",
				Description:    "Test change",
				SecurityImpact: tt.impact,
			})

			err := formatter.Format(result)
			require.NoError(t, err)

			assert.Contains(t, buf.String(), tt.want)
		})
	}
}

func TestMarkdownFormatter_Format_EscapesPipeCharacters(t *testing.T) {
	var buf bytes.Buffer
	formatter := NewMarkdownFormatter(&buf)

	result := diff.NewResult()
	result.AddChange(diff.Change{
		Type:        diff.ChangeModified,
		Section:     diff.SectionFirewall,
		Path:        "test",
		Description: "Rule with | pipe character",
	})

	err := formatter.Format(result)
	require.NoError(t, err)

	// The pipe should be escaped
	assert.Contains(t, buf.String(), "\\|")
}
