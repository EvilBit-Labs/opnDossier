package formatters

import (
	"bytes"
	"strings"
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/diff"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewTerminalFormatter(t *testing.T) {
	var buf bytes.Buffer
	formatter := NewTerminalFormatter(&buf)

	assert.NotNil(t, formatter)
	assert.Equal(t, &buf, formatter.writer)
}

func TestTerminalFormatter_Format_NoChanges(t *testing.T) {
	var buf bytes.Buffer
	formatter := NewTerminalFormatter(&buf)
	formatter.useStyles = false // Disable styles for testing

	result := diff.NewResult()

	err := formatter.Format(result)
	require.NoError(t, err)

	output := buf.String()
	assert.Contains(t, output, "No changes detected")
}

func TestTerminalFormatter_Format_WithChanges(t *testing.T) {
	var buf bytes.Buffer
	formatter := NewTerminalFormatter(&buf)
	formatter.useStyles = false // Disable styles for testing

	result := diff.NewResult()
	result.AddChange(diff.Change{
		Type:        diff.ChangeAdded,
		Section:     diff.SectionFirewall,
		Path:        "filter.rule[uuid=123]",
		Description: "Added rule: Allow SSH",
		NewValue:    "type=pass, proto=tcp, dst=any:22",
	})
	result.AddChange(diff.Change{
		Type:           diff.ChangeRemoved,
		Section:        diff.SectionFirewall,
		Path:           "filter.rule[uuid=456]",
		Description:    "Removed rule: Legacy FTP",
		OldValue:       "type=pass, proto=tcp, dst=any:21",
		SecurityImpact: "medium",
	})

	err := formatter.Format(result)
	require.NoError(t, err)

	output := buf.String()

	// Check summary
	assert.Contains(t, output, "+1 added")
	assert.Contains(t, output, "-1 removed")

	// Check section header (capitalized)
	assert.Contains(t, output, "Firewall")

	// Check change details
	assert.Contains(t, output, "Allow SSH")
	assert.Contains(t, output, "Legacy FTP")
	assert.Contains(t, output, "[MEDIUM]")

	// Check paths
	assert.Contains(t, output, "filter.rule[uuid=123]")
	assert.Contains(t, output, "filter.rule[uuid=456]")

	// Check values
	assert.Contains(t, output, "type=pass, proto=tcp, dst=any:22")
	assert.Contains(t, output, "type=pass, proto=tcp, dst=any:21")
}

func TestTerminalFormatter_Format_ModifiedChange(t *testing.T) {
	var buf bytes.Buffer
	formatter := NewTerminalFormatter(&buf)
	formatter.useStyles = false

	result := diff.NewResult()
	result.AddChange(diff.Change{
		Type:        diff.ChangeModified,
		Section:     diff.SectionSystem,
		Path:        "system.hostname",
		Description: "Hostname changed",
		OldValue:    "old-firewall",
		NewValue:    "new-firewall",
	})

	err := formatter.Format(result)
	require.NoError(t, err)

	output := buf.String()
	assert.Contains(t, output, "~1 modified")
	assert.Contains(t, output, "Hostname changed")
	assert.Contains(t, output, "Old: old-firewall")
	assert.Contains(t, output, "New: new-firewall")
}

func TestTerminalFormatter_Format_MultipleSections(t *testing.T) {
	var buf bytes.Buffer
	formatter := NewTerminalFormatter(&buf)
	formatter.useStyles = false

	result := diff.NewResult()
	result.AddChange(diff.Change{
		Type:        diff.ChangeAdded,
		Section:     diff.SectionInterfaces,
		Path:        "interfaces.opt1",
		Description: "Added interface: opt1 (DMZ)",
	})
	result.AddChange(diff.Change{
		Type:        diff.ChangeModified,
		Section:     diff.SectionSystem,
		Path:        "system.hostname",
		Description: "Hostname changed",
	})
	result.AddChange(diff.Change{
		Type:        diff.ChangeRemoved,
		Section:     diff.SectionVLANs,
		Path:        "vlans.vlan[vlan10]",
		Description: "Removed VLAN: vlan10",
	})

	err := formatter.Format(result)
	require.NoError(t, err)

	output := buf.String()

	// All sections should be present
	assert.Contains(t, output, "interfaces")
	assert.Contains(t, output, "system")
	assert.Contains(t, output, "vlans")

	// Sections should appear in sorted order
	interfacesIdx := strings.Index(output, "interfaces")
	systemIdx := strings.Index(output, "system")
	vlansIdx := strings.Index(output, "vlans")

	assert.Less(t, interfacesIdx, systemIdx)
	assert.Less(t, systemIdx, vlansIdx)
}

func TestTerminalFormatter_Format_SecurityImpactLevels(t *testing.T) {
	tests := []struct {
		name   string
		impact string
		want   string
	}{
		{name: "high", impact: "high", want: "[HIGH]"},
		{name: "medium", impact: "medium", want: "[MEDIUM]"},
		{name: "low", impact: "low", want: "[LOW]"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			formatter := NewTerminalFormatter(&buf)
			formatter.useStyles = false

			result := diff.NewResult()
			result.AddChange(diff.Change{
				Type:           diff.ChangeAdded,
				Section:        diff.SectionFirewall,
				Path:           "filter.rule[uuid=123]",
				Description:    "Test rule",
				SecurityImpact: tt.impact,
			})

			err := formatter.Format(result)
			require.NoError(t, err)

			assert.Contains(t, buf.String(), tt.want)
		})
	}
}

func TestTerminalFormatter_Format_ChangeSymbols(t *testing.T) {
	tests := []struct {
		name       string
		changeType diff.ChangeType
		wantSymbol string
	}{
		{name: "added", changeType: diff.ChangeAdded, wantSymbol: "+"},
		{name: "removed", changeType: diff.ChangeRemoved, wantSymbol: "-"},
		{name: "modified", changeType: diff.ChangeModified, wantSymbol: "~"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			formatter := NewTerminalFormatter(&buf)
			formatter.useStyles = false

			result := diff.NewResult()
			result.AddChange(diff.Change{
				Type:        tt.changeType,
				Section:     diff.SectionSystem,
				Path:        "test.path",
				Description: "Test change",
			})

			err := formatter.Format(result)
			require.NoError(t, err)

			// The symbol should appear as "  + Test change" or similar
			assert.Contains(t, buf.String(), tt.wantSymbol+" Test change")
		})
	}
}

func TestShouldUseStyles(t *testing.T) {
	tests := []struct {
		name     string
		termVar  string
		colorVar string
		expected bool
	}{
		{
			name:     "normal terminal",
			termVar:  "xterm",
			colorVar: "",
			expected: true,
		},
		{
			name:     "dumb terminal",
			termVar:  "dumb",
			colorVar: "",
			expected: false,
		},
		{
			name:     "no color environment",
			termVar:  "xterm",
			colorVar: "1",
			expected: false,
		},
		{
			name:     "dumb terminal with no color",
			termVar:  "dumb",
			colorVar: "1",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("TERM", tt.termVar)
			t.Setenv("NO_COLOR", tt.colorVar)

			result := shouldUseStyles()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestCreateStyles(t *testing.T) {
	t.Run("styles enabled", func(t *testing.T) {
		styles := createStyles(true)

		// Verify that styles are created (non-nil and have colors)
		assert.NotNil(t, styles.added)
		assert.NotNil(t, styles.removed)
		assert.NotNil(t, styles.modified)
		assert.NotNil(t, styles.sectionHeader)
		assert.NotNil(t, styles.path)
		assert.NotNil(t, styles.description)
		assert.NotNil(t, styles.value)
		assert.NotNil(t, styles.securityHigh)
		assert.NotNil(t, styles.securityMedium)
		assert.NotNil(t, styles.securityLow)
		assert.NotNil(t, styles.summary)
		assert.NotNil(t, styles.noChanges)

		// Test that styles actually render differently
		testText := "test"
		styledText := styles.added.Render(testText)
		assert.NotEmpty(t, styledText)
		// Should contain ANSI escape codes when styles are enabled
		assert.GreaterOrEqual(t, len(styledText), len(testText))
	})

	t.Run("styles disabled", func(t *testing.T) {
		styles := createStyles(false)

		// All styles should be zero values (no styling)
		testText := "test"
		styledText := styles.added.Render(testText)
		assert.Equal(t, testText, styledText)
	})
}

func TestCapitalizeFirst(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "lowercase word",
			input:    "system",
			expected: "System",
		},
		{
			name:     "uppercase word",
			input:    "SYSTEM",
			expected: "SYSTEM",
		},
		{
			name:     "mixed case",
			input:    "systemConfig",
			expected: "SystemConfig",
		},
		{
			name:     "empty string",
			input:    "",
			expected: "",
		},
		{
			name:     "single character",
			input:    "a",
			expected: "A",
		},
		{
			name:     "special characters",
			input:    "1-system",
			expected: "1-system",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := capitalizeFirst(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestTerminalFormatter_Format_WithStyles(t *testing.T) {
	var buf bytes.Buffer
	formatter := NewTerminalFormatter(&buf)
	formatter.useStyles = true // Enable styles

	result := diff.NewResult()
	result.AddChange(diff.Change{
		Type:           diff.ChangeAdded,
		Section:        diff.SectionFirewall,
		Path:           "filter.rule[uuid=123]",
		Description:    "Added rule: Allow SSH",
		SecurityImpact: "high",
		NewValue:       "type=pass, proto=tcp, dst=any:22",
	})

	err := formatter.Format(result)
	require.NoError(t, err)

	output := buf.String()

	// With styles enabled, output should contain ANSI escape codes
	assert.Contains(t, output, "Added rule: Allow SSH")
	assert.Contains(t, output, "[HIGH]")
	assert.Contains(t, output, "New: type=pass, proto=tcp, dst=any:22")

	// Output should be non-empty (hard to test exact ANSI sequences)
	assert.NotEmpty(t, output)
}

func TestTerminalFormatter_Format_EmptyValues(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	formatter := NewTerminalFormatter(&buf)
	formatter.useStyles = false

	result := diff.NewResult()
	result.AddChange(diff.Change{
		Type:        diff.ChangeAdded,
		Section:     diff.SectionSystem,
		Path:        "system.hostname",
		Description: "Added hostname",
		// OldValue and NewValue are empty
	})

	err := formatter.Format(result)
	require.NoError(t, err)

	output := buf.String()

	// Should not contain "Old:" or "New:" lines
	assert.NotContains(t, output, "Old:")
	assert.NotContains(t, output, "New:")
	assert.Contains(t, output, "Added hostname")
	assert.Contains(t, output, "Path: system.hostname")
}

func TestTerminalFormatter_Format_SummaryGeneration(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	formatter := NewTerminalFormatter(&buf)
	formatter.useStyles = false

	result := diff.NewResult()

	// Add multiple changes to test summary generation
	result.AddChange(diff.Change{Type: diff.ChangeAdded, Section: diff.SectionSystem, Description: "Added item 1"})
	result.AddChange(diff.Change{Type: diff.ChangeAdded, Section: diff.SectionSystem, Description: "Added item 2"})
	result.AddChange(
		diff.Change{Type: diff.ChangeRemoved, Section: diff.SectionFirewall, Description: "Removed item 1"},
	)
	result.AddChange(
		diff.Change{Type: diff.ChangeModified, Section: diff.SectionInterfaces, Description: "Modified item 1"},
	)

	err := formatter.Format(result)
	require.NoError(t, err)

	output := buf.String()

	// Verify summary contains correct counts
	assert.Contains(t, output, "+2 added")
	assert.Contains(t, output, "-1 removed")
	assert.Contains(t, output, "~1 modified")
	assert.Contains(t, output, "Configuration Diff:")
}

func TestTerminalFormatter_FormatNoChanges(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	formatter := NewTerminalFormatter(&buf)
	formatter.useStyles = false

	err := formatter.formatNoChanges()
	require.NoError(t, err)

	output := buf.String()
	assert.Contains(t, output, "No changes detected between configurations.")
}
