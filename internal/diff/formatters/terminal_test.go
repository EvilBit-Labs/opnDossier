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
