package diff

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestChangeType_String(t *testing.T) {
	tests := []struct {
		name     string
		ct       ChangeType
		expected string
	}{
		{"added", ChangeAdded, "added"},
		{"removed", ChangeRemoved, "removed"},
		{"modified", ChangeModified, "modified"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.ct.String())
		})
	}
}

func TestChangeType_Symbol(t *testing.T) {
	tests := []struct {
		name     string
		ct       ChangeType
		expected string
	}{
		{"added", ChangeAdded, "+"},
		{"removed", ChangeRemoved, "-"},
		{"modified", ChangeModified, "~"},
		{"unknown", ChangeType("unknown"), "?"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.ct.Symbol())
		})
	}
}

func TestSection_String(t *testing.T) {
	tests := []struct {
		name     string
		section  Section
		expected string
	}{
		{"system", SectionSystem, "system"},
		{"firewall", SectionFirewall, "firewall"},
		{"nat", SectionNAT, "nat"},
		{"interfaces", SectionInterfaces, "interfaces"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.section.String())
		})
	}
}

func TestAllSections(t *testing.T) {
	sections := AllSections()
	assert.Len(t, sections, 11)
	assert.Contains(t, sections, SectionSystem)
	assert.Contains(t, sections, SectionFirewall)
	assert.Contains(t, sections, SectionNAT)
}

func TestNewResult(t *testing.T) {
	result := NewResult()
	require.NotNil(t, result)
	assert.NotNil(t, result.Changes)
	assert.Empty(t, result.Changes)
	assert.Equal(t, 0, result.Summary.Total)
}

func TestResult_AddChange(t *testing.T) {
	result := NewResult()

	// Add an added change
	result.AddChange(Change{
		Type:        ChangeAdded,
		Section:     SectionFirewall,
		Path:        "filter.rule[0]",
		Description: "Added new rule",
	})
	assert.Equal(t, 1, result.Summary.Added)
	assert.Equal(t, 0, result.Summary.Removed)
	assert.Equal(t, 0, result.Summary.Modified)
	assert.Equal(t, 1, result.Summary.Total)

	// Add a removed change
	result.AddChange(Change{
		Type:        ChangeRemoved,
		Section:     SectionFirewall,
		Path:        "filter.rule[1]",
		Description: "Removed old rule",
	})
	assert.Equal(t, 1, result.Summary.Added)
	assert.Equal(t, 1, result.Summary.Removed)
	assert.Equal(t, 0, result.Summary.Modified)
	assert.Equal(t, 2, result.Summary.Total)

	// Add a modified change
	result.AddChange(Change{
		Type:        ChangeModified,
		Section:     SectionSystem,
		Path:        "system.hostname",
		Description: "Changed hostname",
		OldValue:    "old-host",
		NewValue:    "new-host",
	})
	assert.Equal(t, 1, result.Summary.Added)
	assert.Equal(t, 1, result.Summary.Removed)
	assert.Equal(t, 1, result.Summary.Modified)
	assert.Equal(t, 3, result.Summary.Total)
}

func TestResult_ChangesBySection(t *testing.T) {
	result := NewResult()
	result.AddChange(Change{Type: ChangeAdded, Section: SectionFirewall, Path: "rule1"})
	result.AddChange(Change{Type: ChangeRemoved, Section: SectionFirewall, Path: "rule2"})
	result.AddChange(Change{Type: ChangeModified, Section: SectionSystem, Path: "hostname"})

	bySection := result.ChangesBySection()

	assert.Len(t, bySection[SectionFirewall], 2)
	assert.Len(t, bySection[SectionSystem], 1)
	assert.Empty(t, bySection[SectionNAT])
}

func TestResult_HasChanges(t *testing.T) {
	result := NewResult()
	assert.False(t, result.HasChanges())

	result.AddChange(Change{Type: ChangeAdded, Section: SectionSystem, Path: "test"})
	assert.True(t, result.HasChanges())
}

func TestOptions_ShouldIncludeSection(t *testing.T) {
	tests := []struct {
		name     string
		opts     Options
		section  Section
		expected bool
	}{
		{
			name:     "empty sections includes all",
			opts:     Options{},
			section:  SectionFirewall,
			expected: true,
		},
		{
			name:     "matching section included",
			opts:     Options{Sections: []string{"firewall", "nat"}},
			section:  SectionFirewall,
			expected: true,
		},
		{
			name:     "non-matching section excluded",
			opts:     Options{Sections: []string{"firewall", "nat"}},
			section:  SectionSystem,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.opts.ShouldIncludeSection(tt.section))
		})
	}
}

func TestChange_JSONMarshal(t *testing.T) {
	change := Change{
		Type:           ChangeModified,
		Section:        SectionSystem,
		Path:           "system.hostname",
		Description:    "Changed hostname",
		OldValue:       "old-host",
		NewValue:       "new-host",
		SecurityImpact: "low",
	}

	data, err := json.Marshal(change)
	require.NoError(t, err)

	var unmarshaled Change
	err = json.Unmarshal(data, &unmarshaled)
	require.NoError(t, err)

	assert.Equal(t, change, unmarshaled)
}

func TestResult_JSONMarshal(t *testing.T) {
	result := &Result{
		Summary: Summary{
			Added:    1,
			Removed:  2,
			Modified: 3,
			Total:    6,
		},
		Metadata: Metadata{
			OldFile:     "old.xml",
			NewFile:     "new.xml",
			ComparedAt:  time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
			ToolVersion: "1.0.0",
		},
		Changes: []Change{
			{Type: ChangeAdded, Section: SectionFirewall, Path: "rule1"},
		},
	}

	data, err := json.Marshal(result)
	require.NoError(t, err)

	var unmarshaled Result
	err = json.Unmarshal(data, &unmarshaled)
	require.NoError(t, err)

	assert.Equal(t, result.Summary, unmarshaled.Summary)
	assert.Equal(t, result.Metadata.OldFile, unmarshaled.Metadata.OldFile)
	assert.Len(t, unmarshaled.Changes, 1)
}
