package formatters

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/diff"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewJSONFormatter(t *testing.T) {
	var buf bytes.Buffer
	formatter := NewJSONFormatter(&buf)

	assert.NotNil(t, formatter)
	assert.True(t, formatter.pretty)
}

func TestNewJSONFormatterCompact(t *testing.T) {
	var buf bytes.Buffer
	formatter := NewJSONFormatterCompact(&buf)

	assert.NotNil(t, formatter)
	assert.False(t, formatter.pretty)
}

func TestJSONFormatter_Format_NoChanges(t *testing.T) {
	var buf bytes.Buffer
	formatter := NewJSONFormatter(&buf)

	result := diff.NewResult()

	err := formatter.Format(result)
	require.NoError(t, err)

	// Verify valid JSON
	var parsed diff.Result
	err = json.Unmarshal(buf.Bytes(), &parsed)
	require.NoError(t, err)

	assert.Equal(t, 0, parsed.Summary.Total)
	assert.Empty(t, parsed.Changes)
}

func TestJSONFormatter_Format_WithChanges(t *testing.T) {
	var buf bytes.Buffer
	formatter := NewJSONFormatter(&buf)

	result := diff.NewResult()
	result.AddChange(diff.Change{
		Type:           diff.ChangeAdded,
		Section:        diff.SectionFirewall,
		Path:           "filter.rule[uuid=123]",
		Description:    "Added rule: Allow SSH",
		NewValue:       "type=pass, proto=tcp, dst=any:22",
		SecurityImpact: "medium",
	})
	result.AddChange(diff.Change{
		Type:        diff.ChangeRemoved,
		Section:     diff.SectionFirewall,
		Path:        "filter.rule[uuid=456]",
		Description: "Removed rule: Legacy FTP",
		OldValue:    "type=pass, proto=tcp, dst=any:21",
	})

	err := formatter.Format(result)
	require.NoError(t, err)

	// Verify valid JSON and structure
	var parsed diff.Result
	err = json.Unmarshal(buf.Bytes(), &parsed)
	require.NoError(t, err)

	assert.Equal(t, 1, parsed.Summary.Added)
	assert.Equal(t, 1, parsed.Summary.Removed)
	assert.Equal(t, 2, parsed.Summary.Total)
	assert.Len(t, parsed.Changes, 2)

	// Check first change
	assert.Equal(t, diff.ChangeAdded, parsed.Changes[0].Type)
	assert.Equal(t, diff.SectionFirewall, parsed.Changes[0].Section)
	assert.Equal(t, "filter.rule[uuid=123]", parsed.Changes[0].Path)
	assert.Equal(t, "medium", parsed.Changes[0].SecurityImpact)
}

func TestJSONFormatter_Format_Compact(t *testing.T) {
	var buf bytes.Buffer
	formatter := NewJSONFormatterCompact(&buf)

	result := diff.NewResult()
	result.AddChange(diff.Change{
		Type:        diff.ChangeModified,
		Section:     diff.SectionSystem,
		Path:        "system.hostname",
		Description: "Hostname changed",
	})

	err := formatter.Format(result)
	require.NoError(t, err)

	output := buf.String()

	// Compact output should not have newlines in the JSON structure
	// (only the trailing newline from Encode)
	lines := bytes.Count(buf.Bytes(), []byte("\n"))
	assert.Equal(t, 1, lines, "Compact JSON should be a single line")

	// But should still be valid JSON
	var parsed diff.Result
	err = json.Unmarshal([]byte(output), &parsed)
	require.NoError(t, err)
	assert.Equal(t, 1, parsed.Summary.Modified)
}

func TestJSONFormatter_SetPretty(t *testing.T) {
	var buf bytes.Buffer
	formatter := NewJSONFormatter(&buf)

	assert.True(t, formatter.pretty)
	formatter.SetPretty(false)
	assert.False(t, formatter.pretty)
	formatter.SetPretty(true)
	assert.True(t, formatter.pretty)
}

func TestJSONFormatter_Format_AllChangeTypes(t *testing.T) {
	var buf bytes.Buffer
	formatter := NewJSONFormatter(&buf)

	result := diff.NewResult()
	result.AddChange(diff.Change{
		Type:    diff.ChangeAdded,
		Section: diff.SectionFirewall,
		Path:    "added",
	})
	result.AddChange(diff.Change{
		Type:    diff.ChangeRemoved,
		Section: diff.SectionFirewall,
		Path:    "removed",
	})
	result.AddChange(diff.Change{
		Type:    diff.ChangeModified,
		Section: diff.SectionFirewall,
		Path:    "modified",
	})

	err := formatter.Format(result)
	require.NoError(t, err)

	var parsed diff.Result
	err = json.Unmarshal(buf.Bytes(), &parsed)
	require.NoError(t, err)

	assert.Equal(t, 1, parsed.Summary.Added)
	assert.Equal(t, 1, parsed.Summary.Removed)
	assert.Equal(t, 1, parsed.Summary.Modified)
	assert.Equal(t, 3, parsed.Summary.Total)
}
