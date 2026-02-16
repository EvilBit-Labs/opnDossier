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

func TestJSONFormatter_Format_Pretty_vs_Compact(t *testing.T) {
	t.Parallel()

	result := diff.NewResult()
	result.AddChange(diff.Change{
		Type:        diff.ChangeAdded,
		Section:     diff.SectionSystem,
		Path:        "system.hostname",
		Description: "Added hostname",
		NewValue:    "test-host",
	})

	t.Run("pretty formatting", func(t *testing.T) {
		t.Parallel()
		var buf bytes.Buffer
		formatter := NewJSONFormatter(&buf)

		err := formatter.Format(result)
		require.NoError(t, err)

		output := buf.String()

		// Pretty JSON should have indentation and multiple lines
		assert.Contains(t, output, "  \"changes\":")
		assert.Contains(t, output, "  \"summary\":")

		// Should have more than one line due to indentation
		lines := bytes.Count(buf.Bytes(), []byte("\n"))
		assert.Greater(t, lines, 5)
	})

	t.Run("compact formatting", func(t *testing.T) {
		t.Parallel()
		var buf bytes.Buffer
		formatter := NewJSONFormatterCompact(&buf)

		err := formatter.Format(result)
		require.NoError(t, err)

		// Compact should be single line (plus trailing newline)
		lines := bytes.Count(buf.Bytes(), []byte("\n"))
		assert.Equal(t, 1, lines)

		// Should not contain indentation
		assert.NotContains(t, buf.String(), "  \"")
	})
}

func TestJSONFormatter_SetPretty_AffectsOutput(t *testing.T) {
	t.Parallel()

	result := diff.NewResult()
	result.AddChange(diff.Change{
		Type:        diff.ChangeAdded,
		Section:     diff.SectionSystem,
		Path:        "test",
		Description: "Test change",
	})

	// Test that changing pretty setting affects output
	var buf1, buf2 bytes.Buffer
	formatter1 := NewJSONFormatter(&buf1)
	formatter2 := NewJSONFormatter(&buf2)

	// Set one to compact
	formatter2.SetPretty(false)

	err1 := formatter1.Format(result)
	require.NoError(t, err1)

	err2 := formatter2.Format(result)
	require.NoError(t, err2)

	output1 := buf1.String()
	output2 := buf2.String()

	// Outputs should be different
	assert.NotEqual(t, output1, output2)

	// Pretty should be longer due to indentation
	assert.Greater(t, len(output1), len(output2))
}
