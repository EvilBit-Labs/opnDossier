// Package cmd provides the command-line interface for opnDossier.
package cmd

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// listFormatsTestCleanup restores the global --json flag value between
// subtests since it is a package-level Cobra flag variable (per GOTCHAS.md §1.1).
func listFormatsTestCleanup(t *testing.T) {
	t.Helper()
	t.Cleanup(func() { listFormatsJSONOutput = false })
}

func TestListFormats_TextOutput(t *testing.T) {
	listFormatsTestCleanup(t)

	buf := &bytes.Buffer{}
	listFormatsCmd.SetOut(buf)
	t.Cleanup(func() { listFormatsCmd.SetOut(nil) })

	require.NoError(t, runListFormats(listFormatsCmd, nil))

	out := buf.String()
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	require.NotEmpty(t, lines, "registry should return at least one format")

	expected := []string{"markdown", "json", "yaml", "text", "html"}
	for _, want := range expected {
		assert.Contains(t, lines, want, "canonical format %q must be present", want)
	}

	// Aliases (yml -> yaml) must NOT appear in the canonical list — agents
	// should pass canonical names to --format. ValidFormatsWithAliases is a
	// separate registry method that the completion code uses.
	assert.NotContains(t, lines, "yml", "yml alias must not appear; only canonical names")
}

func TestListFormats_JSONOutput(t *testing.T) {
	listFormatsTestCleanup(t)
	listFormatsJSONOutput = true

	buf := &bytes.Buffer{}
	listFormatsCmd.SetOut(buf)
	t.Cleanup(func() { listFormatsCmd.SetOut(nil) })

	require.NoError(t, runListFormats(listFormatsCmd, nil))

	var decoded []formatEntry
	require.NoError(t, json.Unmarshal(buf.Bytes(), &decoded))
	require.NotEmpty(t, decoded)

	for _, e := range decoded {
		assert.NotEmpty(t, e.Name, "every entry must have a non-empty name")
		assert.NotEmpty(
			t,
			e.Description,
			"every entry must have a non-empty description (fallback applies if registry has none)",
		)
	}
}

func TestListFormats_RejectsPositionalArgs(t *testing.T) {
	listFormatsTestCleanup(t)

	root := GetRootCmd()
	buf := &bytes.Buffer{}
	root.SetOut(buf)
	root.SetErr(buf)
	root.SetArgs([]string{"list", "formats", "unexpected"})
	t.Cleanup(func() { root.SetArgs(nil) })

	err := root.Execute()
	require.Error(t, err, "list formats does not accept positional arguments")
}

func TestListFormats_Lightweight(t *testing.T) {
	assert.Equal(
		t,
		"true",
		listFormatsCmd.Annotations["lightweight"],
		"list formats must be lightweight — registry enumeration only",
	)
}

// TestListFormats_SortStability runs the command twice in succession and
// asserts that both invocations produce byte-identical output. Stability is
// a contract for agents that diff capability snapshots across invocations.
func TestListFormats_SortStability(t *testing.T) {
	listFormatsTestCleanup(t)

	buf1 := &bytes.Buffer{}
	listFormatsCmd.SetOut(buf1)
	require.NoError(t, runListFormats(listFormatsCmd, nil))

	buf2 := &bytes.Buffer{}
	listFormatsCmd.SetOut(buf2)
	require.NoError(t, runListFormats(listFormatsCmd, nil))

	t.Cleanup(func() { listFormatsCmd.SetOut(nil) })

	assert.Equal(t, buf1.String(), buf2.String(), "two consecutive invocations must produce identical output")
}

// TestListFormats_JSONShapeContract pins the JSON envelope shape so future
// field renames or removals are caught at CI time. Mirrors the docs/for-agents.md
// "Capability discovery" promise: `[{"name", "description"}]`.
func TestListFormats_JSONShapeContract(t *testing.T) {
	listFormatsTestCleanup(t)
	listFormatsJSONOutput = true

	buf := &bytes.Buffer{}
	listFormatsCmd.SetOut(buf)
	t.Cleanup(func() { listFormatsCmd.SetOut(nil) })

	require.NoError(t, runListFormats(listFormatsCmd, nil))

	// Decode generically so we observe the actual JSON keys, not what the
	// Go struct happens to map them to.
	var generic []map[string]any
	require.NoError(t, json.Unmarshal(buf.Bytes(), &generic))
	require.NotEmpty(t, generic, "format registry must contain entries")

	// Every entry must carry exactly the documented field set.
	expectedKeys := map[string]bool{"name": true, "description": true}
	for i, entry := range generic {
		require.Len(t, entry, len(expectedKeys), "entry %d must have %d fields", i, len(expectedKeys))
		for k := range entry {
			assert.True(t, expectedKeys[k], "entry %d has unexpected key %q (v1 schema is name, description)", i, k)
		}
		// Field types
		_, nameOk := entry["name"].(string)
		_, descOk := entry["description"].(string)
		assert.True(t, nameOk, "entry %d: name must be string", i)
		assert.True(t, descOk, "entry %d: description must be string", i)
	}
}
