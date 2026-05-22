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
