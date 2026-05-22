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

// listDevicesTestCleanup restores the global --json flag value between
// subtests since it is a package-level Cobra flag variable (per GOTCHAS.md §1.1
// — never use t.Parallel in tests that mutate cmd-package globals).
func listDevicesTestCleanup(t *testing.T) {
	t.Helper()
	t.Cleanup(func() { listDevicesJSONOutput = false })
}

func TestListDevices_TextOutput(t *testing.T) {
	listDevicesTestCleanup(t)

	buf := &bytes.Buffer{}
	listDevicesCmd.SetOut(buf)
	t.Cleanup(func() { listDevicesCmd.SetOut(nil) })

	require.NoError(t, runListDevices(listDevicesCmd, nil))

	out := buf.String()
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	assert.NotEmpty(t, lines, "registry should return at least one device type")
	assert.Contains(t, lines, "opnsense", "opnsense parser must be present")
	assert.Contains(t, lines, "pfsense", "pfsense parser must be present")

	// Verify sort stability — output is sorted alphabetically by parser registry.
	sorted := make([]string, len(lines))
	copy(sorted, lines)
	for i := 1; i < len(sorted); i++ {
		assert.LessOrEqual(t, sorted[i-1], sorted[i], "device list must be sorted")
	}
}

func TestListDevices_JSONOutput(t *testing.T) {
	listDevicesTestCleanup(t)
	listDevicesJSONOutput = true

	buf := &bytes.Buffer{}
	listDevicesCmd.SetOut(buf)
	t.Cleanup(func() { listDevicesCmd.SetOut(nil) })

	require.NoError(t, runListDevices(listDevicesCmd, nil))

	var decoded []deviceEntry
	require.NoError(t, json.Unmarshal(buf.Bytes(), &decoded))
	require.NotEmpty(t, decoded, "JSON output must contain at least one device entry")

	names := make([]string, 0, len(decoded))
	for _, e := range decoded {
		assert.NotEmpty(t, e.Name, "every entry must have a non-empty name")
		assert.NotEmpty(
			t,
			e.Description,
			"every entry must have a non-empty description (fallback applies if registry has none)",
		)
		names = append(names, e.Name)
	}

	assert.Contains(t, names, "opnsense")
	assert.Contains(t, names, "pfsense")
}

func TestListDevices_RejectsPositionalArgs(t *testing.T) {
	listDevicesTestCleanup(t)

	root := GetRootCmd()
	buf := &bytes.Buffer{}
	root.SetOut(buf)
	root.SetErr(buf)
	root.SetArgs([]string{"list", "devices", "unexpected"})
	t.Cleanup(func() { root.SetArgs(nil) })

	err := root.Execute()
	require.Error(t, err, "list devices does not accept positional arguments")
}

func TestListDevices_Lightweight(t *testing.T) {
	assert.Equal(
		t,
		"true",
		listDevicesCmd.Annotations["lightweight"],
		"list devices must be lightweight — registry enumeration only",
	)
}
