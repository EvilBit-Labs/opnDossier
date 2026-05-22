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

// listTestEntry is a minimal listEntry implementation used to exercise the
// shared emitList helper in isolation from the per-subcommand types.
type listTestEntry struct {
	Name string `json:"name"`
	Desc string `json:"description,omitempty"`
}

func (e listTestEntry) name() string { return e.Name }

func TestListCmd_Structure(t *testing.T) {
	assert.Equal(t, "list", listCmd.Use, "list command Use should be 'list'")
	assert.Equal(t, "utility", listCmd.GroupID, "list belongs in the utility group")
	assert.Equal(
		t,
		"true",
		listCmd.Annotations["lightweight"],
		"list parent should be lightweight (children opt in/out individually)",
	)
	assert.True(t, listCmd.HasSubCommands(), "list must have subcommands registered via init()")
}

func TestListCmd_NoSubcommandPrintsHelp(t *testing.T) {
	// Bare `opnDossier list` (no subcommand) should print help listing the
	// three subcommands and exit 0. Cobra renders help by default for a
	// parent without RunE; this test pins that behavior so a future
	// contributor adding an unexpected RunE to listCmd fails the assertion.
	root := GetRootCmd()
	buf := &bytes.Buffer{}
	root.SetOut(buf)
	root.SetErr(buf)
	root.SetArgs([]string{"list"})
	t.Cleanup(func() {
		root.SetArgs(nil)
		root.SetOut(nil)
		root.SetErr(nil)
	})

	require.NoError(t, root.Execute())
	out := buf.String()
	assert.Contains(t, out, "plugins", "help must mention plugins subcommand")
	assert.Contains(t, out, "devices", "help must mention devices subcommand")
	assert.Contains(t, out, "formats", "help must mention formats subcommand")
}

func TestListCmd_UnknownSubcommandFallsBackToHelp(t *testing.T) {
	// The original plan called for unknown subcommands to error and exit
	// non-zero. The actual Cobra wiring in this codebase falls back to
	// printing help with exit 0 (matches the project's `config` parent
	// command behavior — see cmd/config.go). Pin THAT contract so the
	// fallback doesn't silently mutate into something else.
	//
	// Agents that need to detect typos should compare the printed output
	// against the expected subcommand list — the parent's help text always
	// names the three registered children.
	root := GetRootCmd()
	buf := &bytes.Buffer{}
	root.SetOut(buf)
	root.SetErr(buf)
	root.SetArgs([]string{"list", "definitely-not-a-real-subcommand"})
	t.Cleanup(func() {
		root.SetArgs(nil)
		root.SetOut(nil)
		root.SetErr(nil)
	})

	require.NoError(t, root.Execute(), "Cobra falls back to help on unknown subcommand")
	out := buf.String()
	assert.Contains(t, out, "plugins", "fallback help must still list the subcommands")
	assert.Contains(t, out, "devices")
	assert.Contains(t, out, "formats")
}

func TestListCmd_RegisteredSubcommands(t *testing.T) {
	// The three subcommands the NATS-148 contract promises. New subcommands
	// added later should also appear here so this test serves as a registry
	// of the public introspection surface.
	expected := map[string]bool{
		"devices": false,
		"formats": false,
		"plugins": false,
	}

	for _, sub := range listCmd.Commands() {
		if _, ok := expected[sub.Name()]; ok {
			expected[sub.Name()] = true
		}
	}

	for name, found := range expected {
		assert.True(t, found, "list must register %q subcommand", name)
	}
}

func TestEmitList_TextMode(t *testing.T) {
	buf := &bytes.Buffer{}
	items := []listEntry{
		listTestEntry{Name: "alpha"},
		listTestEntry{Name: "bravo"},
	}

	require.NoError(t, emitList(buf, items, false))
	assert.Equal(t, "alpha\nbravo\n", buf.String())
}

func TestEmitList_TextMode_EmptyInputWritesNothing(t *testing.T) {
	buf := &bytes.Buffer{}
	require.NoError(t, emitList(buf, nil, false))
	assert.Empty(t, buf.String(), "empty registry must produce zero bytes in text mode")
}

func TestEmitList_JSONMode(t *testing.T) {
	buf := &bytes.Buffer{}
	items := []listEntry{
		listTestEntry{Name: "alpha", Desc: "first"},
		listTestEntry{Name: "bravo", Desc: "second"},
	}

	require.NoError(t, emitList(buf, items, true))

	var decoded []listTestEntry
	require.NoError(t, json.Unmarshal(buf.Bytes(), &decoded))
	require.Len(t, decoded, 2)
	assert.Equal(t, "alpha", decoded[0].Name)
	assert.Equal(t, "first", decoded[0].Desc)
	assert.True(t, strings.HasSuffix(buf.String(), "\n"), "JSON output should end with newline")
}

func TestEmitList_JSONMode_EmptyInputWritesEmptyArray(t *testing.T) {
	buf := &bytes.Buffer{}
	require.NoError(t, emitList(buf, nil, true))

	var decoded []listTestEntry
	require.NoError(t, json.Unmarshal(buf.Bytes(), &decoded))
	assert.Empty(t, decoded, "empty registry must emit JSON [] (not null)")
}

// TestEmitList_JSONNameMatchesInterfaceName pins the implicit contract that
// every listEntry implementer marshals to a JSON object whose `name` field
// equals the value returned by the interface's name() method. Without this,
// a future struct satisfying listEntry could ship to agents with a missing
// or mismatched `name` field and only manual inspection would catch it.
func TestEmitList_JSONNameMatchesInterfaceName(t *testing.T) {
	cases := []listEntry{
		deviceEntry{Name: "opnsense", Description: "x"},
		formatEntry{Name: "json", Description: "x"},
		pluginEntry{Name: "stig", Description: "x", Version: "1.0"},
	}

	for _, entry := range cases {
		t.Run(entry.name(), func(t *testing.T) {
			buf := &bytes.Buffer{}
			require.NoError(t, emitList(buf, []listEntry{entry}, true))

			var decoded []map[string]any
			require.NoError(t, json.Unmarshal(buf.Bytes(), &decoded))
			require.Len(t, decoded, 1)
			assert.Equal(
				t,
				entry.name(),
				decoded[0]["name"],
				"JSON `name` field must equal interface name() return value",
			)
		})
	}
}
