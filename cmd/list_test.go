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
