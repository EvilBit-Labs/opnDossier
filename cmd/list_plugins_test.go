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

// listPluginsTestCleanup restores global flag state between subtests since
// listPluginsJSONOutput and listPluginsPluginDir are package-level Cobra flag
// variables (GOTCHAS.md §1.1 — no t.Parallel here).
func listPluginsTestCleanup(t *testing.T) {
	t.Helper()
	t.Cleanup(func() {
		listPluginsJSONOutput = false
		listPluginsPluginDir = ""
	})
}

func TestListPlugins_BuiltinsListed_TextMode(t *testing.T) {
	listPluginsTestCleanup(t)

	buf := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	listPluginsCmd.SetOut(buf)
	listPluginsCmd.SetErr(stderr)
	t.Cleanup(func() {
		listPluginsCmd.SetOut(nil)
		listPluginsCmd.SetErr(nil)
	})

	require.NoError(t, runListPlugins(listPluginsCmd, nil))

	out := buf.String()
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	require.NotEmpty(t, lines)

	// The built-in plugins registered by InitializePlugins.
	for _, want := range []string{"stig", "sans", "firewall"} {
		assert.Contains(t, lines, want, "built-in %q plugin must be listed", want)
	}

	// Trust-model warning should NOT fire when --plugin-dir is empty.
	assert.Empty(t, stderr.String(), "no warning expected without --plugin-dir")
}

func TestListPlugins_JSONOutput(t *testing.T) {
	listPluginsTestCleanup(t)
	listPluginsJSONOutput = true

	buf := &bytes.Buffer{}
	listPluginsCmd.SetOut(buf)
	listPluginsCmd.SetErr(&bytes.Buffer{})
	t.Cleanup(func() {
		listPluginsCmd.SetOut(nil)
		listPluginsCmd.SetErr(nil)
	})

	require.NoError(t, runListPlugins(listPluginsCmd, nil))

	var decoded []pluginEntry
	require.NoError(t, json.Unmarshal(buf.Bytes(), &decoded))
	require.NotEmpty(t, decoded, "JSON output must contain at least one plugin")

	for _, e := range decoded {
		assert.NotEmpty(t, e.Name, "every entry must have a non-empty name")
		assert.NotEmpty(t, e.Version, "every entry must have a non-empty version")
		assert.NotEmpty(t, e.Description, "every entry must have a non-empty description")
	}
}

func TestListPlugins_PluginDirTriggersTrustModelWarning(t *testing.T) {
	listPluginsTestCleanup(t)
	// Use a known-missing path so InitializePlugins surfaces the error
	// while the warning still fires before the failure.
	listPluginsPluginDir = "/nonexistent/path/for/list-plugins-trust-test"

	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	listPluginsCmd.SetOut(stdout)
	listPluginsCmd.SetErr(stderr)
	t.Cleanup(func() {
		listPluginsCmd.SetOut(nil)
		listPluginsCmd.SetErr(nil)
	})

	// We expect an error from InitializePlugins because the path is
	// non-existent and the user explicitly supplied it.
	err := runListPlugins(listPluginsCmd, nil)
	require.Error(t, err, "explicit missing plugin dir must surface an error")

	// But the trust-model warning should already have been written before
	// the error fired.
	warning := stderr.String()
	assert.Contains(
		t,
		warning,
		"Warning:",
		"trust-model warning must be emitted to stderr when --plugin-dir is supplied",
	)
	assert.Contains(t, warning, "--plugin-dir", "warning must mention the flag")
}

func TestListPlugins_NotLightweight(t *testing.T) {
	// Unlike list devices / list formats, list plugins must initialize the
	// PluginManager so dynamic plugin loading works. The lightweight
	// annotation MUST be absent.
	_, ok := listPluginsCmd.Annotations["lightweight"]
	assert.False(t, ok, "list plugins must not carry the lightweight annotation — InitializePlugins is required")
}

func TestListPlugins_RejectsPositionalArgs(t *testing.T) {
	listPluginsTestCleanup(t)

	root := GetRootCmd()
	buf := &bytes.Buffer{}
	root.SetOut(buf)
	root.SetErr(buf)
	root.SetArgs([]string{"list", "plugins", "unexpected"})
	t.Cleanup(func() { root.SetArgs(nil) })

	err := root.Execute()
	require.Error(t, err, "list plugins does not accept positional arguments")
}
