// Package cmd provides the command-line interface for opnDossier.
package cmd

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/audit"
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

// TestListPlugins_SortStability pins the consecutive-invocation determinism
// contract for `list plugins` (devices and formats have equivalents). Agents
// diffing capability snapshots across invocations need byte-stable output.
func TestListPlugins_SortStability(t *testing.T) {
	listPluginsTestCleanup(t)

	buf1 := &bytes.Buffer{}
	listPluginsCmd.SetOut(buf1)
	listPluginsCmd.SetErr(&bytes.Buffer{})
	require.NoError(t, runListPlugins(listPluginsCmd, nil))

	buf2 := &bytes.Buffer{}
	listPluginsCmd.SetOut(buf2)
	listPluginsCmd.SetErr(&bytes.Buffer{})
	require.NoError(t, runListPlugins(listPluginsCmd, nil))

	t.Cleanup(func() {
		listPluginsCmd.SetOut(nil)
		listPluginsCmd.SetErr(nil)
	})

	assert.Equal(t, buf1.String(), buf2.String(), "two consecutive invocations must produce identical output")
}

// TestListPlugins_JSONShapeContract pins the JSON envelope shape for the
// plugins subcommand. Field set is `name`, `description`, `version`. Future
// adds are forward-compatible, but renames or removals must surface as a
// failing test (not a silent agent-side regression).
func TestListPlugins_JSONShapeContract(t *testing.T) {
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

	var generic []map[string]any
	require.NoError(t, json.Unmarshal(buf.Bytes(), &generic))
	require.NotEmpty(t, generic, "built-in plugin registry must contain entries")

	expectedKeys := map[string]bool{"name": true, "description": true, "version": true}
	for i, entry := range generic {
		require.Len(t, entry, len(expectedKeys), "entry %d must have %d fields", i, len(expectedKeys))
		for k := range entry {
			assert.True(
				t,
				expectedKeys[k],
				"entry %d has unexpected key %q (v1 schema is name, description, version)",
				i,
				k,
			)
		}
		_, nameOk := entry["name"].(string)
		_, descOk := entry["description"].(string)
		_, verOk := entry["version"].(string)
		assert.True(t, nameOk, "entry %d: name must be string", i)
		assert.True(t, descOk, "entry %d: description must be string", i)
		assert.True(t, verOk, "entry %d: version must be string", i)
		assert.NotEmpty(t, entry["name"], "entry %d: name must be non-empty", i)
		assert.NotEmpty(
			t,
			entry["version"],
			"entry %d: version must be non-empty (fallback to %q applies)",
			i,
			versionUnknown,
		)
	}
}

// TestListPlugins_FallbackVersionWhenLookupFails stresses the
// readPluginMetadata fallback path: GetPlugin returns ErrPluginNotFound
// for a name absent from the registry. The helper must return a populated
// entry with Version=versionUnknown rather than an empty Version that
// would violate the JSON envelope's non-empty Version contract.
func TestListPlugins_FallbackVersionWhenLookupFails(t *testing.T) {
	// Stress the readPluginMetadata fallback path: GetPlugin returns
	// ErrPluginNotFound for a name absent from the registry. The helper
	// must return a populated entry with Version=versionUnknown rather
	// than an empty Version that would violate the JSON contract.
	listPluginsTestCleanup(t)

	pm := audit.NewPluginManager(logger, nil)
	require.NoError(t, pm.InitializePlugins(t.Context()))

	entry := readPluginMetadata(pm.GetRegistry(), "no-such-plugin-name-for-test")
	assert.Equal(t, "no-such-plugin-name-for-test", entry.Name)
	assert.Equal(t, versionUnknown, entry.Version, "fallback path must populate Version with %q", versionUnknown)
}
