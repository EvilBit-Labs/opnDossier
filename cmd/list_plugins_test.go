// Package cmd provides the command-line interface for opnDossier.
package cmd

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/audit"
	"github.com/EvilBit-Labs/opnDossier/internal/compliance"
	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
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
	// the error fired. Anchor the assertions on distinguishing fragments of
	// the actual security message — not just "Warning:" — so a future
	// "make this prettier" rewrite that loses the security content fails
	// this test.
	warning := stderr.String()
	assert.Contains(t, warning, "--plugin-dir", "warning must mention the flag")
	assert.Contains(
		t,
		warning,
		"dynamic .so plugins",
		"warning must explicitly call out dynamic shared object loading",
	)
	assert.Contains(
		t,
		warning,
		"full process privileges",
		"warning must convey privilege escalation risk to the operator",
	)
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
// plugins subcommand. The v1 schema is `name`, `description`, `version`
// (required) plus optional `status` and `loadError` for failure paths.
// Future field adds are forward-compatible; renames or removals must
// surface as a failing test (not a silent agent-side regression).
//
// On a clean built-in run no entries should carry a `status` field —
// Status is omitted from JSON when "ok" so the common case stays minimal.
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

	// Required and optional keys per the v1 schema.
	requiredKeys := map[string]bool{"name": true, "description": true, "version": true}
	optionalKeys := map[string]bool{"status": true, "loadError": true}

	for i, entry := range generic {
		for k := range entry {
			assert.True(
				t,
				requiredKeys[k] || optionalKeys[k],
				"entry %d has unexpected key %q (v1 schema is name, description, version, optionally status, loadError)",
				i,
				k,
			)
		}
		for k := range requiredKeys {
			_, present := entry[k]
			assert.True(t, present, "entry %d missing required key %q", i, k)
		}
		// Field types
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
			i, versionUnknown,
		)
		// Built-in plugins should not carry a status field — Status="ok"
		// is omitted from JSON via `omitempty`.
		_, hasStatus := entry["status"]
		assert.False(t, hasStatus, "entry %d (%q) is a built-in and must not emit status field", i, entry["name"])
	}
}

// TestListPlugins_FallbackVersionWhenLookupFails stresses the
// readPluginMetadata lookup-failure path: GetPlugin returns
// ErrPluginNotFound for a name absent from the registry. The helper must
// return a populated entry with Version=versionUnknown and
// Status=pluginStatusLookupFailed rather than an empty entry that would
// violate the JSON envelope's non-empty-Version contract or silently look
// like a normal "ok" entry.
func TestListPlugins_FallbackVersionWhenLookupFails(t *testing.T) {
	listPluginsTestCleanup(t)

	pm := audit.NewPluginManager(logger, nil)
	require.NoError(t, pm.InitializePlugins(t.Context()))

	entry := readPluginMetadata(pm.GetRegistry(), "no-such-plugin-name-for-test")
	assert.Equal(t, "no-such-plugin-name-for-test", entry.Name)
	assert.Equal(t, versionUnknown, entry.Version, "fallback path must populate Version with %q", versionUnknown)
	assert.Equal(t, pluginStatusLookupFailed, entry.Status, "lookup-failed entries must carry Status=lookup-failed")
}

// panicMetadataPlugin is a test fixture that panics from Description() or
// Version(). Name() never panics because the audit registry calls Name()
// during RegisterPlugin (internal/audit/plugin.go) — a plugin that panicked
// in Name() would fail to register and never reach readPluginMetadata at
// enumeration time. The realistic enumeration-time DoS vectors are
// Description() and Version().
type panicMetadataPlugin struct {
	pluginName string
	panicOn    string // "Description" | "Version"
}

func (p *panicMetadataPlugin) Name() string { return p.pluginName }

func (p *panicMetadataPlugin) Description() string {
	if p.panicOn == "Description" {
		panic("simulated plugin Description() crash")
	}

	return "panic-test plugin"
}

func (p *panicMetadataPlugin) Version() string {
	if p.panicOn == "Version" {
		panic("simulated plugin Version() crash")
	}

	return "v0.0.0"
}

// RunChecks satisfies the compliance.Plugin interface; the three-value
// return signature comes from the interface, not this fixture.
//
//nolint:gocritic // unnamedResult fires on the interface-dictated signature
func (p *panicMetadataPlugin) RunChecks(_ *common.CommonDevice) ([]compliance.Finding, []string, error) {
	return nil, nil, nil
}

func (p *panicMetadataPlugin) GetControls() []compliance.Control { return nil }

func (p *panicMetadataPlugin) GetControlByID(_ string) (*compliance.Control, error) {
	return nil, compliance.ErrControlNotFound
}

func (p *panicMetadataPlugin) ValidateConfiguration() error { return nil }

// TestReadPluginMetadata_RecoversFromVersionPanic pins the fault-isolation
// contract: a plugin whose Description() or Version() panics must not crash
// `list plugins`. The recovered entry carries Status="panicked" so JSON
// consumers can detect the failure without scraping stderr. (Name() is not
// tested here — see panicMetadataPlugin's doc for why.)
func TestReadPluginMetadata_RecoversFromVersionPanic(t *testing.T) {
	cases := []struct {
		name    string
		panicOn string
	}{
		{"panic in Description", "Description"},
		{"panic in Version", "Version"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			reg := audit.NewPluginRegistry()
			require.NoError(t, reg.RegisterPlugin(&panicMetadataPlugin{
				pluginName: "panic-test-" + tc.panicOn,
				panicOn:    tc.panicOn,
			}))

			entry := readPluginMetadata(reg, "panic-test-"+tc.panicOn)
			assert.Equal(
				t,
				pluginStatusPanicked,
				entry.Status,
				"panic in %s must produce Status=panicked",
				tc.panicOn,
			)
			assert.NotEmpty(t, entry.Name, "Name must be non-empty even after panic")
			assert.Equal(t, versionUnknown, entry.Version, "Version must default to %q after panic", versionUnknown)
		})
	}
}

// TestListPlugins_LoadFailureSurfacesInJSON verifies that dynamic plugin
// load failures appear as load-failed entries in the JSON envelope (not
// only on stderr). Without this, agents piping --json | jq cannot detect
// partial-load conditions and may treat a degraded enumeration as
// authoritative.
func TestListPlugins_LoadFailureSurfacesInJSON(t *testing.T) {
	// Build a load failure directly: feed a constructed entry through the
	// constructor and through emitList, then re-parse to confirm shape.
	entry := newLoadFailedEntry("evil.so", assertableError{msg: "preflight rejected: world-writable"})
	assert.Equal(t, "evil.so", entry.Name)
	assert.Equal(t, pluginStatusLoadFailed, entry.Status, "load-failed entries must carry the documented Status")
	assert.Equal(t, versionUnknown, entry.Version)
	assert.Contains(t, entry.LoadError, "world-writable")

	// Round-trip through JSON to confirm the loadError field surfaces.
	buf := &bytes.Buffer{}
	require.NoError(t, emitList(buf, []listEntry{entry}, true))

	var decoded []map[string]any
	require.NoError(t, json.Unmarshal(buf.Bytes(), &decoded))
	require.Len(t, decoded, 1)
	assert.Equal(t, pluginStatusLoadFailed, decoded[0]["status"])
	assert.Contains(t, decoded[0]["loadError"], "world-writable")
}

// assertableError is a minimal error fixture for tests that need a known
// error message in the JSON loadError field.
type assertableError struct{ msg string }

func (e assertableError) Error() string { return e.msg }
