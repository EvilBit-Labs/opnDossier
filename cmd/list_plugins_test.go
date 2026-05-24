// Package cmd provides the command-line interface for opnDossier.
package cmd

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
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

	// Register cleanup BEFORE any require.NoError call that could abort
	// the test mid-flight. If the first invocation panics or fails an
	// inner require, leaking SetOut/SetErr buffers into later tests breaks
	// output capture for the rest of the suite.
	t.Cleanup(func() {
		listPluginsCmd.SetOut(nil)
		listPluginsCmd.SetErr(nil)
	})

	buf1 := &bytes.Buffer{}
	listPluginsCmd.SetOut(buf1)
	listPluginsCmd.SetErr(&bytes.Buffer{})
	require.NoError(t, runListPlugins(listPluginsCmd, nil))

	buf2 := &bytes.Buffer{}
	listPluginsCmd.SetOut(buf2)
	listPluginsCmd.SetErr(&bytes.Buffer{})
	require.NoError(t, runListPlugins(listPluginsCmd, nil))

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

// TestListPlugins_DynamicPluginDirEndToEnd drives the full runListPlugins
// pipeline against a real --plugin-dir on disk. The test creates a stub
// .so file in a temp directory; the file will fail plugin.Open (or
// preflight) because it isn't a real shared object, and that failure
// must:
//
//   - propagate through pm.InitializePlugins -> pm.GetLoadResult()
//   - surface inline in the JSON envelope as a load-failed entry with
//     a non-empty LoadError
//   - emit the trust-model warning to stderr before any load attempt
//   - leave exit code 0 (failures are surfaced, not fatal — matching
//     the documented contract in docs/for-agents.md)
//
// Cross-platform: skipped on Windows because Go's plugin package and
// the preflight permission-bit checks are POSIX-only (GOTCHAS.md §2.5).
// This is the end-to-end happy path for the --plugin-dir code path; the
// helper-level TestListPlugins_LoadFailureSurfacesInJSON exercises the
// JSON shape independently via newLoadFailedEntry, but this test wires
// the full PluginManager.SetPluginDir -> InitializePlugins ->
// GetLoadResult chain that runListPlugins relies on.
func TestListPlugins_DynamicPluginDirEndToEnd(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("dynamic plugin loading is POSIX-only (GOTCHAS.md §2.5)")
	}

	listPluginsTestCleanup(t)

	pluginDir := t.TempDir()
	stubPath := filepath.Join(pluginDir, "stub.so")
	require.NoError(t, os.WriteFile(stubPath, []byte("not a real shared object"), 0o600))

	listPluginsPluginDir = pluginDir
	listPluginsJSONOutput = true

	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	listPluginsCmd.SetOut(stdout)
	listPluginsCmd.SetErr(stderr)
	t.Cleanup(func() {
		listPluginsCmd.SetOut(nil)
		listPluginsCmd.SetErr(nil)
	})

	// Run the full subcommand. A stub .so will fail to open; the
	// failure must surface in the JSON envelope, NOT abort the command.
	require.NoError(t, runListPlugins(listPluginsCmd, nil), "load failures must not be fatal")

	// Trust-model warning must have fired before the load attempt.
	warning := stderr.String()
	assert.Contains(t, warning, "--plugin-dir", "trust-model warning must mention --plugin-dir")
	assert.Contains(t, warning, "dynamic .so plugins", "trust-model warning must explicitly call out .so loading")

	// JSON envelope must contain a load-failed entry for stub.so.
	var entries []pluginEntry
	require.NoError(t, json.Unmarshal(stdout.Bytes(), &entries))

	var stub *pluginEntry
	for i := range entries {
		if entries[i].Name == "stub.so" {
			stub = &entries[i]

			break
		}
	}

	require.NotNil(t, stub, "stub.so must appear as a load-failed entry in the JSON envelope")
	assert.Equal(
		t,
		pluginStatusLoadFailed,
		stub.Status,
		"stub.so must carry Status=load-failed; got %q",
		stub.Status,
	)
	assert.NotEmpty(t, stub.LoadError, "load-failed entries must populate LoadError with the underlying failure reason")
	assert.NotEmpty(
		t,
		stub.Description,
		"load-failed entries must have non-empty Description (JSON envelope invariant)",
	)
	assert.Equal(t, versionUnknown, stub.Version, "load-failed entries must default Version to %q", versionUnknown)

	// Built-in plugins must still be enumerated alongside the failure.
	builtinFound := 0
	for _, e := range entries {
		switch e.Name {
		case "stig", "sans", "firewall":
			builtinFound++
		}
	}
	assert.GreaterOrEqual(
		t,
		builtinFound,
		1,
		"built-in plugins must still appear even when --plugin-dir has load failures",
	)
}

// TestListPlugins_DynamicPluginLoadFailureHiddenFromTextMode verifies the
// pipeline-safety contract for text mode: `list plugins --plugin-dir` in
// text mode must NOT include load-failed plugin names in stdout because
// the documented contract is that the output is safe to pipe directly into
// --plugins. A name like `stub.so` that won't actually load would break
// `opnDossier list plugins --plugin-dir ./plugins | xargs -I{} opnDossier
// audit --plugins {} config.xml`. Stderr WARN logs still fire (via the
// shared logger) so the operator has a diagnostic trail.
func TestListPlugins_DynamicPluginLoadFailureHiddenFromTextMode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("dynamic plugin loading is POSIX-only (GOTCHAS.md §2.5)")
	}

	listPluginsTestCleanup(t)

	pluginDir := t.TempDir()
	stubPath := filepath.Join(pluginDir, "stub.so")
	require.NoError(t, os.WriteFile(stubPath, []byte("not a real shared object"), 0o600))

	listPluginsPluginDir = pluginDir
	// listPluginsJSONOutput stays false — this test exercises the text-mode path.

	stdout := &bytes.Buffer{}
	listPluginsCmd.SetOut(stdout)
	listPluginsCmd.SetErr(&bytes.Buffer{})
	t.Cleanup(func() {
		listPluginsCmd.SetOut(nil)
		listPluginsCmd.SetErr(nil)
	})

	require.NoError(t, runListPlugins(listPluginsCmd, nil), "load failures must not be fatal")

	// Text-mode stdout must contain built-ins but NOT stub.so. Agents
	// piping into --plugins must never see a name that won't actually load.
	stdoutLines := strings.Split(strings.TrimRight(stdout.String(), "\n"), "\n")
	assert.Contains(t, stdoutLines, "stig", "built-in plugins must appear in text mode")
	assert.NotContains(
		t,
		stdoutLines,
		"stub.so",
		"text-mode output must NOT include load-failed plugin names (pipeline-safety contract)",
	)
}
