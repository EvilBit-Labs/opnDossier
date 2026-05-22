// Package cmd provides the command-line interface for opnDossier.
package cmd

import (
	"fmt"

	"github.com/EvilBit-Labs/opnDossier/internal/audit"
	"github.com/spf13/cobra"
)

// listPluginsJSONOutput controls whether `list plugins` emits JSON.
var listPluginsJSONOutput bool //nolint:gochecknoglobals // Cobra flag variable

// listPluginsPluginDir is the optional directory to load dynamic .so plugins
// from before enumeration. When set, the trust-model warning emitted by
// warnPluginDirTrustModel fires on stderr (matching `audit --plugin-dir`).
var listPluginsPluginDir string //nolint:gochecknoglobals // Cobra flag variable

// Plugin entry Status values. The Status field on pluginEntry distinguishes
// successful enumeration from the failure paths so JSON consumers can
// detect issues without guessing from a sentinel Version value (which can
// collide with plugins that legitimately self-report any string,
// including "unknown"). A normal entry leaves Status as "" so the field
// is omitted from JSON via `omitempty`; failure entries carry one of the
// pluginStatus* constants below.
const (
	pluginStatusPanicked      = "panicked"       // Name/Description/Version panicked
	pluginStatusLookupFailed  = "lookup-failed"  // ListPlugins returned a name GetPlugin can't resolve
	pluginStatusLoadFailed    = "load-failed"    // Dynamic .so failed preflight or plugin.Open
	pluginStatusVersionFilled = "version-filled" // Version was empty, fallback applied
)

// versionUnknown substitutes for an empty Version when a plugin reports ""
// but otherwise loaded successfully. Status="version-filled" signals the
// substitution so consumers don't conflate it with a plugin that genuinely
// self-reports "unknown".
const versionUnknown = "unknown"

// pluginEntry is the per-plugin record emitted by `list plugins --json`.
// In text mode only Name is rendered; the remaining fields are JSON-only.
//
// Status is omitted from JSON when "ok" so the common-case envelope stays
// minimal. LoadError is populated only when Status == pluginStatusLoadFailed.
//
// Invariants enforced by the constructors (newPluginEntry / newLoadFailedEntry):
//   - Name is always non-empty.
//   - Version is always non-empty (versionUnknown when no real value available).
//   - Status is one of the pluginStatus* constants.
//
// Direct struct literals bypass these invariants; prefer the constructors.
type pluginEntry struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Version     string `json:"version"`
	Status      string `json:"status,omitempty"`
	LoadError   string `json:"loadError,omitempty"`
}

func (e pluginEntry) name() string { return e.Name }

// newPluginEntry constructs an entry with non-empty Version. The common
// success case leaves Status as "" so the JSON envelope stays minimal
// (omitempty drops the field). If the plugin's Version() reports empty,
// the entry is marked pluginStatusVersionFilled so consumers can tell the
// fallback fired and that the plugin's self-reported version is not
// available.
func newPluginEntry(name, description, version string) pluginEntry {
	entry := pluginEntry{
		Name:        name,
		Description: description,
		Version:     version,
	}
	if version == "" {
		entry.Version = versionUnknown
		entry.Status = pluginStatusVersionFilled
	}

	return entry
}

// newLoadFailedEntry constructs an entry representing a dynamic plugin that
// failed preflight or plugin.Open. Carries the underlying error message so
// the JSON envelope is self-describing — agents don't need to scrape stderr.
func newLoadFailedEntry(name string, err error) pluginEntry {
	msg := ""
	if err != nil {
		msg = err.Error()
	}

	return pluginEntry{
		Name:      name,
		Version:   versionUnknown,
		Status:    pluginStatusLoadFailed,
		LoadError: msg,
	}
}

// listPluginsCmd enumerates the compliance plugins the running binary can use.
// Built-in plugins are always shown; dynamic .so plugins appear when an
// explicit --plugin-dir is supplied (matching the audit command's contract).
//
// Not lightweight: requires audit.PluginManager.InitializePlugins which runs
// each built-in plugin's registration logic and, when --plugin-dir is set,
// the preflight + plugin.Open path (GOTCHAS.md §2.3, §2.5).
var listPluginsCmd = &cobra.Command{ //nolint:gochecknoglobals // Cobra command
	Use:   "plugins",
	Short: "List available compliance plugins",
	Args:  cobra.NoArgs,
	Long: `List the compliance plugins the running opnDossier binary supports.

Built-in plugins (such as STIG, SANS, and firewall) are always listed. To
include dynamically-loaded .so plugins, pass --plugin-dir pointing at the
directory containing them; that flag triggers the same trust-model warning
and preflight checks that the audit command applies.

By default the command writes one plugin name per line. Use --json to emit a
structured array of {name, description, version, status, loadError?}
objects. Status is "ok" for normal entries (and omitted from JSON), or one
of "panicked", "lookup-failed", "load-failed", "version-filled" when the
metadata could not be read normally.`,
	Example: `  # Plain text, one plugin name per line
  opnDossier list plugins

  # JSON output for automation
  opnDossier list plugins --json

  # Include dynamic plugins from a directory
  opnDossier list plugins --plugin-dir ./plugins --json`,
	RunE: runListPlugins,
}

func runListPlugins(cmd *cobra.Command, _ []string) error {
	// Surface the dynamic-plugin trust-model warning whenever --plugin-dir
	// is supplied, mirroring the audit command (cmd/audit.go). Treat write
	// failure as fatal since this is a security-sensitive disclosure: better
	// to abort than to load a dynamic .so without the operator having seen
	// the warning.
	if err := warnPluginDirTrustModel(cmd.ErrOrStderr(), listPluginsPluginDir); err != nil {
		return fmt.Errorf("emit trust-model warning: %w", err)
	}

	pm := audit.NewPluginManager(logger, nil)
	if listPluginsPluginDir != "" {
		// SetPluginDir must precede InitializePlugins (GOTCHAS.md §2.3).
		// We pass explicit=true because the user supplied the flag.
		pm.SetPluginDir(listPluginsPluginDir, true)
	}

	if err := pm.InitializePlugins(cmd.Context()); err != nil {
		return fmt.Errorf("initialize plugins: %w", err)
	}

	registry := pm.GetRegistry()
	names := registry.ListPlugins()

	// Surface dynamic plugin load failures both via WARN logs (legacy
	// stderr surface) AND inline in the JSON envelope as load-failed
	// entries (machine-readable). Agents piping --json | jq no longer
	// need to scrape stderr to detect partial loads.
	loadResult := pm.GetLoadResult()
	entries := make([]listEntry, 0, len(names)+loadResult.Failed())

	for _, n := range names {
		entries = append(entries, readPluginMetadata(registry, n))
	}

	for _, f := range loadResult.Failures {
		logger.Warn("Dynamic plugin failed to load",
			"plugin", f.Name,
			"error", f.Err,
		)
		entries = append(entries, newLoadFailedEntry(f.Name, f.Err))
	}

	return emitList(cmd.OutOrStdout(), entries, listPluginsJSONOutput)
}

// readPluginMetadata invokes a plugin's Name/Description/Version with panic
// recovery so a single malformed dynamic .so cannot DoS the enumeration.
// audit.PluginRegistry.RunComplianceChecks has equivalent recovery
// (GOTCHAS.md §2.2); list plugins inherits the same fault-isolation
// requirement because the metadata getters can call into untrusted .so code.
// Returns a populated pluginEntry on every path; the returned Status field
// distinguishes "ok" / "panicked" / "lookup-failed" / "version-filled".
//
// The named return is required so the deferred recover can preserve the
// pre-populated panic-fallback entry — Go returns the zero value on
// recover() in unnamed-return functions, which would erase the Name and
// versionUnknown defaults populated below.
//
//nolint:nonamedreturns // intentional: defer/recover needs to mutate the return value
func readPluginMetadata(registry *audit.PluginRegistry, name string) (entry pluginEntry) {
	// Seed the entry with safe defaults tagged "panicked". Success paths
	// overwrite the whole value via newPluginEntry below; if a metadata
	// getter panics, the defer/recover fires and this seed survives.
	entry = pluginEntry{
		Name:    name,
		Version: versionUnknown,
		Status:  pluginStatusPanicked,
	}

	defer func() {
		if r := recover(); r != nil {
			logger.Warn("Plugin metadata read panicked",
				"plugin", name,
				"recovered", fmt.Sprintf("%v", r),
			)
		}
	}()

	p, err := registry.GetPlugin(name)
	if err != nil {
		// Should be unreachable — ListPlugins and GetPlugin read the
		// same underlying map (see equivalent defensive note in
		// internal/audit/plugin_manager.go and the explicit lookup-failed
		// status here so consumers can detect the divergence if it ever
		// happens).
		logger.Warn("Listed plugin not retrievable from registry",
			"plugin", name,
			"error", err,
		)
		entry.Status = pluginStatusLookupFailed

		return entry
	}

	entry = newPluginEntry(p.Name(), p.Description(), p.Version())

	return entry
}

func init() {
	listCmd.AddCommand(listPluginsCmd)

	listPluginsCmd.Flags().BoolVar(
		&listPluginsJSONOutput,
		"json",
		false,
		"Emit a JSON array of {name, description, version, status?, loadError?} objects",
	)
	setFlagAnnotation(listPluginsCmd.Flags(), "json", []string{categoryOutput})

	listPluginsCmd.Flags().StringVar(
		&listPluginsPluginDir,
		"plugin-dir",
		"",
		pluginDirFlagUsage,
	)

	// Match the audit command's annotation so tooling that filters by
	// flag-category sees plugin-dir consistently across commands.
	setFlagAnnotation(listPluginsCmd.Flags(), "plugin-dir", []string{categoryAudit})
}
