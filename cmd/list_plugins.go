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

// versionUnknown is the Version field substitute when per-plugin metadata
// cannot be read (registry-lookup failure or panic in plugin.Version()).
// Keeps the JSON envelope's Version field non-empty so machine consumers
// can rely on its presence even in defensive paths.
const versionUnknown = "unknown"

// pluginEntry is the per-plugin record emitted by `list plugins --json`.
// In text mode only Name is rendered; Description and Version are JSON-only.
type pluginEntry struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Version     string `json:"version"`
}

func (e pluginEntry) name() string { return e.Name }

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
structured array of {name, description, version} objects.`,
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
	// is supplied, mirroring the audit command (cmd/audit.go).
	warnPluginDirTrustModel(cmd.ErrOrStderr(), listPluginsPluginDir)

	pm := audit.NewPluginManager(logger, nil)
	if listPluginsPluginDir != "" {
		// SetPluginDir must precede InitializePlugins (GOTCHAS.md §2.3).
		// We pass explicit=true because the user supplied the flag.
		pm.SetPluginDir(listPluginsPluginDir, true)
	}

	if err := pm.InitializePlugins(cmd.Context()); err != nil {
		return fmt.Errorf("initialize plugins: %w", err)
	}

	// Surface any dynamic plugin load failures. Per-plugin failures are
	// non-fatal in InitializePlugins (the registry skips them), so without
	// this loop an operator passing --plugin-dir cannot distinguish a
	// successfully-loaded set from one where every .so was rejected.
	// Mirrors cmd/audit_handler.go behavior so the list command does not
	// silently swallow failures that audit would surface.
	loadResult := pm.GetLoadResult()
	if loadResult.Failed() > 0 {
		for _, f := range loadResult.Failures {
			logger.Warn("Dynamic plugin failed to load",
				"plugin", f.Name,
				"error", f.Err,
			)
		}
	}

	registry := pm.GetRegistry()
	names := registry.ListPlugins()
	entries := make([]listEntry, 0, len(names))

	for _, n := range names {
		entries = append(entries, readPluginMetadata(registry, n))
	}

	return emitList(cmd.OutOrStdout(), entries, listPluginsJSONOutput)
}

// readPluginMetadata invokes a plugin's Name/Description/Version with panic
// recovery so a single malformed dynamic .so cannot DoS the enumeration.
// audit.PluginRegistry.RunComplianceChecks has equivalent recovery
// (GOTCHAS.md §2.2); list plugins inherits the same fault-isolation
// requirement because the metadata getters can call into untrusted .so code.
// Returns a populated pluginEntry on every path; on panic or registry
// lookup failure, Version defaults to versionUnknown so the JSON envelope's
// non-empty-Version invariant holds.
func readPluginMetadata(registry *audit.PluginRegistry, name string) pluginEntry {
	entry := pluginEntry{Name: name, Version: versionUnknown}

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
		// same underlying map (GOTCHAS.md §2.2 note in plugin_manager.go).
		// If it does happen, log and keep the default entry so JSON
		// consumers see Version="unknown" rather than empty.
		logger.Warn("Listed plugin not retrievable from registry",
			"plugin", name,
			"error", err,
		)

		return entry
	}

	entry.Name = p.Name()
	entry.Description = p.Description()
	entry.Version = nonEmptyOr(p.Version(), versionUnknown)

	return entry
}

// nonEmptyOr returns s when non-empty, fallback otherwise. Used so plugins
// returning "" from Version() do not break the JSON envelope's non-empty
// invariant.
func nonEmptyOr(s, fallback string) string {
	if s == "" {
		return fallback
	}

	return s
}

func init() {
	listCmd.AddCommand(listPluginsCmd)

	listPluginsCmd.Flags().BoolVar(
		&listPluginsJSONOutput,
		"json",
		false,
		"Emit a JSON array of {name, description, version} objects",
	)

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
