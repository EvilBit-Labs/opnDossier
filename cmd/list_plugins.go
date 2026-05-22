// Package cmd provides the command-line interface for opnDossier.
package cmd

import (
	"context"
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
	// is supplied, mirroring the audit command (cmd/audit.go:138).
	warnPluginDirTrustModel(cmd.ErrOrStderr(), listPluginsPluginDir)

	pm := audit.NewPluginManager(logger, nil)
	if listPluginsPluginDir != "" {
		// SetPluginDir must precede InitializePlugins (GOTCHAS.md §2.3).
		// We pass explicit=true because the user supplied the flag.
		pm.SetPluginDir(listPluginsPluginDir, true)
	}

	if err := pm.InitializePlugins(context.Background()); err != nil {
		return fmt.Errorf("initialize plugins: %w", err)
	}

	registry := pm.GetRegistry()
	names := registry.ListPlugins()
	entries := make([]listEntry, 0, len(names))

	for _, n := range names {
		p, err := registry.GetPlugin(n)
		if err != nil {
			// Should be unreachable — ListPlugins and GetPlugin read the
			// same underlying map (GOTCHAS.md §2.2 note in plugin_manager.go).
			// If it does happen, fall back to a name-only entry so the
			// command still reports every plugin the registry knows.
			entries = append(entries, pluginEntry{Name: n})

			continue
		}

		entries = append(entries, pluginEntry{
			Name:        p.Name(),
			Description: p.Description(),
			Version:     p.Version(),
		})
	}

	return emitList(cmd.OutOrStdout(), entries, listPluginsJSONOutput)
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
