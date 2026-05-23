// Package cmd provides the command-line interface for opnDossier.
package cmd

import (
	"slices"

	"github.com/EvilBit-Labs/opnDossier/pkg/parser"
	"github.com/spf13/cobra"
)

// listDevicesJSONOutput controls whether `list devices` emits JSON.
var listDevicesJSONOutput bool //nolint:gochecknoglobals // Cobra flag variable

// deviceEntry is the per-device record emitted by `list devices --json`.
// In text mode only Name is rendered; Description is JSON-only.
type deviceEntry struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

func (e deviceEntry) name() string { return e.Name }

// listDevicesCmd enumerates the device-config parsers the running binary
// supports. The list is sourced from parser.DefaultRegistry() so it stays in
// sync with whatever parsers are registered at init() time.
var listDevicesCmd = &cobra.Command{ //nolint:gochecknoglobals // Cobra command
	Use:   "devices",
	Short: "List supported device-config parsers",
	Annotations: map[string]string{
		annotationLightweight: annotationValueOn, // Pure registry enumeration, no config load needed.
	},
	Args: cobra.NoArgs,
	Long: `List the device-configuration parsers the running opnDossier binary supports.

The output is sourced from the parser registry, so it always reflects what the
binary can actually accept for --device-type.

By default the command writes one name per line. Use --json to emit a structured
array of {name, description} objects suitable for jq or other automation.`,
	Example: `  # Plain text, one device type per line
  opnDossier list devices

  # JSON output for automation
  opnDossier list devices --json`,
	RunE: runListDevices,
}

func runListDevices(cmd *cobra.Command, _ []string) error {
	names := parser.DefaultRegistry().List()
	// Defensive sort at the command boundary even though the registry's
	// List() currently sorts (pkg/parser/registry.go). Per AGENTS.md cmd/
	// convention: CLI output derived from a map must be sorted before
	// rendering. Belt-and-suspenders against a future registry refactor
	// that drops the internal sort.
	slices.Sort(names)
	entries := make([]listEntry, 0, len(names))

	for _, n := range names {
		desc, ok := deviceTypeDescriptions[n]
		if !ok {
			desc = n + " device type"
		}

		entries = append(entries, deviceEntry{Name: n, Description: desc})
	}

	return emitList(cmd.OutOrStdout(), entries, listDevicesJSONOutput)
}

func init() {
	listCmd.AddCommand(listDevicesCmd)

	listDevicesCmd.Flags().BoolVar(
		&listDevicesJSONOutput,
		"json",
		false,
		"Emit a JSON array of {name, description} objects",
	)
	setFlagAnnotation(listDevicesCmd.Flags(), "json", []string{categoryOutput})
}
