// Package cmd provides the command-line interface for opnDossier.
package cmd

import (
	"github.com/EvilBit-Labs/opnDossier/internal/converter"
	"github.com/spf13/cobra"
)

// listFormatsJSONOutput controls whether `list formats` emits JSON.
var listFormatsJSONOutput bool //nolint:gochecknoglobals // Cobra flag variable

// formatEntry is the per-format record emitted by `list formats --json`.
// Only canonical format names appear; aliases (e.g. yml -> yaml) are
// intentionally excluded so the list reflects the values an agent should
// pass to --format. Each entry carries a human-readable description sourced
// from the same lookup table the shell-completion code uses.
type formatEntry struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

func (e formatEntry) name() string { return e.Name }

// listFormatsCmd enumerates the output formats the running binary supports.
// The list is sourced from converter.DefaultRegistry so it stays in sync with
// whatever format handlers are registered at init() time.
var listFormatsCmd = &cobra.Command{ //nolint:gochecknoglobals // Cobra command
	Use:     "formats",
	Short:   "List available output formats",
	GroupID: "",
	Annotations: map[string]string{
		annotationLightweight: annotationValueOn, // Pure registry enumeration, no config load needed.
	},
	Args: cobra.NoArgs,
	Long: `List the output formats the running opnDossier binary supports.

The output is sourced from the format registry and reflects the canonical
names you can pass to --format on commands such as convert and audit. Aliases
like 'yml' are not listed; use the canonical name they resolve to.

By default the command writes one name per line. Use --json to emit a
structured array of {name, description} objects.`,
	Example: `  # Plain text, one format per line
  opnDossier list formats

  # JSON output for automation
  opnDossier list formats --json`,
	RunE: runListFormats,
}

func runListFormats(cmd *cobra.Command, _ []string) error {
	names := converter.DefaultRegistry.ValidFormats()
	entries := make([]listEntry, 0, len(names))

	for _, n := range names {
		desc, ok := formatDescriptions[n]
		if !ok {
			desc = n + " format"
		}

		entries = append(entries, formatEntry{Name: n, Description: desc})
	}

	return emitList(cmd.OutOrStdout(), entries, listFormatsJSONOutput)
}

func init() {
	listCmd.AddCommand(listFormatsCmd)

	listFormatsCmd.Flags().BoolVar(
		&listFormatsJSONOutput,
		"json",
		false,
		"Emit a JSON array of {name, description} objects",
	)
}
