// Package cmd provides the command-line interface for opnDossier.
package cmd

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/spf13/cobra"
)

// listCmd is the parent command for capability-discovery subcommands.
// Each subcommand wraps an existing internal registry so AI agents and
// automation pipelines can enumerate the binary's capabilities via stable
// machine-readable output without parsing --help text.
var listCmd = &cobra.Command{ //nolint:gochecknoglobals // Cobra command
	Use:     "list",
	Short:   "Enumerate supported plugins, devices, and output formats",
	GroupID: groupUtility,
	Annotations: map[string]string{
		annotationLightweight: annotationValueOn, // Parent emits help only; no heavy init.
	},
	Args: cobra.NoArgs,
	Long: `The 'list' command group enumerates the capabilities the running opnDossier
binary supports: compliance plugins, device parsers, and output formats.

Subcommands emit one entry per line by default, suitable for shell pipelines,
and accept --json for structured machine-readable output.

Subcommands:
  plugins   List available compliance plugins (built-in plus dynamic if --plugin-dir set)
  devices   List supported device-config parsers
  formats   List available output formats

Examples:
  # Plain text output (one name per line)
  opnDossier list devices

  # JSON output suitable for jq
  opnDossier list formats --json

  # Preview dynamic plugins from a directory
  opnDossier list plugins --plugin-dir ./plugins`,
}

// init registers the list parent command with the root command. Child
// subcommands register themselves with listCmd in their own init() functions.
func init() {
	rootCmd.AddCommand(listCmd)
}

// emitList writes items to the command's stdout in either text or JSON form.
// In text mode it writes one name per line. In JSON mode it pretty-prints the
// items as a JSON array. Returns an error only when JSON marshaling fails;
// callers should let the error propagate so DetermineExitCode maps it to
// ExitGeneralError. Empty input is never an error — empty registries write
// nothing in text mode and "[]\n" in JSON mode.
func emitList(out io.Writer, items []listEntry, asJSON bool) error {
	if asJSON {
		// Normalize nil to an empty slice so JSON output is always "[]"
		// rather than "null" — agents parsing the output should never
		// have to handle the null case for an empty registry.
		if items == nil {
			items = []listEntry{}
		}

		encoded, err := json.MarshalIndent(items, "", "  ")
		if err != nil {
			return fmt.Errorf("encode list as JSON: %w", err)
		}

		if _, err := fmt.Fprintln(out, string(encoded)); err != nil {
			return fmt.Errorf("write JSON output: %w", err)
		}

		return nil
	}

	for _, item := range items {
		if _, err := fmt.Fprintln(out, item.name()); err != nil {
			return fmt.Errorf("write text output: %w", err)
		}
	}

	return nil
}

// listEntry is the shared interface implemented by per-subcommand entry types.
// Text mode writes only the name(); JSON mode marshals the concrete type so
// each subcommand can expose its own description/version/etc. fields.
type listEntry interface {
	name() string
}
