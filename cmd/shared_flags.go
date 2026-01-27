// Package cmd provides the command-line interface for opnDossier.
package cmd

import (
	"github.com/spf13/cobra"
)

// Shared flag variables for convert and display commands.
var (
	// Styling flags.
	sharedSections        []string //nolint:gochecknoglobals // Sections to include
	sharedTheme           string   //nolint:gochecknoglobals // Theme for rendering
	sharedWrapWidth       = -1     //nolint:gochecknoglobals // Text wrap width
	sharedNoWrap          bool     //nolint:gochecknoglobals // Disable text wrapping
	sharedIncludeTunables bool     //nolint:gochecknoglobals // Include system tunables in output
	sharedComprehensive   bool     //nolint:gochecknoglobals // Generate comprehensive report
)

// addSharedTemplateFlags adds shared flags that are common to both convert and display commands.
// Note: This function name is kept for backward compatibility but no longer adds template-specific flags.
func addSharedTemplateFlags(cmd *cobra.Command) {
	cmd.Flags().
		BoolVar(&sharedIncludeTunables, "include-tunables", false, "Include system tunables in the output report")
	setFlagAnnotation(cmd.Flags(), "include-tunables", []string{"content"})

	cmd.Flags().
		StringSliceVar(&sharedSections, "section", []string{}, "Specific sections to include in output (comma-separated, e.g., system,network,firewall)")
	setFlagAnnotation(cmd.Flags(), "section", []string{"content"})

	cmd.Flags().
		IntVar(&sharedWrapWidth, "wrap", -1, "Text wrap width in characters (-1 = auto-detect terminal width, 0 = no wrapping, recommended: 80-120)")
	setFlagAnnotation(cmd.Flags(), "wrap", []string{"formatting"})

	cmd.Flags().
		BoolVar(&sharedNoWrap, "no-wrap", false, "Disable text wrapping (alias for --wrap 0)")
	setFlagAnnotation(cmd.Flags(), "no-wrap", []string{"formatting"})

	cmd.Flags().
		BoolVar(&sharedComprehensive, "comprehensive", false, "Generate comprehensive detailed reports with full configuration analysis")
	setFlagAnnotation(cmd.Flags(), "comprehensive", []string{"audit"})
}

// addDisplayFlags adds display-specific flags (theme for glamour rendering).
func addDisplayFlags(cmd *cobra.Command) {
	cmd.Flags().
		StringVar(&sharedTheme, "theme", "", "Theme for rendering output (light, dark, auto, none)")
	setFlagAnnotation(cmd.Flags(), "theme", []string{"display"})
}

// Constants for flag validation.
const (
	MinWrapWidth = 40  // Minimum recommended wrap width
	MaxWrapWidth = 200 // Maximum recommended wrap width
)
