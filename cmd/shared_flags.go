// Package cmd provides the command-line interface for opnDossier.
package cmd

import (
	"os"
	"path/filepath"
	"strings"

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
// addSharedTemplateFlags adds shared CLI flags for content, formatting, and audit-related
// output controls to the provided command. The function name is retained for backward
// compatibility but it no longer introduces template-specific flags.
//
// Flags added:
//
//	--include-tunables    Include system tunables in the output report.
//	--section             Comma-separated list of specific sections to include (e.g., system,network,firewall).
//	--wrap                Text wrap width in characters (-1 = auto-detect terminal width, 0 = no wrapping).
//	--no-wrap             Disable text wrapping (alias for --wrap 0).
//	--comprehensive       Generate comprehensive detailed reports with full configuration analysis.
//
// Example:
//
//	mycmd --section system,network --wrap 100 --include-tunables --comprehensive
//
// cmd must be a non-nil *cobra.Command.
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

// addDisplayFlags adds display-related CLI flags to cmd.
// It defines the --theme flag to select the rendering theme ("light", "dark", "auto", or "none")
// and annotates the flag as display-related.
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

// ValidXMLFiles provides shell completion for XML configuration files.
// It returns a list of .xml files in the current directory and subdirectories,
// along with a completion directive for file completion.
func ValidXMLFiles(_ *cobra.Command, _ []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	// If user is completing a path, get the directory part
	dir := "."
	prefix := ""
	if toComplete != "" {
		if strings.HasSuffix(toComplete, "/") {
			dir = toComplete
		} else {
			dir = filepath.Dir(toComplete)
			prefix = filepath.Base(toComplete)
		}
	}

	var completions []string

	// Walk the directory to find XML files
	entries, err := os.ReadDir(dir)
	if err != nil {
		// Fall back to default file completion
		return nil, cobra.ShellCompDirectiveDefault
	}

	for _, entry := range entries {
		name := entry.Name()

		// Skip hidden files
		if strings.HasPrefix(name, ".") {
			continue
		}

		// Check if entry matches the prefix
		if prefix != "" && !strings.HasPrefix(strings.ToLower(name), strings.ToLower(prefix)) {
			continue
		}

		fullPath := filepath.Join(dir, name)
		if dir == "." {
			fullPath = name
		}

		if entry.IsDir() {
			// Add directories with trailing slash for further completion
			completions = append(completions, fullPath+"/")
		} else if strings.HasSuffix(strings.ToLower(name), ".xml") {
			// Add XML files
			completions = append(completions, fullPath)
		}
	}

	if len(completions) == 0 {
		// Fall back to default file completion if no matches
		return nil, cobra.ShellCompDirectiveDefault
	}

	return completions, cobra.ShellCompDirectiveNoSpace
}

// ValidFormats provides shell completion for output format values.
func ValidFormats(_ *cobra.Command, _ []string, _ string) ([]string, cobra.ShellCompDirective) {
	return []string{
		"markdown\tStandard markdown format (default)",
		"json\tJSON format for programmatic access",
		"yaml\tYAML format for configuration management",
	}, cobra.ShellCompDirectiveNoFileComp
}

// ValidThemes provides shell completion for theme values.
func ValidThemes(_ *cobra.Command, _ []string, _ string) ([]string, cobra.ShellCompDirective) {
	return []string{
		"auto\tAuto-detect based on terminal (default)",
		"light\tLight theme for light terminals",
		"dark\tDark theme for dark terminals",
		"none\tNo styling (raw output)",
	}, cobra.ShellCompDirectiveNoFileComp
}

// ValidSections provides shell completion for section filter values.
func ValidSections(_ *cobra.Command, _ []string, _ string) ([]string, cobra.ShellCompDirective) {
	return []string{
		"system\tSystem configuration and settings",
		"network\tNetwork interfaces and routing",
		"firewall\tFirewall rules and policies",
		"services\tConfigured services and daemons",
		"security\tSecurity settings and certificates",
	}, cobra.ShellCompDirectiveNoFileComp
}

// ValidColorModes provides shell completion for color mode values.
func ValidColorModes(_ *cobra.Command, _ []string, _ string) ([]string, cobra.ShellCompDirective) {
	return []string{
		"auto\tAuto-detect color support (default)",
		"always\tAlways use colors",
		"never\tNever use colors",
	}, cobra.ShellCompDirectiveNoFileComp
}
