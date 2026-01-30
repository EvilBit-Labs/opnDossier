// Package cmd provides the command-line interface for opnDossier.
package cmd

import (
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// customHelpTemplate is the enhanced help template with better organization.
// It groups flags by category and provides a cleaner visual hierarchy.
const customHelpTemplate = `{{with (or .Long .Short)}}{{. | trimTrailingWhitespaces}}

{{end}}{{if or .Runnable .HasSubCommands}}{{.UsageString}}{{end}}`

// customUsageTemplate provides the usage section with grouped flags.
const customUsageTemplate = `Usage:{{if .Runnable}}
  {{.UseLine}}{{end}}{{if .HasAvailableSubCommands}}
  {{.CommandPath}} [command]{{end}}{{if gt (len .Aliases) 0}}

Aliases:
  {{.NameAndAliases}}{{end}}{{if .HasExample}}

Examples:
{{.Example}}{{end}}{{if .HasAvailableSubCommands}}{{$cmds := .Commands}}{{if eq (len .Groups) 0}}

Available Commands:{{range $cmds}}{{if (or .IsAvailableCommand (eq .Name "help"))}}
  {{rpad .Name .NamePadding }} {{.Short}}{{end}}{{end}}{{else}}{{range $group := .Groups}}

{{.Title}}{{range $cmds}}{{if (and (eq .GroupID $group.ID) (or .IsAvailableCommand (eq .Name "help")))}}
  {{rpad .Name .NamePadding }} {{.Short}}{{end}}{{end}}{{end}}{{if not .AllChildCommandsHaveGroup}}

Additional Commands:{{range $cmds}}{{if (and (eq .GroupID "") (or .IsAvailableCommand (eq .Name "help")))}}
  {{rpad .Name .NamePadding }} {{.Short}}{{end}}{{end}}{{end}}{{end}}{{end}}{{if .HasAvailableLocalFlags}}

Flags:
{{.LocalFlags.FlagUsages | trimTrailingWhitespaces}}{{end}}{{if .HasAvailableInheritedFlags}}

Global Flags:
{{.InheritedFlags.FlagUsages | trimTrailingWhitespaces}}{{end}}{{if .HasHelpSubCommands}}

Additional help topics:{{range .Commands}}{{if .IsAdditionalHelpTopicCommand}}
  {{rpad .CommandPath .CommandPathPadding}} {{.Short}}{{end}}{{end}}{{end}}{{if .HasAvailableSubCommands}}

Use "{{.CommandPath}} [command] --help" for more information about a command.{{end}}
`

// InitHelp configures the root command with enhanced help features.
// This should be called after all commands are registered.
func InitHelp(cmd *cobra.Command) {
	// Enable suggestions for typos
	cmd.SuggestionsMinimumDistance = 2

	// Set custom help and usage templates
	cmd.SetHelpTemplate(customHelpTemplate)
	cmd.SetUsageTemplate(customUsageTemplate)

	// Add custom suggestion function for better context-aware hints
	cmd.SetHelpFunc(createCustomHelpFunc(cmd.HelpFunc()))
}

// createCustomHelpFunc wraps the default help function with additional features.
func createCustomHelpFunc(defaultHelp func(*cobra.Command, []string)) func(*cobra.Command, []string) {
	return func(cmd *cobra.Command, args []string) {
		// Call the default help
		defaultHelp(cmd, args)

		// Add helpful hints at the end for root command
		if cmd.Parent() == nil && cmd.HasAvailableSubCommands() {
			fmt.Println()
			fmt.Println("Tip: Use 'opnDossier validate config.xml' to check your configuration before converting.")
		}
	}
}

// GetSuggestions returns suggested commands for a given invalid input.
// It uses Levenshtein distance to find similar command names.
func GetSuggestions(cmd *cobra.Command, arg string) []string {
	if cmd.DisableSuggestions {
		return nil
	}

	suggestions := cmd.SuggestionsFor(arg)
	if len(suggestions) == 0 {
		// Try flag suggestions if no command suggestions found
		suggestions = suggestFlags(cmd, arg)
	}

	return suggestions
}

// suggestFlags returns suggested flag names for a given invalid flag input.
func suggestFlags(cmd *cobra.Command, arg string) []string {
	// Remove leading dashes for comparison
	flagName := strings.TrimLeft(arg, "-")
	if flagName == "" {
		return nil
	}

	var suggestions []string
	minDistance := cmd.SuggestionsMinimumDistance

	// Check local flags
	cmd.Flags().VisitAll(func(flag *pflag.Flag) {
		if distance := levenshteinDistance(flagName, flag.Name); distance <= minDistance {
			suggestions = append(suggestions, "--"+flag.Name)
		}
	})

	// Check inherited flags
	cmd.InheritedFlags().VisitAll(func(flag *pflag.Flag) {
		if distance := levenshteinDistance(flagName, flag.Name); distance <= minDistance {
			if !slices.Contains(suggestions, "--"+flag.Name) {
				suggestions = append(suggestions, "--"+flag.Name)
			}
		}
	})

	sort.Strings(suggestions)

	return suggestions
}

// levenshteinDistance calculates the edit distance between two strings.
// This is used for fuzzy matching to suggest corrections for typos.
func levenshteinDistance(s1, s2 string) int {
	if s1 == "" {
		return len(s2)
	}
	if s2 == "" {
		return len(s1)
	}

	// Create a matrix to store distances
	matrix := make([][]int, len(s1)+1)
	for i := range matrix {
		matrix[i] = make([]int, len(s2)+1)
		matrix[i][0] = i
	}
	for j := range matrix[0] {
		matrix[0][j] = j
	}

	// Fill in the matrix
	for i := 1; i <= len(s1); i++ {
		for j := 1; j <= len(s2); j++ {
			cost := 1
			if s1[i-1] == s2[j-1] {
				cost = 0
			}
			matrix[i][j] = min(
				matrix[i-1][j]+1,      // deletion
				matrix[i][j-1]+1,      // insertion
				matrix[i-1][j-1]+cost, // substitution
			)
		}
	}

	return matrix[len(s1)][len(s2)]
}

// GetFlagObjectsByCategory returns flag objects grouped by their category annotation.
// This is useful for organizing help output with full flag metadata.
// Unlike GetFlagsByCategory in root.go which returns flag names as strings,
// this function returns the actual pflag.Flag objects for richer help formatting.
func GetFlagObjectsByCategory(cmd *cobra.Command) map[string][]*pflag.Flag {
	categories := make(map[string][]*pflag.Flag)

	cmd.Flags().VisitAll(func(flag *pflag.Flag) {
		category := "other"
		if cat, ok := flag.Annotations["category"]; ok && len(cat) > 0 {
			category = cat[0]
		}
		categories[category] = append(categories[category], flag)
	})

	return categories
}

// FormatExamples formats command examples for display.
// It ensures consistent indentation and formatting.
func FormatExamples(examples string) string {
	if examples == "" {
		return ""
	}

	lines := strings.Split(examples, "\n")
	var formatted []string

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			formatted = append(formatted, "")
			continue
		}
		// Ensure consistent indentation (2 spaces)
		if strings.HasPrefix(trimmed, "#") {
			// Comments get 2 spaces
			formatted = append(formatted, "  "+trimmed)
		} else {
			// Commands get 4 spaces
			formatted = append(formatted, "    "+trimmed)
		}
	}

	return strings.Join(formatted, "\n")
}
