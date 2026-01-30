// Package cmd provides the command-line interface for opnDossier.
package cmd

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/EvilBit-Labs/opnDossier/internal/config"
	"github.com/charmbracelet/lipgloss"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

// ExitConfigValidationError is the exit code for configuration validation errors.
const ExitConfigValidationError = 5

// Line number display width for context output.
const lineNumberWidth = 6

// Terminal environment constants.
const (
	termEnvVar    = "TERM"
	noColorEnvVar = "NO_COLOR"
	termDumb      = "dumb"
)

// useStylesCheck returns true if terminal styling should be applied.
// Respects TERM=dumb and NO_COLOR environment variables.
func useStylesCheck() bool {
	return os.Getenv(termEnvVar) != termDumb && os.Getenv(noColorEnvVar) == ""
}

// configValidateCmd validates a configuration file.
var configValidateCmd = &cobra.Command{ //nolint:gochecknoglobals // Cobra command
	Use:   "validate [file]",
	Short: "Validate a configuration file",
	Long: `Validate a configuration file for syntax and semantic errors.

This command checks that a configuration file is valid YAML and that all
configuration options are recognized and have valid values. It reports
errors with line numbers where possible.

Exit codes:
  0 - Configuration is valid
  5 - Configuration validation error

Examples:
  # Validate the default configuration file
  opnDossier config validate

  # Validate a specific configuration file
  opnDossier config validate /path/to/config.yaml

  # Validate configuration in CI/CD pipeline
  opnDossier config validate ~/.opnDossier.yaml || exit 1`,
	Args: cobra.MaximumNArgs(1),
	RunE: runConfigValidate,
}

// init registers the config validate command.
func init() {
	configCmd.AddCommand(configValidateCmd)
}

// runConfigValidate executes the config validate command.
func runConfigValidate(cmd *cobra.Command, args []string) error {
	cmdCtx := GetCommandContext(cmd)
	if cmdCtx == nil {
		return errors.New("command context not initialized")
	}

	// Determine the configuration file to validate
	var configPath string
	if len(args) > 0 {
		configPath = args[0]
	} else {
		// Try default location
		home, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("failed to get home directory: %w", err)
		}
		configPath = filepath.Join(home, ".opnDossier.yaml")
	}

	// Check if file exists
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		return fmt.Errorf("configuration file not found: %s", configPath)
	}

	// Read the file
	content, err := os.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("failed to read configuration file: %w", err)
	}

	// Validate YAML syntax first
	var rawYAML map[string]any
	if err := yaml.Unmarshal(content, &rawYAML); err != nil {
		return reportYAMLError(configPath, content, err)
	}

	// Check for unknown keys
	unknownKeys := findUnknownKeys(rawYAML)
	if len(unknownKeys) > 0 {
		reportUnknownKeys(configPath, unknownKeys)
	}

	// Attempt to load the configuration to validate semantic correctness
	_, err = config.LoadConfig(configPath)
	if err != nil {
		return reportConfigError(configPath, err)
	}

	// Success
	if useStylesCheck() {
		successStyle := lipgloss.NewStyle().
			Foreground(lipgloss.Color("10")). // Green
			Bold(true)

		pathStyle := lipgloss.NewStyle().
			Foreground(lipgloss.Color("14")). // Cyan
			Underline(true)

		fmt.Printf("%s %s\n",
			successStyle.Render("Valid:"),
			pathStyle.Render(configPath),
		)

		if len(unknownKeys) > 0 {
			warnStyle := lipgloss.NewStyle().
				Foreground(lipgloss.Color("11")). // Yellow
				Italic(true)
			fmt.Println()
			fmt.Println(warnStyle.Render("Note: Unknown keys were found but ignored."))
		}
	} else {
		fmt.Printf("Valid: %s\n", configPath)
		if len(unknownKeys) > 0 {
			fmt.Println()
			fmt.Println("Note: Unknown keys were found but ignored.")
		}
	}

	return nil
}

// reportYAMLError reports a YAML parsing error with line number if available.
func reportYAMLError(configPath string, content []byte, err error) error {
	lineNum := extractYAMLLineNumber(err)

	if useStylesCheck() {
		errorStyle := lipgloss.NewStyle().
			Foreground(lipgloss.Color("9")). // Red
			Bold(true)

		pathStyle := lipgloss.NewStyle().
			Foreground(lipgloss.Color("14")). // Cyan
			Underline(true)

		lineStyle := lipgloss.NewStyle().
			Foreground(lipgloss.Color("11")). // Yellow
			Bold(true)

		fmt.Fprintf(os.Stderr, "%s %s\n",
			errorStyle.Render("YAML syntax error in:"),
			pathStyle.Render(configPath),
		)

		if lineNum > 0 {
			fmt.Fprintf(os.Stderr, "%s %d\n",
				lineStyle.Render("Line:"),
				lineNum,
			)
			showLineContext(content, lineNum)
		}

		fmt.Fprintf(os.Stderr, "\n%s %s\n",
			errorStyle.Render("Error:"),
			err.Error(),
		)
	} else {
		fmt.Fprintf(os.Stderr, "YAML syntax error in: %s\n", configPath)
		if lineNum > 0 {
			fmt.Fprintf(os.Stderr, "Line: %d\n", lineNum)
			showLineContextPlain(content, lineNum)
		}
		fmt.Fprintf(os.Stderr, "\nError: %s\n", err.Error())
	}

	ExitWithCode(ExitConfigValidationError)
	return nil // unreachable, but satisfies return
}

// extractYAMLLineNumber attempts to extract the line number from a YAML error.
func extractYAMLLineNumber(err error) int {
	// yaml.v3 errors typically contain "line X" or "yaml: line X:"
	errStr := err.Error()

	// Look for "line X:" pattern using strings.Cut
	_, after, found := strings.Cut(errStr, "line ")
	if found {
		var lineNum int
		if _, scanErr := fmt.Sscanf(after, "%d", &lineNum); scanErr == nil {
			return lineNum
		}
	}

	return 0
}

// showLineContext displays the lines around the error with styling.
func showLineContext(content []byte, lineNum int) {
	scanner := bufio.NewScanner(strings.NewReader(string(content)))
	currentLine := 0
	contextLines := 2 // Show 2 lines before and after

	lineNumStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("8")). // Gray
		Width(lineNumberWidth)

	errorLineStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("9")). // Red
		Bold(true)

	contextStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("15")) // White

	markerStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("9")). // Red
		Bold(true)

	fmt.Fprintln(os.Stderr)

	for scanner.Scan() {
		currentLine++
		if currentLine >= lineNum-contextLines && currentLine <= lineNum+contextLines {
			lineNumStr := lineNumStyle.Render(fmt.Sprintf("%4d |", currentLine))

			if currentLine == lineNum {
				fmt.Fprintf(os.Stderr, "%s %s %s\n",
					markerStyle.Render(">>>"),
					lineNumStr,
					errorLineStyle.Render(scanner.Text()),
				)
			} else {
				fmt.Fprintf(os.Stderr, "    %s %s\n",
					lineNumStr,
					contextStyle.Render(scanner.Text()),
				)
			}
		}
		if currentLine > lineNum+contextLines {
			break
		}
	}
}

// showLineContextPlain displays the lines around the error without styling.
func showLineContextPlain(content []byte, lineNum int) {
	scanner := bufio.NewScanner(strings.NewReader(string(content)))
	currentLine := 0
	contextLines := 2 // Show 2 lines before and after

	fmt.Fprintln(os.Stderr)

	for scanner.Scan() {
		currentLine++
		if currentLine >= lineNum-contextLines && currentLine <= lineNum+contextLines {
			if currentLine == lineNum {
				fmt.Fprintf(os.Stderr, ">>> %4d | %s\n", currentLine, scanner.Text())
			} else {
				fmt.Fprintf(os.Stderr, "    %4d | %s\n", currentLine, scanner.Text())
			}
		}
		if currentLine > lineNum+contextLines {
			break
		}
	}
}

// findUnknownKeys checks for unknown configuration keys.
func findUnknownKeys(raw map[string]any) []string {
	knownKeys := map[string]bool{
		"input_file":   true,
		"output_file":  true,
		"verbose":      true,
		"quiet":        true,
		"theme":        true,
		"format":       true,
		"template":     true,
		"sections":     true,
		"wrap":         true,
		"engine":       true,
		"use_template": true,
		"json_output":  true,
		"minimal":      true,
		"no_progress":  true,
		"display":      true,
		"export":       true,
		"logging":      true,
		"validation":   true,
	}

	knownNestedKeys := map[string]map[string]bool{
		"display": {
			"width":               true,
			"pager":               true,
			"syntax_highlighting": true,
		},
		"export": {
			"format":    true,
			"directory": true,
			"template":  true,
			"backup":    true,
		},
		"logging": {
			"level":  true,
			"format": true,
		},
		"validation": {
			"strict":            true,
			"schema_validation": true,
		},
	}

	var unknown []string

	for key, value := range raw {
		if !knownKeys[key] {
			unknown = append(unknown, key)
			continue
		}

		// Check nested keys
		if nested, ok := value.(map[string]any); ok {
			if nestedKnown, hasNested := knownNestedKeys[key]; hasNested {
				for nestedKey := range nested {
					if !nestedKnown[nestedKey] {
						unknown = append(unknown, key+"."+nestedKey)
					}
				}
			}
		}
	}

	// Sort for deterministic output
	sort.Strings(unknown)

	return unknown
}

// reportUnknownKeys reports unknown configuration keys as warnings.
func reportUnknownKeys(configPath string, keys []string) {
	if useStylesCheck() {
		warnStyle := lipgloss.NewStyle().
			Foreground(lipgloss.Color("11")). // Yellow
			Bold(true)

		keyStyle := lipgloss.NewStyle().
			Foreground(lipgloss.Color("14")). // Cyan
			Italic(true)

		fmt.Fprintf(os.Stderr, "%s %s\n",
			warnStyle.Render("Warning: Unknown configuration keys in"),
			configPath,
		)

		for _, key := range keys {
			fmt.Fprintf(os.Stderr, "  - %s\n", keyStyle.Render(key))
		}
	} else {
		fmt.Fprintf(os.Stderr, "Warning: Unknown configuration keys in %s\n", configPath)
		for _, key := range keys {
			fmt.Fprintf(os.Stderr, "  - %s\n", key)
		}
	}

	fmt.Fprintln(os.Stderr)
}

// reportConfigError reports a configuration validation error.
func reportConfigError(configPath string, err error) error {
	if useStylesCheck() {
		errorStyle := lipgloss.NewStyle().
			Foreground(lipgloss.Color("9")). // Red
			Bold(true)

		pathStyle := lipgloss.NewStyle().
			Foreground(lipgloss.Color("14")). // Cyan
			Underline(true)

		fmt.Fprintf(os.Stderr, "%s %s\n",
			errorStyle.Render("Configuration error in:"),
			pathStyle.Render(configPath),
		)

		fmt.Fprintf(os.Stderr, "\n%s %s\n",
			errorStyle.Render("Error:"),
			err.Error(),
		)
	} else {
		fmt.Fprintf(os.Stderr, "Configuration error in: %s\n", configPath)
		fmt.Fprintf(os.Stderr, "\nError: %s\n", err.Error())
	}

	ExitWithCode(ExitConfigValidationError)
	return nil // unreachable, but satisfies return
}
