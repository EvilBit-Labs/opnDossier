// Package cmd provides the command-line interface for opnDossier.
package cmd

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/charmbracelet/lipgloss"
	"github.com/spf13/cobra"
)

// configInitFlags holds the flags for the config init command.
var (
	configInitOutputPath string //nolint:gochecknoglobals // Cobra flag variable
	configInitForce      bool   //nolint:gochecknoglobals // Cobra flag variable
)

// configTemplate is the template configuration file content with all options commented.
const configTemplate = `# opnDossier Configuration File
# ================================
# This file configures the opnDossier CLI tool for processing OPNsense configurations.
# Place this file at ~/.opnDossier.yaml or specify with --config flag.
#
# Configuration precedence (highest to lowest):
#   1. Command-line flags
#   2. Environment variables (OPNDOSSIER_*)
#   3. Configuration file
#   4. Built-in defaults

# ------------------------------------------------------------------------------
# Basic Settings
# ------------------------------------------------------------------------------

# Default input file path (typically not set - use CLI argument)
# input_file: ""

# Default output file path (empty = stdout)
# output_file: ""

# Enable verbose logging (debug level)
# verbose: false

# Enable quiet mode (suppress all except errors)
# quiet: false

# Output format: markdown, json, yaml
# format: markdown

# Default theme for terminal output: light, dark, auto, none
# theme: ""

# Sections to include in output (empty = all sections)
# sections: []

# Text wrap width (-1 = auto-detect, 0 = no wrap, >0 = specific width)
# wrap: -1

# Report generation engine: programmatic, template
# engine: programmatic

# Enable template mode explicitly
# use_template: false

# Output errors in JSON format for automation
# json_output: false

# Minimal output mode (suppress progress and verbose messages)
# minimal: false

# Disable progress indicators
# no_progress: false

# ------------------------------------------------------------------------------
# Display Settings
# ------------------------------------------------------------------------------

# display:
#   # Terminal width for display (-1 = auto-detect)
#   width: -1
#
#   # Enable pager for long output
#   pager: false
#
#   # Enable syntax highlighting
#   syntax_highlighting: true

# ------------------------------------------------------------------------------
# Export Settings
# ------------------------------------------------------------------------------

# export:
#   # Default export format
#   format: markdown
#
#   # Default export directory
#   directory: ""
#
#   # Default export template
#   template: ""
#
#   # Create backup before overwriting
#   backup: false

# ------------------------------------------------------------------------------
# Logging Settings
# ------------------------------------------------------------------------------

# logging:
#   # Log level: debug, info, warn, error
#   level: info
#
#   # Log format: text, json
#   format: text

# ------------------------------------------------------------------------------
# Validation Settings
# ------------------------------------------------------------------------------

# validation:
#   # Enable strict validation
#   strict: false
#
#   # Enable XML schema validation
#   schema_validation: false

# ------------------------------------------------------------------------------
# Environment Variables
# ------------------------------------------------------------------------------
# All settings can be overridden via environment variables with OPNDOSSIER_ prefix:
#
#   OPNDOSSIER_VERBOSE=true
#   OPNDOSSIER_FORMAT=json
#   OPNDOSSIER_THEME=dark
#   OPNDOSSIER_WRAP=120
#   OPNDOSSIER_DISPLAY_WIDTH=100
#   OPNDOSSIER_LOGGING_LEVEL=debug
#   OPNDOSSIER_VALIDATION_STRICT=true
#
# For nested keys, use underscore as separator:
#   OPNDOSSIER_DISPLAY_SYNTAX_HIGHLIGHTING=false
`

// configInitCmd generates a template configuration file.
var configInitCmd = &cobra.Command{ //nolint:gochecknoglobals // Cobra command
	Use:   "init",
	Short: "Generate a template configuration file",
	Long: `Generate a template configuration file with all options commented out.

This creates a well-documented .opnDossier.yaml file that you can customize
to set your preferred defaults. The template includes all available options
with explanations.

By default, the configuration file is created in your home directory as
~/.opnDossier.yaml. Use --output to specify a different location.

Examples:
  # Generate template in default location (~/.opnDossier.yaml)
  opnDossier config init

  # Generate template at a custom path
  opnDossier config init --output /path/to/config.yaml

  # Overwrite existing configuration file
  opnDossier config init --force

  # Generate in current directory
  opnDossier config init --output .opnDossier.yaml`,
	Args: cobra.NoArgs,
	RunE: runConfigInit,
}

// init registers the config init command and its flags.
func init() {
	configCmd.AddCommand(configInitCmd)

	configInitCmd.Flags().
		StringVarP(&configInitOutputPath, "output", "o", "", "Output path for configuration file (default: ~/.opnDossier.yaml)")
	setFlagAnnotation(configInitCmd.Flags(), "output", []string{"output"})

	configInitCmd.Flags().
		BoolVarP(&configInitForce, "force", "f", false, "Overwrite existing configuration file")
	setFlagAnnotation(configInitCmd.Flags(), "force", []string{"output"})
}

// runConfigInit executes the config init command.
func runConfigInit(cmd *cobra.Command, _ []string) error {
	cmdCtx := GetCommandContext(cmd)
	if cmdCtx == nil {
		return errors.New("command context not initialized")
	}

	// Determine output path
	outputPath := configInitOutputPath
	if outputPath == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("failed to get home directory: %w", err)
		}
		outputPath = filepath.Join(home, ".opnDossier.yaml")
	}

	// Check if file exists
	if _, err := os.Stat(outputPath); err == nil {
		if !configInitForce {
			return fmt.Errorf("configuration file already exists at %s. Use --force to overwrite", outputPath)
		}
	}

	// Ensure directory exists
	dir := filepath.Dir(outputPath)
	if dir != "." && dir != "" {
		if _, err := os.Stat(dir); os.IsNotExist(err) {
			return fmt.Errorf("output directory does not exist: %s", dir)
		}
	}

	// Write the configuration file
	//nolint:gosec // Config files should be readable by the user
	if err := os.WriteFile(outputPath, []byte(configTemplate), 0o644); err != nil {
		return fmt.Errorf("failed to write configuration file: %w", err)
	}

	// Output success message with styling
	successStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("10")). // Green
		Bold(true)

	pathStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("14")). // Cyan
		Underline(true)

	fmt.Printf("%s %s\n",
		successStyle.Render("Created configuration file:"),
		pathStyle.Render(outputPath),
	)

	tipStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("8")). // Gray
		Italic(true)

	fmt.Println()
	fmt.Println(tipStyle.Render("Tip: Edit the file and uncomment options you want to customize."))

	return nil
}
