// Package cmd provides the command-line interface for opnDossier.
package cmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/EvilBit-Labs/opnDossier/internal/config"
	"github.com/charmbracelet/lipgloss"
	"github.com/spf13/cobra"
)

// configShowJSONOutput controls whether to output configuration as JSON.
var configShowJSONOutput bool //nolint:gochecknoglobals // Cobra flag variable

// Source indicator constants for configuration values.
const (
	sourceDefault    = "default"
	sourceConfigured = "configured"
)

// Style width constants for Lipgloss formatting.
const (
	configKeyWidth   = 35
	configValueWidth = 25
)

// ConfigValue represents a configuration value with its source.
type ConfigValue struct {
	Key    string `json:"key"`
	Value  any    `json:"value"`
	Source string `json:"source"`
}

// ConfigShowOutput represents the full configuration output for JSON format.
type ConfigShowOutput struct {
	Values []ConfigValue `json:"values"`
}

// configShowCmd displays the effective configuration with source indicators.
var configShowCmd = &cobra.Command{ //nolint:gochecknoglobals // Cobra command
	Use:   "show",
	Short: "Display the effective configuration",
	Long: `Display the effective configuration with source indicators showing where each
value originated from (file, environment variable, flag, or default).

The output shows all configuration options and their current values, along with
the source that set them. This helps understand how configuration is being
resolved and which settings take precedence.

Sources:
  default     - Built-in default value
  configured  - Set via file, environment variable, or flag

Examples:
  # Show configuration with styled output
  opnDossier config show

  # Show configuration as JSON for scripting
  opnDossier config show --json

  # Show configuration with a specific config file
  opnDossier --config /path/to/config.yaml config show`,
	Args: cobra.NoArgs,
	RunE: runConfigShow,
}

// init registers the config show command and its flags.
func init() {
	configCmd.AddCommand(configShowCmd)

	configShowCmd.Flags().
		BoolVar(&configShowJSONOutput, "json", false, "Output configuration in JSON format")
	setFlagAnnotation(configShowCmd.Flags(), "json", []string{"output"})
}

// runConfigShow executes the config show command.
func runConfigShow(cmd *cobra.Command, _ []string) error {
	cmdCtx := GetCommandContext(cmd)
	if cmdCtx == nil {
		return errors.New("command context not initialized")
	}

	cfg := cmdCtx.Config
	if cfg == nil {
		return errors.New("configuration not loaded")
	}

	// Build configuration values with sources
	values := buildConfigValues(cfg)

	if configShowJSONOutput {
		return outputConfigJSON(values)
	}

	return outputConfigStyled(values)
}

// buildConfigValues creates a list of configuration values with their sources.
// Note: Determining the actual source requires inspecting viper's precedence,
// which we approximate here based on whether values differ from defaults.
func buildConfigValues(cfg *config.Config) []ConfigValue {
	// Build values list with source detection
	// Source detection logic: if a value differs from the default, it came from
	// file, env, or flag. Without access to viper internals, we indicate "configured".
	values := []ConfigValue{
		// Flat fields
		{Key: "input_file", Value: cfg.InputFile, Source: detectSource(cfg.InputFile, "")},
		{Key: "output_file", Value: cfg.OutputFile, Source: detectSource(cfg.OutputFile, "")},
		{Key: "verbose", Value: cfg.Verbose, Source: detectSourceBool(cfg.Verbose, false)},
		{Key: "quiet", Value: cfg.Quiet, Source: detectSourceBool(cfg.Quiet, false)},
		{Key: "theme", Value: cfg.Theme, Source: detectSource(cfg.Theme, "")},
		{Key: "format", Value: cfg.Format, Source: detectSource(cfg.Format, "markdown")},
		{Key: "template", Value: cfg.Template, Source: detectSource(cfg.Template, "")},
		{Key: "sections", Value: cfg.Sections, Source: detectSourceSlice(cfg.Sections)},
		{Key: "wrap", Value: cfg.WrapWidth, Source: detectSourceInt(cfg.WrapWidth, -1)},
		{Key: "engine", Value: cfg.Engine, Source: detectSource(cfg.Engine, "programmatic")},
		{Key: "use_template", Value: cfg.UseTemplate, Source: detectSourceBool(cfg.UseTemplate, false)},
		{Key: "json_output", Value: cfg.JSONOutput, Source: detectSourceBool(cfg.JSONOutput, false)},
		{Key: "minimal", Value: cfg.Minimal, Source: detectSourceBool(cfg.Minimal, false)},
		{Key: "no_progress", Value: cfg.NoProgress, Source: detectSourceBool(cfg.NoProgress, false)},

		// Display section
		{Key: "display.width", Value: cfg.Display.Width, Source: detectSourceInt(cfg.Display.Width, -1)},
		{Key: "display.pager", Value: cfg.Display.Pager, Source: detectSourceBool(cfg.Display.Pager, false)},
		{
			Key:    "display.syntax_highlighting",
			Value:  cfg.Display.SyntaxHighlighting,
			Source: detectSourceBool(cfg.Display.SyntaxHighlighting, true),
		},

		// Export section
		{Key: "export.format", Value: cfg.Export.Format, Source: detectSource(cfg.Export.Format, "markdown")},
		{Key: "export.directory", Value: cfg.Export.Directory, Source: detectSource(cfg.Export.Directory, "")},
		{Key: "export.template", Value: cfg.Export.Template, Source: detectSource(cfg.Export.Template, "")},
		{Key: "export.backup", Value: cfg.Export.Backup, Source: detectSourceBool(cfg.Export.Backup, false)},

		// Logging section
		{Key: "logging.level", Value: cfg.Logging.Level, Source: detectSource(cfg.Logging.Level, "info")},
		{Key: "logging.format", Value: cfg.Logging.Format, Source: detectSource(cfg.Logging.Format, "text")},

		// Validation section
		{
			Key:    "validation.strict",
			Value:  cfg.Validation.Strict,
			Source: detectSourceBool(cfg.Validation.Strict, false),
		},
		{
			Key:    "validation.schema_validation",
			Value:  cfg.Validation.SchemaValidation,
			Source: detectSourceBool(cfg.Validation.SchemaValidation, false),
		},
	}

	return values
}

// detectSource determines if a string value differs from its default.
func detectSource(value, defaultVal string) string {
	if value == defaultVal {
		return sourceDefault
	}
	return sourceConfigured
}

// detectSourceBool determines if a bool value differs from its default.
func detectSourceBool(value, defaultVal bool) string {
	if value == defaultVal {
		return sourceDefault
	}
	return sourceConfigured
}

// detectSourceInt determines if an int value differs from its default.
func detectSourceInt(value, defaultVal int) string {
	if value == defaultVal {
		return sourceDefault
	}
	return sourceConfigured
}

// detectSourceSlice determines if a slice value differs from its default (empty).
func detectSourceSlice(value []string) string {
	if len(value) == 0 {
		return sourceDefault
	}
	return sourceConfigured
}

// outputConfigJSON outputs configuration values as JSON.
func outputConfigJSON(values []ConfigValue) error {
	output := ConfigShowOutput{Values: values}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(output); err != nil {
		return fmt.Errorf("failed to encode configuration as JSON: %w", err)
	}
	return nil
}

// outputConfigStyled outputs configuration values with Lipgloss styling.
func outputConfigStyled(values []ConfigValue) error {
	// Check if styling should be applied (respect TERM=dumb and NO_COLOR)
	if !useStylesCheck() {
		return outputConfigPlain(values)
	}

	// Define styles
	titleStyle := lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("12")). // Blue
		MarginBottom(1)

	keyStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("14")). // Cyan
		Width(configKeyWidth)

	valueStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("15")). // White
		Width(configValueWidth)

	sourceDefaultStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("8")). // Gray
		Italic(true)

	sourceConfiguredStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("10")). // Green
		Italic(true)

	// Print title
	fmt.Println(titleStyle.Render("opnDossier Effective Configuration"))
	fmt.Println()

	// Group values by section
	currentSection := ""
	for _, v := range values {
		// Determine section from key
		section := ""
		if strings.Contains(v.Key, ".") {
			section = strings.Split(v.Key, ".")[0]
		}

		// Print section header if changed
		if section != currentSection && section != "" {
			fmt.Println()
			sectionStyle := lipgloss.NewStyle().
				Bold(true).
				Foreground(lipgloss.Color("11")). // Yellow
				MarginTop(1)
			fmt.Println(sectionStyle.Render("[" + section + "]"))
			currentSection = section
		}

		// Format value for display
		valueStr := formatValueForDisplay(v.Value)

		// Select source style
		var sourceStyled string
		if v.Source == sourceDefault {
			sourceStyled = sourceDefaultStyle.Render("(" + v.Source + ")")
		} else {
			sourceStyled = sourceConfiguredStyle.Render("(" + v.Source + ")")
		}

		// Print the configuration line
		fmt.Printf("%s %s %s\n",
			keyStyle.Render(v.Key+":"),
			valueStyle.Render(valueStr),
			sourceStyled,
		)
	}

	return nil
}

// outputConfigPlain outputs configuration values without styling for dumb terminals.
func outputConfigPlain(values []ConfigValue) error {
	fmt.Println("opnDossier Effective Configuration")
	fmt.Println()

	// Group values by section
	currentSection := ""
	for _, v := range values {
		// Determine section from key
		section := ""
		if strings.Contains(v.Key, ".") {
			section = strings.Split(v.Key, ".")[0]
		}

		// Print section header if changed
		if section != currentSection && section != "" {
			fmt.Println()
			fmt.Println("[" + section + "]")
			currentSection = section
		}

		// Format value for display
		valueStr := formatValueForDisplay(v.Value)

		// Print the configuration line
		fmt.Printf("  %-35s %-25s (%s)\n", v.Key+":", valueStr, v.Source)
	}

	return nil
}

// formatValueForDisplay converts a configuration value to a display string.
func formatValueForDisplay(value any) string {
	switch v := value.(type) {
	case string:
		if v == "" {
			return "(empty)"
		}
		return v
	case bool:
		if v {
			return "true"
		}
		return "false"
	case int:
		return strconv.Itoa(v)
	case []string:
		if len(v) == 0 {
			return "(empty)"
		}
		return strings.Join(v, ", ")
	default:
		return fmt.Sprintf("%v", v)
	}
}
