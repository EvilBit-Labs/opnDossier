// Package cmd provides the command-line interface for opnDossier.
package cmd

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/EvilBit-Labs/opnDossier/internal/converter"
	"github.com/EvilBit-Labs/opnDossier/internal/logging"
	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
	"github.com/EvilBit-Labs/opnDossier/pkg/parser"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// Shared flag variables for convert and display commands.
var (
	// Parsing flags.
	sharedDeviceType string //nolint:gochecknoglobals // Force device type (bypasses auto-detection)

	// Styling flags.
	sharedSections        []string //nolint:gochecknoglobals // Sections to include
	sharedTheme           string   //nolint:gochecknoglobals // Theme for rendering
	sharedWrapWidth       = -1     //nolint:gochecknoglobals // Text wrap width
	sharedNoWrap          bool     //nolint:gochecknoglobals // Disable text wrapping
	sharedIncludeTunables bool     //nolint:gochecknoglobals // Include system tunables in output
	sharedComprehensive   bool     //nolint:gochecknoglobals // Generate comprehensive report
	sharedRedact          bool     //nolint:gochecknoglobals // Redact sensitive fields in output

	// Audit flags.
	// TODO(#457): Remove shared audit globals — no longer bound to any CLI flags
	// after audit flag removal from convert. Retained because buildAuditOptions()
	// and generateOutputByFormat() still reference them.
	sharedAuditMode       string   //nolint:gochecknoglobals // Audit mode (standard, blue, red)
	sharedSelectedPlugins []string //nolint:gochecknoglobals // Selected compliance plugins
	sharedPluginDir       string   //nolint:gochecknoglobals // Directory for dynamic .so plugins
)

// addSharedTemplateFlags adds shared CLI flags for content, formatting, and audit-related
// output controls to the provided command. The function name is retained for backward
// compatibility but it no longer introduces template-specific flags.
//
// Flags added:
//
//	--include-tunables    Include all system tunables in report output (markdown, text, HTML only; JSON/YAML always include all tunables).
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
		BoolVar(&sharedIncludeTunables, "include-tunables", false, "Include all system tunables in report output (markdown, text, HTML only; JSON/YAML always include all tunables)")
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

// addSharedRedactFlag adds the --redact flag to cmd for redacting sensitive fields
// (passwords, keys, community strings) in output.
func addSharedRedactFlag(cmd *cobra.Command) {
	cmd.Flags().
		BoolVar(&sharedRedact, "redact", false, "Redact sensitive fields (passwords, keys, community strings) in output")
	setFlagAnnotation(cmd.Flags(), "redact", []string{"output"})
}

// Constants for flag validation.
const (
	// MinWrapWidth is the minimum recommended wrap width in characters.
	MinWrapWidth = 40
	// MaxWrapWidth is the maximum recommended wrap width in characters.
	MaxWrapWidth = 200
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

// formatDescriptions maps canonical format names to their shell completion descriptions.
// When registering a new format in the DefaultRegistry, add a description here too.
// Missing entries fall back to a generic description.
var formatDescriptions = map[string]string{ //nolint:gochecknoglobals // static lookup table
	"markdown": "Standard markdown format (default)",
	"json":     "JSON format for programmatic access",
	"yaml":     "YAML format for configuration management",
	"text":     "Plain text format (markdown without formatting)",
	"html":     "Self-contained HTML report for web viewing",
}

// deviceTypeDescriptions maps registered device types to their shell completion descriptions.
var deviceTypeDescriptions = map[string]string{ //nolint:gochecknoglobals // static lookup table
	"opnsense": "OPNsense firewall configuration",
}

// ValidFormats provides shell completion for output format values.
// Canonical format names are sourced from the converter.DefaultRegistry.
func ValidFormats(_ *cobra.Command, _ []string, _ string) ([]string, cobra.ShellCompDirective) {
	formats := converter.DefaultRegistry.ValidFormats()
	completions := make([]string, 0, len(formats))

	for _, f := range formats {
		desc, ok := formatDescriptions[f]
		if !ok {
			desc = f + " format"
		}

		completions = append(completions, f+"\t"+desc)
	}

	return completions, cobra.ShellCompDirectiveNoFileComp
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

// ValidAuditModes provides shell completion for audit mode values.
func ValidAuditModes(_ *cobra.Command, _ []string, _ string) ([]string, cobra.ShellCompDirective) {
	return []string{
		"standard\tNeutral, comprehensive documentation report",
		"blue\tDefensive audit with security findings",
		"red\tAttacker-focused recon report",
	}, cobra.ShellCompDirectiveNoFileComp
}

// ValidAuditPlugins provides shell completion for audit plugin values.
func ValidAuditPlugins(_ *cobra.Command, _ []string, _ string) ([]string, cobra.ShellCompDirective) {
	return []string{
		"stig\tSecurity Technical Implementation Guide",
		"sans\tSANS Firewall Baseline",
		"firewall\tFirewall Configuration Analysis",
	}, cobra.ShellCompDirectiveNoFileComp
}

// ValidDeviceTypes provides shell completion for device type values.
// Canonical device type names are sourced from the parser.DefaultRegistry.
func ValidDeviceTypes(_ *cobra.Command, _ []string, _ string) ([]string, cobra.ShellCompDirective) {
	devices := parser.DefaultRegistry().List()
	completions := make([]string, 0, len(devices))

	for _, d := range devices {
		desc, ok := deviceTypeDescriptions[d]
		if !ok {
			desc = d + " device type"
		}

		completions = append(completions, d+"\t"+desc)
	}

	return completions, cobra.ShellCompDirectiveNoFileComp
}

// validateDeviceType validates the --device-type flag against the parser registry.
// It checks the raw flag value directly against registered device types, so
// third-party parsers registered in the registry are accepted even if they are
// not built into the common.DeviceType enum.
func validateDeviceType() error {
	if sharedDeviceType == "" {
		return nil
	}

	if _, ok := parser.DefaultRegistry().Get(sharedDeviceType); ok {
		return nil
	}

	return fmt.Errorf(
		"unsupported device type: %q; supported values: %s",
		sharedDeviceType,
		parser.DefaultRegistry().SupportedDevices(),
	)
}

// resolveDeviceType converts the raw --device-type flag value into a
// common.DeviceType suitable for Factory.CreateDevice. For built-in types
// (opnsense, pfsense) it returns the canonical enum constant. For non-empty
// values that are validated against the registry but not in the built-in enum,
// it falls back to casting the normalized registry key, allowing third-party
// registered parsers to work via the CLI.
func resolveDeviceType() common.DeviceType {
	if sharedDeviceType == "" {
		return common.DeviceTypeUnknown
	}

	dt := common.ParseDeviceType(sharedDeviceType)
	if dt != common.DeviceTypeUnknown {
		return dt
	}

	// The value has been validated against the registry by validateDeviceType,
	// so it is a valid registered key that is not a built-in enum member.
	// Normalize to lowercase to match registry key normalization.
	return common.DeviceType(strings.ToLower(strings.TrimSpace(sharedDeviceType)))
}

// validateOutputFlags validates format, wrap, and section flag combinations that are
// shared across multiple commands (convert, audit). It checks mutual exclusivity of
// wrap flags, validates the output format against the converter registry, warns when
// section filtering is used with JSON or YAML, and validates wrap width range.
//
// Command-specific validation (e.g., audit mode, plugin names) should be performed
// in the calling command's PreRunE, not here.
//
// The cmdLogger parameter is used for structured warnings; if nil, warnings fall back to stderr.
func validateOutputFlags(flags *pflag.FlagSet, cmdLogger *logging.Logger) error {
	// Validate mutual exclusivity for wrap flags before other checks
	if flags != nil {
		noWrapFlag := flags.Lookup("no-wrap")
		wrapFlag := flags.Lookup("wrap")
		if noWrapFlag != nil && wrapFlag != nil && noWrapFlag.Changed && wrapFlag.Changed {
			return errors.New("--no-wrap and --wrap flags are mutually exclusive")
		}
	}

	// Validate format values via the converter registry
	if format != "" {
		validFormats := converter.DefaultRegistry.ValidFormatsWithAliases()
		if !slices.Contains(validFormats, strings.ToLower(format)) {
			return fmt.Errorf("invalid format %q, must be one of: %s", format, strings.Join(validFormats, ", "))
		}
	}

	// Validate output format compatibility using canonical names for consistent alias handling
	canonicalFormat, _ := converter.DefaultRegistry.Canonical(format)

	if canonicalFormat == "json" && len(sharedSections) > 0 {
		if cmdLogger != nil {
			cmdLogger.Warn("section filtering not supported with JSON format, sections will be ignored")
		} else {
			fmt.Fprintln(
				os.Stderr,
				"Warning: section filtering not supported with JSON format, sections will be ignored",
			)
		}
	}

	if canonicalFormat == "yaml" && len(sharedSections) > 0 {
		if cmdLogger != nil {
			cmdLogger.Warn("section filtering not supported with YAML format, sections will be ignored")
		} else {
			fmt.Fprintln(
				os.Stderr,
				"Warning: section filtering not supported with YAML format, sections will be ignored",
			)
		}
	}

	// Warn (not error) when wrap width is outside recommended range, matching display.go behavior.
	if sharedWrapWidth > 0 && (sharedWrapWidth < MinWrapWidth || sharedWrapWidth > MaxWrapWidth) {
		if cmdLogger != nil {
			cmdLogger.Warn("wrap width is outside recommended range",
				"width", sharedWrapWidth, "min", MinWrapWidth, "max", MaxWrapWidth)
		} else {
			fmt.Fprintf(os.Stderr, "Warning: wrap width %d is outside recommended range [%d, %d]\n",
				sharedWrapWidth, MinWrapWidth, MaxWrapWidth)
		}
	}

	if sharedWrapWidth < -1 {
		return fmt.Errorf("invalid wrap width %d: must be -1 (auto-detect), 0 (no wrapping), or positive",
			sharedWrapWidth)
	}

	return nil
}
