// Package cmd provides the command-line interface for opnDossier.
package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/EvilBit-Labs/opnDossier/internal/constants"
	"github.com/EvilBit-Labs/opnDossier/internal/diff"
	"github.com/EvilBit-Labs/opnDossier/internal/diff/formatters"
	"github.com/EvilBit-Labs/opnDossier/internal/model"
	"github.com/EvilBit-Labs/opnDossier/internal/model/common"
	"github.com/spf13/cobra"
)

// Diff command flags.
var (
	diffOutputFile   string   //nolint:gochecknoglobals // Cobra flag variable
	diffFormat       string   //nolint:gochecknoglobals // Output format (terminal, markdown, json, html)
	diffMode         string   //nolint:gochecknoglobals // Display mode (unified, side-by-side)
	diffSections     []string //nolint:gochecknoglobals // Sections to compare
	diffSecurityOnly bool     //nolint:gochecknoglobals // Show only security-relevant changes
	diffNormalize    bool     //nolint:gochecknoglobals // Normalize values before comparing
	diffDetectOrder  bool     //nolint:gochecknoglobals // Detect rule reordering
)

// Diff format constants.
const (
	// DiffFormatTerminal specifies styled terminal output for diffs.
	DiffFormatTerminal = "terminal"
	// DiffFormatMarkdown specifies Markdown output for diffs.
	DiffFormatMarkdown = "markdown"
	// DiffFormatJSON specifies JSON output for diffs.
	DiffFormatJSON = "json"
	// DiffFormatHTML specifies self-contained HTML output for diffs.
	DiffFormatHTML = "html"
)

// Diff display mode constants.
const (
	// DiffModeUnified specifies unified (default) display mode.
	DiffModeUnified = "unified"
	// DiffModeSideBySide specifies side-by-side display mode.
	DiffModeSideBySide = "side-by-side"
)

// diffRequiredArgs is the number of required arguments for the diff command.
const diffRequiredArgs = 2

// init registers the diff command and its flags with the root command.
func init() {
	rootCmd.AddCommand(diffCmd)

	// Output flags
	diffCmd.Flags().
		StringVarP(&diffOutputFile, "output", "o", "", "Output file path (default: print to console)")
	diffCmd.Flags().
		StringVarP(&diffFormat, "format", "f", DiffFormatTerminal, "Output format (terminal, markdown, json, html)")
	diffCmd.Flags().
		StringVarP(&diffMode, "mode", "m", DiffModeUnified, "Display mode (unified, side-by-side)")

	// Filter flags
	diffCmd.Flags().
		StringSliceVarP(&diffSections, "section", "s", nil, "Sections to compare (default: all)")
	diffCmd.Flags().
		BoolVar(&diffSecurityOnly, "security", false, "Show only security-relevant changes")

	// Analysis flags
	diffCmd.Flags().
		BoolVar(&diffNormalize, "normalize", false, "Normalize displayed values (whitespace, IPs, ports)")
	diffCmd.Flags().
		BoolVar(&diffDetectOrder, "detect-order", false, "Detect rule reordering without content changes")

	// Register flag completions
	registerDiffFlagCompletions(diffCmd)

	// Preserve flag order
	diffCmd.Flags().SortFlags = false
}

// registerDiffFlagCompletions registers completion functions for diff command flags.
func registerDiffFlagCompletions(cmd *cobra.Command) {
	if err := cmd.RegisterFlagCompletionFunc("format", ValidDiffFormats); err != nil {
		logger.Warn("failed to register format completion", "error", err)
	}
	if err := cmd.RegisterFlagCompletionFunc("mode", ValidDiffModes); err != nil {
		logger.Warn("failed to register mode completion", "error", err)
	}
	if err := cmd.RegisterFlagCompletionFunc("section", ValidDiffSections); err != nil {
		logger.Warn("failed to register section completion", "error", err)
	}
}

// ValidDiffFormats provides completion for diff format flag.
func ValidDiffFormats(_ *cobra.Command, _ []string, _ string) ([]string, cobra.ShellCompDirective) {
	return []string{
		DiffFormatTerminal + "\tColor-coded terminal output",
		DiffFormatMarkdown + "\tMarkdown formatted output",
		DiffFormatJSON + "\tJSON structured output",
		DiffFormatHTML + "\tSelf-contained HTML report",
	}, cobra.ShellCompDirectiveNoFileComp
}

// ValidDiffModes provides completion for diff mode flag.
func ValidDiffModes(_ *cobra.Command, _ []string, _ string) ([]string, cobra.ShellCompDirective) {
	return []string{
		DiffModeUnified + "\tStandard unified diff view (default)",
		DiffModeSideBySide + "\tTwo-column side-by-side comparison",
	}, cobra.ShellCompDirectiveNoFileComp
}

// ValidDiffSections provides completion for diff section flag.
func ValidDiffSections(_ *cobra.Command, _ []string, _ string) ([]string, cobra.ShellCompDirective) {
	return []string{
		"system\tSystem settings (hostname, domain, timezone)",
		"firewall\tFirewall rules",
		"nat\tNAT configuration and port forwards",
		"interfaces\tNetwork interfaces",
		"vlans\tVLAN configuration",
		"dhcp\tDHCP servers and static reservations",
		"users\tUser accounts",
		"routing\tStatic routes",
		"dns\tDNS configuration",
		"vpn\tVPN configuration",
		"certificates\tCertificate management",
	}, cobra.ShellCompDirectiveNoFileComp
}

var diffCmd = &cobra.Command{ //nolint:gochecknoglobals // Cobra command
	Use:               "diff <old-config.xml> <new-config.xml>",
	Short:             "Compare two OPNsense configuration files.",
	GroupID:           "core",
	ValidArgsFunction: ValidXMLFiles,
	PreRunE: func(_ *cobra.Command, _ []string) error {
		return validateDiffFlags()
	},
	Long: `The 'diff' command compares two OPNsense config.xml files and shows meaningful
configuration changes in a content-aware, security-focused way.

Unlike a simple XML diff, this command understands OPNsense configuration semantics:
  - Firewall rules are matched by UUID and compared structurally
  - Interfaces are compared by name with detailed field-level changes
  - Static DHCP reservations are tracked by MAC address
  - Security-impacting changes are scored by a pattern-based engine (high/medium/low)

OUTPUT FORMATS:
  terminal   - Color-coded terminal output with symbols (+/-/~)
  markdown   - Markdown formatted output for documentation
  json       - JSON structured output for automation
  html       - Self-contained HTML report

DISPLAY MODES:
  unified      - Standard diff view (default)
  side-by-side - Two-column comparison (terminal only)

SECTIONS:
  system      - System settings (hostname, domain, timezone)
  firewall    - Firewall rules
  nat         - NAT configuration and port forwards
  interfaces  - Network interfaces
  vlans       - VLAN configuration
  dhcp        - DHCP servers and static reservations
  users       - User accounts
  routing     - Static routes

ANALYSIS OPTIONS:
  --normalize     Normalize displayed values (whitespace, IPs, ports)
  --detect-order  Detect when rules are reordered without content changes

SECURITY IMPACT:
  Changes are scored by a pattern-based security engine:
  - HIGH: Permissive rules (any-any), risky configurations
  - MEDIUM: User changes, NAT modifications, protocol downgrades
  - LOW: Minor modifications with limited security relevance

Examples:
  # Compare two configs with terminal output (default)
  opndossier diff old-config.xml new-config.xml

  # Generate markdown report
  opndossier diff old-config.xml new-config.xml -f markdown -o changes.md

  # Compare only firewall rules
  opndossier diff old-config.xml new-config.xml --section firewall

  # Show only security-relevant changes
  opndossier diff old-config.xml new-config.xml --security

  # Generate JSON for automation
  opndossier diff old-config.xml new-config.xml -f json | jq '.changes[]'

  # Compare multiple sections
  opndossier diff old-config.xml new-config.xml -s firewall,nat,interfaces

  # Generate self-contained HTML report
  opndossier diff old-config.xml new-config.xml -f html -o report.html

  # Side-by-side terminal comparison
  opndossier diff old-config.xml new-config.xml -m side-by-side

  # Normalize values and detect reordering
  opndossier diff old-config.xml new-config.xml --normalize --detect-order`,
	Args: cobra.ExactArgs(diffRequiredArgs),
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()
		if ctx == nil {
			ctx = context.Background()
		}

		// Validate device type flag early before any file processing
		if err := validateDeviceType(); err != nil {
			return err
		}

		// Get configuration and logger from CommandContext
		cmdCtx := GetCommandContext(cmd)
		if cmdCtx == nil {
			return errors.New("command context not initialized")
		}
		cmdLogger := cmdCtx.Logger

		// Create timeout context
		timeoutCtx, cancel := context.WithTimeout(ctx, constants.DefaultProcessingTimeout)
		defer cancel()

		// Parse both configuration files
		oldPath := filepath.Clean(args[0])
		newPath := filepath.Clean(args[1])

		cmdLogger.Debug("Parsing configuration files", "old", oldPath, "new", newPath)

		oldConfig, err := parseConfigFile(timeoutCtx, oldPath)
		if err != nil {
			return fmt.Errorf("failed to parse old config %s: %w", oldPath, err)
		}

		newConfig, err := parseConfigFile(timeoutCtx, newPath)
		if err != nil {
			return fmt.Errorf("failed to parse new config %s: %w", newPath, err)
		}

		// Build diff options
		opts := diff.Options{
			Sections:     diffSections,
			SecurityOnly: diffSecurityOnly,
			Format:       diffFormat,
			Mode:         diffMode,
			Normalize:    diffNormalize,
			DetectOrder:  diffDetectOrder,
		}

		// Create diff engine and compare
		engine := diff.NewEngine(oldConfig, newConfig, opts, cmdLogger)
		result, err := engine.Compare(timeoutCtx)
		if err != nil {
			return fmt.Errorf("failed to compare configurations: %w", err)
		}

		// Set metadata
		result.Metadata.OldFile = oldPath
		result.Metadata.NewFile = newPath

		// Format and output the result
		return outputDiffResult(cmd, result, opts)
	},
}

// parseConfigFile parses a device configuration file via the ParserFactory.
func parseConfigFile(ctx context.Context, path string) (*common.CommonDevice, error) {
	// Make path absolute if needed
	if !filepath.IsAbs(path) {
		absPath, err := filepath.Abs(path)
		if err != nil {
			return nil, fmt.Errorf("failed to get absolute path: %w", err)
		}
		path = absPath
	}

	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	device, err := model.NewParserFactory().CreateDevice(ctx, file, sharedDeviceType, false)
	if err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}

	return device, nil
}

// outputDiffResult formats and outputs the diff result.
func outputDiffResult(cmd *cobra.Command, result *diff.Result, opts diff.Options) error {
	// Determine output destination
	output := cmd.OutOrStdout()
	var outputFile *os.File

	if diffOutputFile != "" {
		var err error
		outputFile, err = os.Create(diffOutputFile)
		if err != nil {
			return fmt.Errorf("failed to create output file: %w", err)
		}
		defer func() {
			// Close error is important for write operations - data could be lost
			if cerr := outputFile.Close(); cerr != nil {
				// Log but don't override a previous error
				logger.Warn("failed to close output file", "error", cerr)
			}
		}()
		output = outputFile
	}

	// Create formatter via factory
	formatter, err := formatters.NewWithMode(opts.Format, opts.Mode, output)
	if err != nil {
		return fmt.Errorf("unsupported diff format: %w", err)
	}

	if formatErr := formatter.Format(result); formatErr != nil {
		return formatErr
	}

	// Sync to ensure all data is written to disk before returning success
	if outputFile != nil {
		if err := outputFile.Sync(); err != nil {
			return fmt.Errorf("failed to sync output file: %w", err)
		}
	}

	return nil
}

// validateDiffFlags validates the diff command flags.
func validateDiffFlags() error {
	// Validate format
	validFormats := []string{DiffFormatTerminal, DiffFormatMarkdown, DiffFormatJSON, DiffFormatHTML, ""}
	if !slices.Contains(validFormats, strings.ToLower(diffFormat)) {
		return fmt.Errorf(
			"invalid format %q, must be one of: %s",
			diffFormat,
			strings.Join([]string{DiffFormatTerminal, DiffFormatMarkdown, DiffFormatJSON, DiffFormatHTML}, ", "),
		)
	}

	// Validate mode
	validModes := []string{DiffModeUnified, DiffModeSideBySide, ""}
	if !slices.Contains(validModes, strings.ToLower(diffMode)) {
		return fmt.Errorf("invalid mode %q, must be one of: %s",
			diffMode, DiffModeUnified+", "+DiffModeSideBySide)
	}

	// Side-by-side mode only applies to terminal format
	normalizedFormat := strings.ToLower(diffFormat)
	if strings.EqualFold(diffMode, DiffModeSideBySide) &&
		normalizedFormat != DiffFormatTerminal && normalizedFormat != "" {
		return fmt.Errorf("--mode side-by-side is only supported with --format terminal, got %q", diffFormat)
	}

	// Sections that are implemented
	implementedSections := []string{
		"system",
		"firewall",
		"nat",
		"interfaces",
		"vlans",
		"dhcp",
		"users",
		"routing",
	}

	// Sections that are defined but not yet implemented
	unimplementedSections := []string{
		"dns",
		"vpn",
		"certificates",
	}

	// All valid sections (for error messages)
	allSections := make([]string, 0, len(implementedSections)+len(unimplementedSections))
	allSections = append(allSections, implementedSections...)
	allSections = append(allSections, unimplementedSections...)

	// Validate and normalize sections if provided
	if len(diffSections) > 0 {
		normalizedSections := make([]string, len(diffSections))
		for i, s := range diffSections {
			normalized := strings.ToLower(strings.TrimSpace(s))

			// Check if it's an unimplemented section
			if slices.Contains(unimplementedSections, normalized) {
				return fmt.Errorf("section %q comparison is not yet implemented; available sections: %s",
					s, strings.Join(implementedSections, ", "))
			}

			// Check if it's a valid section at all
			if !slices.Contains(allSections, normalized) {
				return fmt.Errorf("invalid section %q, must be one of: %s",
					s, strings.Join(implementedSections, ", "))
			}

			normalizedSections[i] = normalized
		}
		diffSections = normalizedSections
	}

	return nil
}
