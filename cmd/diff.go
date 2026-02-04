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
	"github.com/EvilBit-Labs/opnDossier/internal/parser"
	"github.com/spf13/cobra"
)

// Diff command flags.
var (
	diffOutputFile   string   //nolint:gochecknoglobals // Cobra flag variable
	diffFormat       string   //nolint:gochecknoglobals // Output format (terminal, markdown, json)
	diffSections     []string //nolint:gochecknoglobals // Sections to compare
	diffSecurityOnly bool     //nolint:gochecknoglobals // Show only security-relevant changes
)

// Diff format constants.
const (
	DiffFormatTerminal = "terminal"
	DiffFormatMarkdown = "markdown"
	DiffFormatJSON     = "json"
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
		StringVarP(&diffFormat, "format", "f", DiffFormatTerminal, "Output format (terminal, markdown, json)")

	// Filter flags
	diffCmd.Flags().
		StringSliceVarP(&diffSections, "section", "s", nil, "Sections to compare (default: all)")
	diffCmd.Flags().
		BoolVar(&diffSecurityOnly, "security", false, "Show only security-relevant changes")

	// Register flag completions
	registerDiffFlagCompletions(diffCmd)

	// Preserve flag order
	diffCmd.Flags().SortFlags = false
}

// registerDiffFlagCompletions registers completion functions for diff command flags.
func registerDiffFlagCompletions(cmd *cobra.Command) {
	if err := cmd.RegisterFlagCompletionFunc("format", ValidDiffFormats); err != nil {
		logger.Debug("failed to register format completion", "error", err)
	}
	if err := cmd.RegisterFlagCompletionFunc("section", ValidSections); err != nil {
		logger.Debug("failed to register section completion", "error", err)
	}
}

// ValidDiffFormats provides completion for diff format flag.
func ValidDiffFormats(_ *cobra.Command, _ []string, _ string) ([]string, cobra.ShellCompDirective) {
	return []string{
		DiffFormatTerminal + "\tColor-coded terminal output",
		DiffFormatMarkdown + "\tMarkdown formatted output",
		DiffFormatJSON + "\tJSON structured output",
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
  - Security-impacting changes are flagged (high/medium/low)

OUTPUT FORMATS:
  terminal   - Color-coded terminal output with symbols (+/-/~)
  markdown   - Markdown formatted output for documentation
  json       - JSON structured output for automation

SECTIONS:
  system      - System settings (hostname, domain, timezone)
  firewall    - Firewall rules
  nat         - NAT configuration and port forwards
  interfaces  - Network interfaces
  vlans       - VLAN configuration
  dhcp        - DHCP servers and static reservations
  users       - User accounts
  routing     - Static routes

SECURITY IMPACT:
  Changes are flagged with security impact levels:
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
  opndossier diff old-config.xml new-config.xml -s firewall,nat,interfaces`,
	Args: cobra.ExactArgs(diffRequiredArgs),
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()
		if ctx == nil {
			ctx = context.Background()
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

// parseConfigFile parses an OPNsense XML configuration file.
func parseConfigFile(ctx context.Context, path string) (*diff.OpnSenseDocument, error) {
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

	p := parser.NewXMLParser()
	doc, err := p.Parse(ctx, file)
	if err != nil {
		return nil, fmt.Errorf("failed to parse XML: %w", err)
	}

	return doc, nil
}

// outputDiffResult formats and outputs the diff result.
func outputDiffResult(cmd *cobra.Command, result *diff.Result, opts diff.Options) error {
	// Determine output destination
	output := cmd.OutOrStdout()
	if diffOutputFile != "" {
		file, err := os.Create(diffOutputFile)
		if err != nil {
			return fmt.Errorf("failed to create output file: %w", err)
		}
		defer file.Close()
		output = file
	}

	// Format based on requested format
	switch strings.ToLower(opts.Format) {
	case DiffFormatTerminal, "":
		formatter := formatters.NewTerminalFormatter(output)
		return formatter.Format(result)
	case DiffFormatMarkdown:
		formatter := formatters.NewMarkdownFormatter(output)
		return formatter.Format(result)
	case DiffFormatJSON:
		formatter := formatters.NewJSONFormatter(output)
		return formatter.Format(result)
	default:
		return fmt.Errorf("unsupported diff format: %s", opts.Format)
	}
}

// validateDiffFlags validates the diff command flags.
func validateDiffFlags() error {
	// Validate format
	validFormats := []string{DiffFormatTerminal, DiffFormatMarkdown, DiffFormatJSON, ""}
	if !slices.Contains(validFormats, strings.ToLower(diffFormat)) {
		return fmt.Errorf("invalid format %q, must be one of: %s",
			diffFormat, strings.Join([]string{DiffFormatTerminal, DiffFormatMarkdown, DiffFormatJSON}, ", "))
	}

	// Validate sections if provided
	if len(diffSections) > 0 {
		validSections := []string{
			"system",
			"firewall",
			"nat",
			"interfaces",
			"vlans",
			"dhcp",
			"users",
			"routing",
			"dns",
			"vpn",
			"certificates",
		}
		for _, s := range diffSections {
			if !slices.Contains(validSections, strings.ToLower(s)) {
				return fmt.Errorf("invalid section %q, must be one of: %s",
					s, strings.Join(validSections, ", "))
			}
		}
	}

	return nil
}
