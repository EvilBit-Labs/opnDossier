// Package cmd provides the command-line interface for opnDossier.
package cmd

import (
	"context"
	"errors"
	"path/filepath"

	"github.com/EvilBit-Labs/opnDossier/internal/audit"
	"github.com/EvilBit-Labs/opnDossier/internal/log"
	"github.com/EvilBit-Labs/opnDossier/internal/markdown"
	"github.com/EvilBit-Labs/opnDossier/internal/model"
	"github.com/spf13/cobra"
)

// Shared flag variables for convert and display commands.
var (
	// Template and styling flags.
	sharedSections        []string //nolint:gochecknoglobals // Sections to include
	sharedTheme           string   //nolint:gochecknoglobals // Theme for rendering
	sharedWrapWidth       int      //nolint:gochecknoglobals // Text wrap width
	sharedCustomTemplate  string   //nolint:gochecknoglobals // Custom template file path
	sharedIncludeTunables bool     //nolint:gochecknoglobals // Include system tunables in output

	// TODO: Audit mode functionality is not yet complete - disabled for now
	// sharedAuditMode       string   //nolint:gochecknoglobals // Audit mode (standard, blue, red)
	// sharedBlackhatMode    bool     //nolint:gochecknoglobals // Enable blackhat mode for red team reports.
	sharedComprehensive bool //nolint:gochecknoglobals // Generate comprehensive report
	// sharedSelectedPlugins []string //nolint:gochecknoglobals // Selected compliance plugins.
)

// addSharedTemplateFlags adds template flags that are common to both convert and display commands.
func addSharedTemplateFlags(cmd *cobra.Command) {
	// Template flags
	cmd.Flags().
		StringVar(&sharedCustomTemplate, "custom-template", "", "Path to custom GoTemplate file (overrides built-in templates and enables template mode)")
	setFlagAnnotation(cmd.Flags(), "custom-template", []string{"template"})

	cmd.Flags().
		BoolVar(&sharedIncludeTunables, "include-tunables", false, "Include system tunables in the output report")
	setFlagAnnotation(cmd.Flags(), "include-tunables", []string{"template"})

	cmd.Flags().
		StringSliceVar(&sharedSections, "section", []string{}, "Specific sections to include in output (comma-separated, e.g., system,network,firewall)")
	setFlagAnnotation(cmd.Flags(), "section", []string{"template"})

	cmd.Flags().
		IntVar(&sharedWrapWidth, "wrap", 0, "Text wrap width in characters (0 = no wrapping, recommended: 80-120)")
	setFlagAnnotation(cmd.Flags(), "wrap", []string{"template"})
}

// addDisplayFlags adds display-specific flags (theme for glamour rendering).
func addDisplayFlags(cmd *cobra.Command) {
	cmd.Flags().
		StringVar(&sharedTheme, "theme", "", "Theme for rendering output (light, dark, auto, none)")
	setFlagAnnotation(cmd.Flags(), "theme", []string{"template"})
}

// TODO: Audit mode functionality is not yet complete - disabled for now
// addSharedAuditFlags adds the shared audit mode flags to a command.
// These flags are used by the convert command for audit report generation.
func addSharedAuditFlags(cmd *cobra.Command) {
	// TODO: Audit mode flags are disabled until audit functionality is complete
	// Audit mode flags are commented out until audit functionality is complete

	cmd.Flags().
		BoolVar(&sharedComprehensive, "comprehensive", false, "Generate comprehensive detailed reports with full configuration analysis")
	setFlagAnnotation(cmd.Flags(), "comprehensive", []string{"audit"})
}

// getSharedTemplateDir returns the template directory path from the custom template flag.
// If custom-template is set, it extracts the directory path from the file path.
func getSharedTemplateDir() string {
	if sharedCustomTemplate == "" {
		return ""
	}
	// Extract directory from custom template file path
	// This maintains backward compatibility with the old template-dir behavior
	// but simplifies the user experience by requiring only one flag
	return filepath.Dir(sharedCustomTemplate)
}

// TODO: Audit mode functionality is not yet complete - disabled for now
// handleAuditMode generates an audit report using the audit mode controller and markdown generator.
func handleAuditMode(
	_ context.Context,
	_ *model.OpnSenseDocument,
	_ markdown.Options,
	_ *log.Logger,
	_ *audit.PluginRegistry,
) (string, error) {
	// TODO: Audit mode is disabled until audit functionality is complete
	return "", errors.New("audit mode functionality is not yet implemented")
}

// TODO: Audit mode functionality is not yet complete - disabled for now
// convertAuditModeToReportMode converts markdown audit mode to audit report mode.
func convertAuditModeToReportMode(_ markdown.AuditMode) (audit.ReportMode, error) {
	// TODO: Audit mode is disabled until audit functionality is complete
	return audit.ModeStandard, errors.New("audit mode functionality is not yet implemented")
}

// TODO: Audit mode functionality is not yet complete - disabled for now
// createModeConfig creates an audit mode configuration from options.
func createModeConfig(_ audit.ReportMode, _ markdown.Options) *audit.ModeConfig {
	// TODO: Audit mode is disabled until audit functionality is complete
	return &audit.ModeConfig{}
}

// TODO: Audit mode functionality is not yet complete - disabled for now
// generateBaseAuditReport generates the base audit report using template rendering.
func generateBaseAuditReport(
	_ context.Context,
	_ *model.OpnSenseDocument,
	_ markdown.Options,
	_ *log.Logger,
) (string, error) {
	// TODO: Audit mode is disabled until audit functionality is complete
	return "", errors.New("audit mode functionality is not yet implemented")
}

// TODO: Audit mode functionality is not yet complete - disabled for now
// createAuditMarkdownOptions creates markdown options specifically for audit mode.
func createAuditMarkdownOptions(_ markdown.Options) markdown.Options {
	// TODO: Audit mode is disabled until audit functionality is complete
	return markdown.Options{}
}

// TODO: Audit mode functionality is not yet complete - disabled for now
// appendAuditFindings appends audit findings summary to the report.
func appendAuditFindings(result string, _ *audit.Report) string {
	// TODO: Audit mode is disabled until audit functionality is complete
	return result
}
