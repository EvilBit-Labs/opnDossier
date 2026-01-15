// Package cmd provides the command-line interface for opnDossier.
package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/EvilBit-Labs/opnDossier/internal/audit"
	"github.com/EvilBit-Labs/opnDossier/internal/constants"
	"github.com/EvilBit-Labs/opnDossier/internal/log"
	"github.com/EvilBit-Labs/opnDossier/internal/markdown"
	"github.com/EvilBit-Labs/opnDossier/internal/model"
	"github.com/spf13/cobra"
)

// Shared flag variables for convert and display commands.
var (
	// Template and styling flags.
	sharedSections          []string //nolint:gochecknoglobals // Sections to include
	sharedTheme             string   //nolint:gochecknoglobals // Theme for rendering
	sharedWrapWidth         = -1     //nolint:gochecknoglobals // Text wrap width
	sharedCustomTemplate    string   //nolint:gochecknoglobals // Custom template file path
	sharedIncludeTunables   bool     //nolint:gochecknoglobals // Include system tunables in output
	sharedTemplateCacheSize int      //nolint:gochecknoglobals // Template cache size (LRU max entries)

	// Warning flags to prevent repeated warnings.
	warnedAboutAbsoluteTemplatePath bool //nolint:gochecknoglobals // Gate absolute path warning

	// Generation engine flags.
	sharedUseTemplate bool   //nolint:gochecknoglobals // Explicitly enable template mode
	sharedEngine      string //nolint:gochecknoglobals // Generation engine (programmatic, template)
	sharedLegacy      bool   //nolint:gochecknoglobals // Enable legacy mode with deprecation warning

	// TODO: Audit mode functionality is not yet complete - disabled for now
	// sharedAuditMode       string   //nolint:gochecknoglobals // Audit mode (standard, blue, red)
	// sharedBlackhatMode    bool     //nolint:gochecknoglobals // Enable blackhat mode for red team reports.
	sharedComprehensive bool //nolint:gochecknoglobals // Generate comprehensive report
	// sharedSelectedPlugins []string //nolint:gochecknoglobals // Selected compliance plugins.
)

// addSharedTemplateFlags adds template flags that are common to both convert and display commands.
func addSharedTemplateFlags(cmd *cobra.Command) {
	// Generation engine flags
	cmd.Flags().
		BoolVar(&sharedUseTemplate, "use-template", false, "Explicitly enable template-based generation mode (default: programmatic)")
	setFlagAnnotation(cmd.Flags(), "use-template", []string{"engine"})

	cmd.Flags().
		StringVar(&sharedEngine, "engine", "", "Generation engine (programmatic, template) - overrides other flags")
	setFlagAnnotation(cmd.Flags(), "engine", []string{"engine"})

	cmd.Flags().
		BoolVar(&sharedLegacy, "legacy", false, "Enable legacy template mode with deprecation warning")
	setFlagAnnotation(cmd.Flags(), "legacy", []string{"engine"})
	// Mark --legacy as deprecated with migration guidance
	// CRITICAL ERROR HANDLING: MarkDeprecated failure is a programming error that must be caught
	// in development. If this fails, it means the flag name is wrong or Cobra is misconfigured.
	// This is NOT a runtime error - it happens during initialization before any user interaction.
	if err := cmd.Flags().MarkDeprecated("legacy",
		fmt.Sprintf("template mode will be removed in %s. Use programmatic generation (default) instead. "+
			"Migration guide: %s", constants.TemplateRemovalVersion, constants.MigrationGuideURL)); err != nil {
		// This indicates a programming error - the flag name should always exist
		panic(fmt.Sprintf("BUG: failed to mark legacy flag as deprecated: %v", err))
	}

	// Template flags
	cmd.Flags().
		StringVar(&sharedCustomTemplate, "custom-template", "", "Path to custom Go text/template file (automatically enables template mode)")
	setFlagAnnotation(cmd.Flags(), "custom-template", []string{"template"})

	// Register filename completion for custom-template flag
	// NON-CRITICAL ERROR HANDLING: Shell completion is optional - degrade gracefully if it fails.
	// Unlike MarkDeprecated (which MUST work), shell completion is a user convenience feature.
	// If registration fails, the flag still works but users lose autocomplete functionality.
	if err := cmd.RegisterFlagCompletionFunc(
		"custom-template",
		func(_ *cobra.Command, _ []string, _ string) ([]string, cobra.ShellCompDirective) {
			// Get files with .tmpl extension in the current directory and subdirectories
			var completions []string
			entries, err := os.ReadDir(".")
			if err != nil {
				return nil, cobra.ShellCompDirectiveError
			}

			for _, entry := range entries {
				if !entry.IsDir() && filepath.Ext(entry.Name()) == ".tmpl" {
					completions = append(completions, entry.Name())
				}
			}

			return completions, cobra.ShellCompDirectiveDefault
		},
	); err != nil {
		// Shell completion is optional - log warning but don't panic
		logger.Warn("shell completion unavailable for custom-template flag",
			"error", err,
			"impact", "users must type full paths manually")
	}

	cmd.Flags().
		BoolVar(&sharedIncludeTunables, "include-tunables", false, "Include system tunables in the output report")
	setFlagAnnotation(cmd.Flags(), "include-tunables", []string{"template"})

	cmd.Flags().
		StringSliceVar(&sharedSections, "section", []string{}, "Specific sections to include in output (comma-separated, e.g., system,network,firewall)")
	setFlagAnnotation(cmd.Flags(), "section", []string{"template"})

	cmd.Flags().
		IntVar(&sharedWrapWidth, "wrap", -1, "Text wrap width in characters (-1 = auto-detect terminal width, 0 = no wrapping, recommended: 80-120)")
	setFlagAnnotation(cmd.Flags(), "wrap", []string{"template"})

	cmd.Flags().
		IntVar(&sharedTemplateCacheSize, "template-cache-size", DefaultTemplateCacheSize, "Maximum number of templates to cache in memory (LRU eviction, default: 10)")
	setFlagAnnotation(cmd.Flags(), "template-cache-size", []string{"template"})
}

// addDisplayFlags adds display-specific flags (theme for glamour rendering).
func addDisplayFlags(cmd *cobra.Command) {
	cmd.Flags().
		StringVar(&sharedTheme, "theme", "", "Theme for rendering output (light, dark, auto, none)")
	setFlagAnnotation(cmd.Flags(), "theme", []string{"template"})
}

// Constants for flag validation.
const (
	MaxTemplateCacheSize = 100 // Maximum recommended template cache size
	MinWrapWidth         = 40  // Minimum recommended wrap width
	MaxWrapWidth         = 200 // Maximum recommended wrap width
)

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
	// Use ToSlash to ensure consistent path separators across platforms
	return filepath.ToSlash(filepath.Dir(sharedCustomTemplate))
}

// determineGenerationEngine determines which generation engine to use based on CLI flags and configuration.
// Returns true for template mode, false for programmatic mode (default).
// Returns ErrUnknownEngineType if an invalid engine type is specified.
//
// Flag precedence (highest to lowest):
// 1. --engine flag (explicit choice: "template" or "programmatic")
// 2. --legacy flag (deprecated, auto-enables template mode)
// 3. --custom-template flag (auto-enables template mode for backward compatibility)
// 4. --use-template flag (explicit template mode selection)
// 5. Default (programmatic mode)
//
// Emits structured deprecation warnings to stderr when template mode is selected,
// unless quiet mode is enabled via the global Cfg configuration.
func determineGenerationEngine(logger *log.Logger) (bool, error) {
	// Explicit engine flag takes highest precedence
	if sharedEngine != "" {
		switch strings.ToLower(sharedEngine) {
		case "template":
			logger.Debug("Using template engine (explicit --engine flag)")
			return true, nil
		case "programmatic":
			logger.Debug("Using programmatic engine (explicit --engine flag)")
			return false, nil
		default:
			return false, fmt.Errorf(
				"%w: %q (valid options: programmatic, template)",
				ErrUnknownEngineType,
				sharedEngine,
			)
		}
	}

	// Legacy flag with deprecation warning
	// Note: Cobra's MarkDeprecated already emits a warning, but we add structured details
	if sharedLegacy {
		logger.Debug("Using template engine (--legacy flag)")
		return true, nil
	}

	// Custom template automatically enables template mode (backward compatibility)
	if sharedCustomTemplate != "" {
		logger.Debug("Using template engine (custom template specified)")
		return true, nil
	}

	// Explicit use-template flag
	if sharedUseTemplate {
		logger.Debug("Using template engine (explicit --use-template flag)")
		return true, nil
	}

	// Default to programmatic mode
	logger.Debug("Using programmatic engine (default)")
	return false, nil
}

// validateTemplatePath validates and sanitizes a template file path for security.
// This prevents path traversal attacks and ensures templates are in safe locations.
//
// Security Note: This validation checks for ".." before cleaning to detect path traversal
// attempts. While this approach has limitations (e.g., encoded paths, symbolic links),
// it provides reasonable protection for user-provided template paths. Templates are
// executed in a controlled environment with no arbitrary code execution, so the risk
// is limited to reading files the user already has access to.
func validateTemplatePath(templatePath string) error {
	if templatePath == "" {
		return nil // Empty path is valid (no template)
	}

	// Check for path traversal attempts BEFORE cleaning
	// (filepath.Clean resolves ".." so checking after is ineffective)
	// Note: This doesn't catch all edge cases (encoded paths, symlinks) but provides
	// reasonable protection for the threat model
	if strings.Contains(templatePath, "..") {
		return fmt.Errorf("template path contains directory traversal sequence: %s", templatePath)
	}

	// Clean the path to normalize separators and resolve redundant elements
	cleanPath := filepath.Clean(templatePath)

	// Allow absolute paths with security warning
	// In template mode (deprecated), users need flexibility to specify custom templates
	// anywhere on their system. The risk is acceptable since template execution doesn't
	// allow arbitrary code execution beyond Go template syntax.
	if filepath.IsAbs(cleanPath) && !warnedAboutAbsoluteTemplatePath {
		logger.Warn("Using absolute template path",
			"path", cleanPath,
			"security_note", "ensure template source is trusted")
		warnedAboutAbsoluteTemplatePath = true
	}

	// Check if file exists and is readable
	if _, err := os.Stat(cleanPath); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("template file does not exist: %s", cleanPath)
		}
		return fmt.Errorf("cannot access template file: %w", err)
	}

	// Check file extension
	ext := filepath.Ext(cleanPath)
	validExtensions := []string{".tmpl", ".template", ".tpl", ".gohtml", ".gotmpl"}
	isValidExt := false
	for _, validExt := range validExtensions {
		if strings.EqualFold(ext, validExt) {
			isValidExt = true
			break
		}
	}

	if !isValidExt {
		logger.Warn("Template file has unusual extension", "path", cleanPath, "extension", ext)
	}

	return nil
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
