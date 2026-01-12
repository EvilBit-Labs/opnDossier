package markdown

import (
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/EvilBit-Labs/opnDossier/internal/constants"
	"github.com/EvilBit-Labs/opnDossier/internal/log"
)

// templateDeprecationWarningOnce ensures the deprecation warning is displayed
// at most once per process execution, even if multiple template generations occur.
var templateDeprecationWarningOnce sync.Once

const (
	// Box formatting constants.
	deprecationWarningBoxPadding    = 4 // "║  " prefix and "  ║" suffix
	deprecationWarningBorderPadding = 2 // Border padding for "╔═" and "═╗"
	deprecationWarningCenterDivisor = 2 // For centering text calculation

	// Content width constants.
	deprecationWarningURLPadding      = 6  // URL padding for "║  " prefix and "  ║" suffix
	deprecationWarningMinContentWidth = 66 // Minimum width for fixed content lines
)

func formatTemplateDeprecationWarningBox() string {
	// Keep this formatting stable: tests validate key content, and users may copy/paste it.
	// Calculate box width based on the longest content line (the URL).
	minContentWidth := len(constants.MigrationGuideURL) + deprecationWarningURLPadding

	// Ensure minimum width for other content lines (the fixed text lines).
	boxWidth := max(minContentWidth, deprecationWarningMinContentWidth)

	// Inner content width is boxWidth - padding (for "║  " and "  ║")
	contentWidth := boxWidth - deprecationWarningBoxPadding

	// Helper to create a content line with proper padding
	makeLine := func(content string) string {
		padding := max(0, contentWidth-len(content))
		return fmt.Sprintf("║  %s%s  ║", content, strings.Repeat(" ", padding))
	}

	// Helper to create horizontal border
	makeBorder := func(left, right string) string {
		return left + strings.Repeat("═", boxWidth-deprecationWarningBorderPadding) + right
	}

	// Helper to center text within content width
	centerText := func(text string) string {
		totalPadding := contentWidth - len(text)
		if totalPadding < 0 {
			return text
		}
		leftPad := totalPadding / deprecationWarningCenterDivisor
		rightPad := totalPadding - leftPad
		return strings.Repeat(" ", leftPad) + text + strings.Repeat(" ", rightPad)
	}

	lines := []string{
		makeBorder("╔", "╗"),
		makeLine(centerText("⚠️  DEPRECATION WARNING ⚠️")),
		makeLine(""),
		makeLine("Template-based generation is deprecated and will be removed"),
		makeLine(
			fmt.Sprintf("in %s. Please migrate to programmatic generation for:", constants.TemplateRemovalVersion),
		),
		makeLine(""),
		makeLine("• 74% faster report generation (643 vs 170 reports/sec)"),
		makeLine("• 78% less memory usage"),
		makeLine("• Type safety with compile-time checks"),
		makeLine("• Better IDE support and maintainability"),
		makeLine(""),
		makeLine("Migration guide:"),
		makeLine(constants.MigrationGuideURL),
		makeLine(""),
		makeLine("To suppress this warning, use --quiet flag"),
		makeBorder("╚", "╝"),
	}

	return strings.Join(lines, "\n")
}

func shouldShowTemplateDeprecationWarning(opts Options) bool {
	if !constants.DeprecationWarningEnabled {
		return false
	}
	if opts.SuppressWarnings {
		return false
	}

	// Only warn when template mode is actually relevant (markdown output).
	// Empty format means "default" which is markdown in DefaultOptions().
	if opts.Format != "" && opts.Format != FormatMarkdown {
		return false
	}

	// Only warn when template mode is explicitly being used.
	// Template mode is indicated by any of:
	// 1. UseTemplateEngine is true (explicit template mode selection)
	// 2. A custom template is provided
	// 3. A template name is specified
	// 4. A template directory is specified
	if !opts.UseTemplateEngine && opts.Template == nil && opts.TemplateName == "" && opts.TemplateDir == "" {
		return false
	}

	return true
}

// showTemplateDeprecationWarning displays a deprecation warning for template mode.
// This function is called during generator initialization when template mode is detected.
// The warning is suppressed if SuppressWarnings is true or DeprecationWarningEnabled is false.
func showTemplateDeprecationWarning(logger *log.Logger, opts Options) {
	if !shouldShowTemplateDeprecationWarning(opts) {
		return
	}
	if logger == nil {
		// Best-effort: if we can't create a logger, fall back to stderr.
		var err error
		logger, err = log.New(log.Config{})
		if err != nil {
			// Last resort: write directly to stderr since we have no logger
			// Report the logger creation failure before attempting to show the warning
			templateDeprecationWarningOnce.Do(func() {
				// Attempt to write both the logger failure and the warning
				if _, writeErr := fmt.Fprintf(
					os.Stderr,
					"WARNING: Failed to create logger for deprecation warning: %v\n\n",
					err,
				); writeErr != nil {
					// Truly catastrophic - can't create logger AND can't write to stderr
					// This should be extremely rare (stderr closed/redirected to invalid target)
					panic(
						fmt.Sprintf(
							"FATAL: Cannot display deprecation warning (logger creation failed: %v, stderr write failed: %v)",
							err,
							writeErr,
						),
					)
				}
				// Now attempt to write the actual warning box
				if _, writeErr := fmt.Fprintln(os.Stderr, formatTemplateDeprecationWarningBox()); writeErr != nil {
					// If we got here, we at least warned about logger failure
					fmt.Fprintf(os.Stderr, "ERROR: Failed to write deprecation warning box to stderr: %v\n", writeErr)
				}
			})
			return
		}
	}

	templateDeprecationWarningOnce.Do(func() {
		logger.Warn(formatTemplateDeprecationWarningBox())
	})
}
