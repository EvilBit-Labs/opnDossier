package markdown

import (
	"fmt"
	"strings"
	"sync"

	"github.com/EvilBit-Labs/opnDossier/internal/constants"
	"github.com/EvilBit-Labs/opnDossier/internal/log"
)

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

	return true
}

// showTemplateDeprecationWarning displays a deprecation warning for template mode.
// This function should be called when template-based generation is invoked.
// The warning is suppressed if SuppressWarnings is true or if the logger is in quiet mode.
func showTemplateDeprecationWarning(logger *log.Logger, opts Options) {
	if !shouldShowTemplateDeprecationWarning(opts) {
		return
	}
	if logger == nil {
		// Best-effort: if we can't create a logger, fail silent to avoid breaking generation.
		var err error
		logger, err = log.New(log.Config{})
		if err != nil {
			return
		}
	}

	templateDeprecationWarningOnce.Do(func() {
		logger.Warn(formatTemplateDeprecationWarningBox())
	})
}
