package converter

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
	deprecationWarningBoxPadding      = 4
	deprecationWarningBorderPadding   = 2
	deprecationWarningCenterDivisor   = 2
	deprecationWarningURLPadding      = 6
	deprecationWarningMinContentWidth = 66
)

func formatTemplateDeprecationWarningBox() string {
	minContentWidth := len(constants.MigrationGuideURL) + deprecationWarningURLPadding
	boxWidth := maxInt(minContentWidth, deprecationWarningMinContentWidth)
	contentWidth := boxWidth - deprecationWarningBoxPadding

	makeLine := func(content string) string {
		padding := maxInt(0, contentWidth-len(content))
		return fmt.Sprintf("║  %s%s  ║", content, strings.Repeat(" ", padding))
	}

	makeBorder := func(left, right string) string {
		return left + strings.Repeat("═", boxWidth-deprecationWarningBorderPadding) + right
	}

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

	if opts.Format != "" && opts.Format != FormatMarkdown {
		return false
	}

	if !opts.UseTemplateEngine && opts.Template == nil && opts.TemplateName == "" && opts.TemplateDir == "" {
		return false
	}

	return true
}

// showTemplateDeprecationWarning displays a deprecation warning for template mode.
func showTemplateDeprecationWarning(logger *log.Logger, opts Options) {
	if !shouldShowTemplateDeprecationWarning(opts) {
		return
	}
	if logger == nil {
		var err error
		logger, err = log.New(log.Config{})
		if err != nil {
			templateDeprecationWarningOnce.Do(func() {
				fmt.Fprintf(os.Stderr, "WARNING: Failed to create logger for deprecation warning: %v\n\n", err)
				fmt.Fprintln(os.Stderr, formatTemplateDeprecationWarningBox())
			})
			return
		}
	}

	templateDeprecationWarningOnce.Do(func() {
		logger.Warn(formatTemplateDeprecationWarningBox())
	})
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
