// Package cmd provides the command-line interface for opnDossier.
package cmd

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/EvilBit-Labs/opnDossier/internal/audit"
	"github.com/EvilBit-Labs/opnDossier/internal/converter"
	"github.com/EvilBit-Labs/opnDossier/internal/log"
	"github.com/EvilBit-Labs/opnDossier/internal/model"
	"github.com/EvilBit-Labs/opnDossier/internal/plugin"
	charmlog "github.com/charmbracelet/log"
)

// handleAuditMode generates a report with audit findings appended.
// It parses the audit mode, initializes the plugin system, runs compliance checks,
// and appends the audit findings to the base markdown report.
func handleAuditMode(
	ctx context.Context,
	doc *model.OpnSenseDocument,
	opt converter.Options,
	logger *log.Logger,
) (string, error) {
	// Parse audit mode
	mode, err := audit.ParseReportMode(opt.AuditMode)
	if err != nil {
		return "", fmt.Errorf("invalid audit mode: %w", err)
	}

	// Create mode config
	modeConfig := &audit.ModeConfig{
		Mode:            mode,
		BlackhatMode:    opt.BlackhatMode,
		Comprehensive:   opt.Comprehensive,
		SelectedPlugins: opt.SelectedPlugins,
	}

	// Initialize plugin manager with slog logger for PluginManager
	slogLogger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
	pm := audit.NewPluginManager(slogLogger)
	if err := pm.InitializePlugins(ctx); err != nil {
		return "", fmt.Errorf("initialize plugins: %w", err)
	}

	// Create charmbracelet/log logger for ModeController
	charmLogger := charmlog.NewWithOptions(os.Stderr, charmlog.Options{
		Level: charmlog.InfoLevel,
	})

	// Create mode controller and generate audit report
	mc := audit.NewModeController(pm.GetRegistry(), charmLogger)
	auditReport, err := mc.GenerateReport(ctx, doc, modeConfig)
	if err != nil {
		return "", fmt.Errorf("generate audit report: %w", err)
	}

	// Generate base markdown report using existing generator
	baseReport, err := generateWithProgrammaticGenerator(ctx, doc, opt, logger)
	if err != nil {
		return "", fmt.Errorf("generate base report: %w", err)
	}

	// Append audit findings section
	return appendAuditFindings(baseReport, auditReport), nil
}

// appendAuditFindings appends compliance summary and findings to the base report.
// It creates a markdown section with a summary table and detailed findings.
func appendAuditFindings(baseReport string, report *audit.Report) string {
	var sb strings.Builder
	sb.WriteString(baseReport)
	sb.WriteString("\n\n## Compliance Audit Summary\n\n")

	// Summary table
	sb.WriteString("| Metric | Value |\n")
	sb.WriteString("|--------|-------|\n")
	sb.WriteString(fmt.Sprintf("| Report Mode | %s |\n", report.Mode))
	sb.WriteString(fmt.Sprintf("| Blackhat Mode | %t |\n", report.BlackhatMode))
	sb.WriteString(fmt.Sprintf("| Comprehensive | %t |\n", report.Comprehensive))
	sb.WriteString(fmt.Sprintf("| Total Findings | %d |\n", len(report.Findings)))

	// Add compliance plugin results if available
	if len(report.Compliance) > 0 {
		sb.WriteString("\n### Plugin Compliance Results\n\n")
		for pluginName, result := range report.Compliance {
			sb.WriteString(fmt.Sprintf("#### %s\n\n", pluginName))
			sb.WriteString(fmt.Sprintf("- Summary: %d findings\n", result.Summary.TotalFindings))
			if result.Summary.CriticalFindings > 0 {
				sb.WriteString(fmt.Sprintf("- Critical: %d\n", result.Summary.CriticalFindings))
			}
			if result.Summary.HighFindings > 0 {
				sb.WriteString(fmt.Sprintf("- High: %d\n", result.Summary.HighFindings))
			}
			if result.Summary.MediumFindings > 0 {
				sb.WriteString(fmt.Sprintf("- Medium: %d\n", result.Summary.MediumFindings))
			}
			if result.Summary.LowFindings > 0 {
				sb.WriteString(fmt.Sprintf("- Low: %d\n", result.Summary.LowFindings))
			}
			sb.WriteString("\n")
		}
	}

	// Findings details if any
	if len(report.Findings) > 0 {
		sb.WriteString("\n### Security Findings\n\n")
		sb.WriteString("| Severity | Component | Title | Recommendation |\n")
		sb.WriteString("|----------|-----------|-------|----------------|\n")

		for _, f := range report.Findings {
			sb.WriteString(fmt.Sprintf("| %s | %s | %s | %s |\n",
				escapePipeForMarkdown(string(f.Severity)),
				escapePipeForMarkdown(f.Component),
				escapePipeForMarkdown(f.Title),
				escapePipeForMarkdown(f.Recommendation)))
		}
	}

	// Add plugin findings from compliance results
	for pluginName, result := range report.Compliance {
		if len(result.Findings) > 0 {
			sb.WriteString(fmt.Sprintf("\n### %s Plugin Findings\n\n", pluginName))
			sb.WriteString("| Type | Title | Description |\n")
			sb.WriteString("|------|-------|-------------|\n")

			for _, f := range result.Findings {
				sb.WriteString(fmt.Sprintf("| %s | %s | %s |\n",
					escapePipeForMarkdown(f.Type),
					escapePipeForMarkdown(f.Title),
					escapePipeForMarkdown(truncateString(f.Description, maxDescriptionLength))))
			}
		}
	}

	// Add metadata summary
	if len(report.Metadata) > 0 {
		sb.WriteString("\n### Audit Metadata\n\n")
		sb.WriteString("| Key | Value |\n")
		sb.WriteString("|-----|-------|\n")
		for key, value := range report.Metadata {
			sb.WriteString(fmt.Sprintf("| %s | %v |\n",
				escapePipeForMarkdown(key),
				value))
		}
	}

	return sb.String()
}

// formatPluginFindings formats plugin findings for display.
//

func formatPluginFindings(findings []plugin.Finding) string {
	if len(findings) == 0 {
		return "No findings"
	}

	var sb strings.Builder
	for i, f := range findings {
		if i > 0 {
			sb.WriteString("; ")
		}
		sb.WriteString(fmt.Sprintf("%s: %s", f.Type, f.Title))
	}
	return sb.String()
}

// escapePipeForMarkdown escapes pipe characters in markdown table cells.
func escapePipeForMarkdown(s string) string {
	return strings.ReplaceAll(s, "|", "\\|")
}

// Maximum description length for table cells.
const maxDescriptionLength = 80

// truncateString truncates a string to the specified maximum length.
func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}
