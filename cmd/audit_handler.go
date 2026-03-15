// Package cmd provides the command-line interface for opnDossier.
package cmd

import (
	"context"
	"fmt"
	"maps"
	"slices"

	"github.com/EvilBit-Labs/opnDossier/internal/analysis"
	"github.com/EvilBit-Labs/opnDossier/internal/audit"
	"github.com/EvilBit-Labs/opnDossier/internal/compliance"
	"github.com/EvilBit-Labs/opnDossier/internal/converter"
	"github.com/EvilBit-Labs/opnDossier/internal/logging"
	"github.com/EvilBit-Labs/opnDossier/internal/model/common"
)

// handleAuditMode generates a report with audit findings.
// It runs compliance checks, maps results onto the device's ComplianceChecks field,
// and delegates report generation to generateWithProgrammaticGenerator.
func handleAuditMode(
	ctx context.Context,
	device *common.CommonDevice,
	auditOpts audit.Options,
	opt converter.Options,
	logger *logging.Logger,
) (string, error) {
	// Parse audit mode
	mode, err := audit.ParseReportMode(auditOpts.AuditMode)
	if err != nil {
		return "", fmt.Errorf("invalid audit mode: %w", err)
	}

	// Create mode config
	modeConfig := &audit.ModeConfig{
		Mode:            mode,
		BlackhatMode:    auditOpts.BlackhatMode,
		Comprehensive:   opt.Comprehensive,
		SelectedPlugins: auditOpts.SelectedPlugins,
	}

	pm := audit.NewPluginManager(logger)
	if err := pm.InitializePlugins(ctx); err != nil {
		return "", fmt.Errorf("initialize plugins: %w", err)
	}

	// Create mode controller and generate audit report
	mc := audit.NewModeController(pm.GetRegistry(), logger)
	auditReport, err := mc.GenerateReport(ctx, device, modeConfig)
	if err != nil {
		return "", fmt.Errorf("generate audit report: %w", err)
	}

	// Map audit results onto the device's ComplianceChecks field
	device.ComplianceChecks = mapAuditReportToComplianceResults(auditReport)

	// Delegate to the standard generator pipeline (handles markdown, JSON, YAML, etc.)
	return generateWithProgrammaticGenerator(ctx, device, opt, logger)
}

// mapAuditReportToComplianceResults converts an audit.Report into a common.ComplianceResults
// for embedding in CommonDevice. This enables all output formats (markdown, JSON, YAML)
// to include compliance data through the standard export pipeline.
func mapAuditReportToComplianceResults(report *audit.Report) *common.ComplianceResults {
	result := &common.ComplianceResults{
		Mode:          string(report.Mode),
		PluginResults: make(map[string]common.PluginComplianceResult, len(report.Compliance)),
		Metadata:      maps.Clone(report.Metadata),
	}

	// Map top-level findings (security analysis findings)
	result.Findings = mapAuditFindings(report.Findings)

	// Map per-plugin compliance results (deterministic iteration order)
	var totalFindings, totalCritical, totalHigh, totalMedium, totalLow int
	var totalCompliant, totalNonCompliant int

	for _, pluginName := range slices.Sorted(maps.Keys(report.Compliance)) {
		cr := report.Compliance[pluginName]
		pluginResult := mapPluginComplianceResult(pluginName, &cr)
		result.PluginResults[pluginName] = pluginResult

		if pluginResult.Summary != nil {
			totalFindings += pluginResult.Summary.TotalFindings
			totalCritical += pluginResult.Summary.CriticalFindings
			totalHigh += pluginResult.Summary.HighFindings
			totalMedium += pluginResult.Summary.MediumFindings
			totalLow += pluginResult.Summary.LowFindings
			totalCompliant += pluginResult.Summary.Compliant
			totalNonCompliant += pluginResult.Summary.NonCompliant
		}
	}

	// Add direct findings to total count
	totalFindings += len(report.Findings)

	// Compute aggregate summary
	result.Summary = &common.ComplianceResultSummary{
		TotalFindings:    totalFindings,
		CriticalFindings: totalCritical,
		HighFindings:     totalHigh,
		MediumFindings:   totalMedium,
		LowFindings:      totalLow,
		PluginCount:      len(report.Compliance),
		Compliant:        totalCompliant,
		NonCompliant:     totalNonCompliant,
	}

	return result
}

// mapAnalysisFinding converts a single analysis.Finding to a common.ComplianceFinding.
// This shared helper is used by both mapAuditFindings and mapComplianceFindings,
// since audit.Finding embeds analysis.Finding and compliance.Finding is a type alias for it.
func mapAnalysisFinding(f analysis.Finding) common.ComplianceFinding {
	return common.ComplianceFinding{
		Type:           f.Type,
		Severity:       f.Severity,
		Title:          f.Title,
		Description:    f.Description,
		Recommendation: f.Recommendation,
		Component:      f.Component,
		References:     slices.Clone(f.References),
	}
}

// mapAuditFindings converts audit.Finding slices to common.ComplianceFinding slices.
func mapAuditFindings(findings []audit.Finding) []common.ComplianceFinding {
	if len(findings) == 0 {
		return nil
	}

	mapped := make([]common.ComplianceFinding, len(findings))
	for i, f := range findings {
		mapped[i] = mapAnalysisFinding(f.Finding)
	}

	return mapped
}

// mapPluginComplianceResult converts an audit.ComplianceResult into a common.PluginComplianceResult.
func mapPluginComplianceResult(pluginName string, cr *audit.ComplianceResult) common.PluginComplianceResult {
	pluginResult := common.PluginComplianceResult{}

	// Map plugin info
	if info, exists := cr.PluginInfo[pluginName]; exists {
		pluginResult.PluginInfo = common.CompliancePluginInfo{
			Name:        info.Name,
			Version:     info.Version,
			Description: info.Description,
		}
		// Map controls from plugin info
		pluginResult.Controls = mapControls(info.Controls)
	}

	// Map findings
	pluginResult.Findings = mapComplianceFindings(cr.Findings)

	// Map summary
	if cr.Summary != nil {
		pluginResult.Summary = &common.ComplianceResultSummary{
			TotalFindings:    cr.Summary.TotalFindings,
			CriticalFindings: cr.Summary.CriticalFindings,
			HighFindings:     cr.Summary.HighFindings,
			MediumFindings:   cr.Summary.MediumFindings,
			LowFindings:      cr.Summary.LowFindings,
			PluginCount:      cr.Summary.PluginCount,
		}

		// Map compliance stats from plugin-level compliance data
		if pc, exists := cr.Summary.Compliance[pluginName]; exists {
			pluginResult.Summary.Compliant = pc.Compliant
			pluginResult.Summary.NonCompliant = pc.NonCompliant
		}
	}

	// Map per-control compliance status (clone to avoid shared reference)
	if controlCompliance, exists := cr.Compliance[pluginName]; exists {
		pluginResult.Compliance = maps.Clone(controlCompliance)
	}

	return pluginResult
}

// mapComplianceFindings converts compliance.Finding (analysis.Finding) slices
// to common.ComplianceFinding slices.
func mapComplianceFindings(findings []compliance.Finding) []common.ComplianceFinding {
	if len(findings) == 0 {
		return nil
	}

	mapped := make([]common.ComplianceFinding, len(findings))
	for i, f := range findings {
		mapped[i] = mapAnalysisFinding(f)
	}

	return mapped
}

// mapControls converts compliance.Control slices to common.ComplianceControl slices.
func mapControls(controls []compliance.Control) []common.ComplianceControl {
	if len(controls) == 0 {
		return nil
	}

	mapped := make([]common.ComplianceControl, len(controls))
	for i, c := range controls {
		mapped[i] = common.ComplianceControl{
			ID:          c.ID,
			Title:       c.Title,
			Description: c.Description,
			Category:    c.Category,
			Severity:    c.Severity,
			Rationale:   c.Rationale,
			Remediation: c.Remediation,
			References:  slices.Clone(c.References),
			Tags:        slices.Clone(c.Tags),
			Metadata:    maps.Clone(c.Metadata),
		}
	}

	return mapped
}
