// Package cmd provides the command-line interface for opnDossier.
package cmd

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/EvilBit-Labs/opnDossier/internal/analysis"
	"github.com/EvilBit-Labs/opnDossier/internal/audit"
	"github.com/EvilBit-Labs/opnDossier/internal/compliance"
	"github.com/EvilBit-Labs/opnDossier/internal/converter"
	"github.com/EvilBit-Labs/opnDossier/internal/logging"
	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
)

// handleAuditMode generates a report with audit findings.
// It runs compliance checks, maps results onto a shallow copy of the device's
// ComplianceChecks field, and delegates report generation to
// generateWithProgrammaticGenerator. The input device is not mutated.
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
		Comprehensive:   opt.Comprehensive,
		SelectedPlugins: auditOpts.SelectedPlugins,
	}

	pm := audit.NewPluginManager(logger)

	// Configure dynamic plugin directory before initialization so that
	// LoadDynamicPlugins actually executes when the user provides a path.
	if auditOpts.PluginDir != "" {
		pm.SetPluginDir(auditOpts.PluginDir, auditOpts.ExplicitPluginDir)
	}

	if err := pm.InitializePlugins(ctx); err != nil {
		return "", fmt.Errorf("initialize plugins: %w", err)
	}

	// Surface any dynamic plugin load failures to the CLI user.
	if loadResult := pm.GetLoadResult(); loadResult.Failed() > 0 {
		failedNames := make([]string, len(loadResult.Failures))
		for i, f := range loadResult.Failures {
			failedNames[i] = f.Name
		}

		logger.Warn("Some dynamic plugins failed to load",
			"failed", loadResult.Failed(),
			"loaded", loadResult.Loaded,
			"files", strings.Join(failedNames, ", "),
		)
	}

	// Create mode controller and generate audit report
	mc := audit.NewModeController(pm.GetRegistry(), logger)
	auditReport, err := mc.GenerateReport(ctx, device, modeConfig)
	if err != nil {
		return "", fmt.Errorf("generate audit report: %w", err)
	}

	// Create a shallow copy so the caller's device is not mutated.
	enrichedDevice := *device
	enrichedDevice.ComplianceChecks = mapAuditReportToComplianceResults(auditReport)

	// Delegate to the standard generator pipeline (handles markdown, JSON, YAML, etc.)
	return generateWithProgrammaticGenerator(ctx, &enrichedDevice, opt, logger)
}

// mapAuditReportToComplianceResults converts an audit.Report into a common.ComplianceResults
// for embedding in CommonDevice. This enables all output formats (markdown, JSON, YAML)
// to include compliance data through the standard export pipeline.
func mapAuditReportToComplianceResults(report *audit.Report) *common.ComplianceResults {
	if report == nil {
		return nil
	}

	result := &common.ComplianceResults{
		Mode:          string(report.Mode),
		PluginResults: make(map[string]common.PluginComplianceResult, len(report.Compliance)),
		Metadata:      maps.Clone(report.Metadata),
	}

	// Map top-level findings (security analysis findings)
	result.Findings = mapAuditFindings(report.Findings)

	// Map per-plugin compliance results (deterministic iteration order)
	var totalFindings, totalCritical, totalHigh, totalMedium, totalLow, totalInfo int
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

	// Add direct findings to total count and severity tallies
	totalFindings += len(report.Findings)

	for _, f := range report.Findings {
		switch strings.ToLower(f.Severity) {
		case "critical":
			totalCritical++
		case "high":
			totalHigh++
		case "medium":
			totalMedium++
		case "low":
			totalLow++
		case "info":
			totalInfo++
		}
	}

	// Compute aggregate summary
	result.Summary = &common.ComplianceResultSummary{
		TotalFindings:    totalFindings,
		CriticalFindings: totalCritical,
		HighFindings:     totalHigh,
		MediumFindings:   totalMedium,
		LowFindings:      totalLow,
		InfoFindings:     totalInfo,
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
		Reference:      f.Reference,
		Tags:           slices.Clone(f.Tags),
		Metadata:       maps.Clone(f.Metadata),
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
		mapped[i].ExploitNotes = f.ExploitNotes
		mapped[i].Control = f.Control

		if f.AttackSurface != nil {
			mapped[i].AttackSurface = &common.ComplianceAttackSurface{
				Type:            f.AttackSurface.Type,
				Ports:           slices.Clone(f.AttackSurface.Ports),
				Services:        slices.Clone(f.AttackSurface.Services),
				Vulnerabilities: slices.Clone(f.AttackSurface.Vulnerabilities),
			}
		}
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

	// Map findings from cr.Findings (the per-plugin subset).
	// cr.PluginFindings is intentionally not mapped here because GenerateReport
	// constructs per-plugin ComplianceResult instances where cr.Findings already
	// contains the plugin-specific findings.
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
