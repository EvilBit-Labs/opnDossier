// Package audit provides security audit functionality for OPNsense configurations
// against industry-standard compliance frameworks through a plugin-based architecture.
package audit

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/EvilBit-Labs/opnDossier/internal/analysis"
	"github.com/EvilBit-Labs/opnDossier/internal/compliance"
	"github.com/EvilBit-Labs/opnDossier/internal/logging"
	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
)

// Static errors for better error handling.
var (
	// ErrModeConfigNil is returned when the mode configuration is nil.
	ErrModeConfigNil = errors.New("mode config cannot be nil")
	// ErrUnsupportedMode is returned when an unsupported report mode is specified.
	ErrUnsupportedMode = errors.New("unsupported report mode")
	// ErrPluginNotFound is returned when a requested compliance plugin cannot be found.
	// This is an alias for compliance.ErrPluginNotFound to ensure a single sentinel
	// identity across both packages, so errors.Is checks match regardless of origin.
	ErrPluginNotFound = compliance.ErrPluginNotFound
	// ErrConfigurationNil is returned when the OPNsense configuration is nil.
	ErrConfigurationNil = errors.New("configuration cannot be nil")
	// ErrDuplicatePlugin is returned when the same plugin appears more than once in the selection.
	ErrDuplicatePlugin = errors.New("duplicate plugin in selection")
)

// ReportMode represents the different types of audit reports that can be generated.
type ReportMode string

// Report mode constants that determine the perspective and focus of audit output.
const (
	// ModeBlue represents a defensive audit report with security findings and recommendations.
	ModeBlue ReportMode = "blue"
	// ModeRed represents an attacker-focused recon report highlighting attack surfaces.
	ModeRed ReportMode = "red"
)

// complianceCheckStatusCompleted is the metadata value indicating compliance checks ran successfully.
const complianceCheckStatusCompleted = "completed"

// ModeController manages the generation of different types of audit reports
// based on the selected mode and configuration.
type ModeController struct {
	registry *PluginRegistry
	logger   *logging.Logger
}

// NewModeController creates a new mode controller with the given plugin registry and logger.
func NewModeController(registry *PluginRegistry, logger *logging.Logger) *ModeController {
	return &ModeController{
		registry: registry,
		logger:   logger,
	}
}

// ModeConfig holds configuration options for report generation.
type ModeConfig struct {
	Mode            ReportMode
	Comprehensive   bool
	SelectedPlugins []string
	TemplateDir     string
}

// ValidateModeConfig validates the mode configuration.
//
// Mode-name validation delegates to ParseReportMode (the SSOT for valid mode
// names) so only one switch exists over the ReportMode enum.
func (mc *ModeController) ValidateModeConfig(config *ModeConfig) error {
	if config == nil {
		return ErrModeConfigNil
	}

	if _, err := ParseReportMode(string(config.Mode)); err != nil {
		return err
	}

	// Normalize plugin names to lowercase for case-insensitive matching,
	// then validate against the registry. A new slice is built to avoid
	// mutating the caller's input.
	if len(config.SelectedPlugins) > 0 {
		availablePlugins := mc.registry.ListPlugins()
		seen := make(map[string]struct{}, len(config.SelectedPlugins))
		normalized := make([]string, 0, len(config.SelectedPlugins))

		for _, pluginName := range config.SelectedPlugins {
			lower := strings.ToLower(pluginName)

			if _, duplicate := seen[lower]; duplicate {
				return fmt.Errorf("%w: %s", ErrDuplicatePlugin, lower)
			}

			seen[lower] = struct{}{}

			if !slices.Contains(availablePlugins, lower) {
				return fmt.Errorf(
					"%w: %q; available plugins: %s",
					ErrPluginNotFound,
					lower,
					strings.Join(availablePlugins, ", "),
				)
			}

			normalized = append(normalized, lower)
		}

		config.SelectedPlugins = normalized
	}

	return nil
}

// GenerateReport generates an audit report based on the specified mode and configuration.
func (mc *ModeController) GenerateReport(
	ctx context.Context,
	device *common.CommonDevice,
	config *ModeConfig,
) (*Report, error) {
	if err := mc.ValidateModeConfig(config); err != nil {
		return nil, fmt.Errorf("invalid mode config: %w", err)
	}

	if device == nil {
		return nil, ErrConfigurationNil
	}

	mc.logger.Info("Generating audit report", "mode", config.Mode, "comprehensive", config.Comprehensive)

	// Create base report structure
	report := &Report{
		Mode:          config.Mode,
		Comprehensive: config.Comprehensive,
		Configuration: device,
		Findings:      make([]Finding, 0),
		Compliance:    make(map[string]ComplianceResult),
		Metadata:      make(map[string]any),
	}

	// Generate mode-specific content
	switch config.Mode {
	case ModeBlue:
		return mc.generateBlueReport(ctx, report, config)
	case ModeRed:
		return mc.generateRedReport(ctx, report, config)
	default:
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedMode, config.Mode)
	}
}

// generateBlueReport generates a defensive audit report with security findings and recommendations.
func (mc *ModeController) generateBlueReport(_ context.Context, report *Report, config *ModeConfig) (*Report, error) {
	mc.logger.Debug("Generating blue team report")

	// Add blue team specific metadata
	report.Metadata["report_type"] = "blue_team"
	report.Metadata["generation_time"] = time.Now().Format(time.RFC3339)

	// Resolve the plugin set: when no plugins are explicitly selected, run all
	// available plugins. This matches the documented behavior where bare
	// `--mode blue` executes a full compliance audit.
	pluginsToRun := config.SelectedPlugins
	if len(pluginsToRun) == 0 {
		pluginsToRun = mc.registry.ListPlugins()
		mc.logger.Debug("No plugins specified, running all available plugins", "plugins", pluginsToRun)
	}

	// Run compliance checks with the resolved plugin set
	if len(pluginsToRun) > 0 {
		complianceResult, err := mc.registry.RunComplianceChecks(
			report.Configuration,
			pluginsToRun,
			mc.logger,
		)
		if err != nil {
			mc.logger.Error("Failed to run compliance checks", "error", err)

			return nil, fmt.Errorf("compliance checks failed: %w", err)
		}

		// Store per-plugin compliance results (not aggregated) so that
		// appendAuditFindings can iterate by plugin name.
		for pluginName, info := range complianceResult.PluginInfo {
			pluginFindings := complianceResult.PluginFindings[pluginName]
			pluginComplianceMap := complianceResult.Compliance[pluginName]

			// Warn if plugin produced findings with unrecognized severity values.
			if counts := countSeverities(pluginFindings); counts.unknown > 0 {
				mc.logger.Warn(
					"Plugin produced findings with unrecognized severity",
					"plugin", pluginName,
					"unknownCount", counts.unknown,
				)
			}

			pluginSummary := computePerPluginSummary(pluginName, pluginFindings, pluginComplianceMap)

			report.Compliance[pluginName] = ComplianceResult{
				Findings:       pluginFindings,
				PluginFindings: map[string][]compliance.Finding{pluginName: pluginFindings},
				Compliance:     map[string]map[string]bool{pluginName: pluginComplianceMap},
				Summary:        pluginSummary,
				PluginInfo:     map[string]PluginInfo{pluginName: info},
			}
		}
		// Add metadata to report indicating successful compliance checks
		report.Metadata["compliance_check_status"] = complianceCheckStatusCompleted
		report.Metadata["compliance_check_time"] = time.Now().Format(time.RFC3339)
	}

	// Run the shared detection engine once (KTD1-KTD3) and render its
	// observations as blue hygiene findings, de-duplicated against the
	// compliance findings just aggregated above.
	observations := analysis.ScanObservations(report.Configuration)

	report.addSecurityFindings(observations)
	report.addComplianceAnalysis()
	report.addRecommendations()
	report.addStructuredConfigurationTables()

	return report, nil
}

// generateRedReport generates an attacker-focused recon report highlighting attack surfaces.
func (mc *ModeController) generateRedReport(_ context.Context, report *Report, _ *ModeConfig) (*Report, error) {
	mc.logger.Debug("Generating red team report")

	// Add red team specific metadata
	report.Metadata["report_type"] = "red_team"
	report.Metadata["generation_time"] = time.Now().Format(time.RFC3339)

	// Add red team specific analysis
	report.addWANExposedServices()
	report.addWeakNATRules()
	report.addAdminPortals()
	report.addAttackSurfaces()
	report.addEnumerationData()

	return report, nil
}

// Report represents a comprehensive audit report with findings and analysis.
type Report struct {
	Mode          ReportMode                  `json:"mode"`
	Comprehensive bool                        `json:"comprehensive"`
	Configuration *common.CommonDevice        `json:"configuration"`
	Findings      []Finding                   `json:"findings"`
	Compliance    map[string]ComplianceResult `json:"compliance"`
	Metadata      map[string]any              `json:"metadata"`
}

// Finding represents a security finding or audit result.
// It embeds analysis.Finding for the common fields (Title, Severity, Description,
// Recommendation, Component, Tags, etc.) and adds audit-specific extensions.
type Finding struct {
	analysis.Finding

	AttackSurface *AttackSurface `json:"attackSurface,omitempty"`
	ExploitNotes  string         `json:"exploitNotes,omitempty"`
	Control       string         `json:"control,omitempty"`
}

// AttackSurface represents attack surface information for red team findings.
type AttackSurface struct {
	Type            string   `json:"type"`
	Ports           []int    `json:"ports"`
	Services        []string `json:"services"`
	Vulnerabilities []string `json:"vulnerabilities"`
}

// TotalFindingsCount returns the aggregate number of findings across both
// direct security findings (report.Findings) and per-plugin compliance
// findings (report.Compliance[*].Summary.TotalFindings). This ensures
// the top-level summary reflects the same totals as the per-plugin sections.
func (r *Report) TotalFindingsCount() int {
	total := len(r.Findings)
	for _, cr := range r.Compliance {
		if cr.Summary != nil {
			total += cr.Summary.TotalFindings
		}
	}
	return total
}

// Rank constants for the R12 severity/reachability ordering below. Lower
// values sort first (most urgent / most exposed leads).
const (
	rankCritical = iota
	rankHigh
	rankMedium
	rankLow
	rankInfo
)

const (
	rankWANReachable = iota
	rankLANOnly
	rankLocal
)

// severityOrder ranks analysis.Severity from most to least urgent for R12
// ordering (blue leads with the most severe findings).
var severityOrder = map[analysis.Severity]int{
	analysis.SeverityCritical: rankCritical,
	analysis.SeverityHigh:     rankHigh,
	analysis.SeverityMedium:   rankMedium,
	analysis.SeverityLow:      rankLow,
	analysis.SeverityInfo:     rankInfo,
}

// reachabilityOrder ranks analysis.Reachability from most to least exposed
// for R12 ordering (blue leads with the most exposed findings within a
// severity tier).
var reachabilityOrder = map[analysis.Reachability]int{
	analysis.WANReachable: rankWANReachable,
	analysis.LANOnly:      rankLANOnly,
	analysis.Local:        rankLocal,
}

// dedupeAgainstPluginFindings implements the R9/KTD4 de-dupe: a hygiene
// observation is suppressed only when it references the same originating
// config element (an exact Component string match) as a finding a fired
// compliance plugin already emitted — never merely a shared category. This
// deliberately uses `never merely a shared category` as the failure-safe
// direction: with today's coarse-grained plugin Component values (e.g.
// "firewall-rules"), few observations will match, but that under-matching
// is the safe direction for a security tool — it never hides a finding that
// should be shown.
func (r *Report) dedupeAgainstPluginFindings(observations []analysis.Observation) []analysis.Observation {
	fired := make(map[string]struct{})

	for _, cr := range r.Compliance {
		for _, f := range cr.Findings {
			if f.Component != "" {
				fired[f.Component] = struct{}{}
			}
		}
	}

	var deduped []analysis.Observation

	for _, obs := range observations {
		if _, matched := fired[obs.Component]; matched {
			continue
		}

		deduped = append(deduped, obs)
	}

	return deduped
}

// addSecurityFindings renders the shared engine's observations as blue
// hygiene findings appended to report.Findings (R7, R8), de-duplicated
// against fired plugin controls (R9) and ordered by severity then
// reachability (R12).
func (r *Report) addSecurityFindings(observations []analysis.Observation) {
	hygiene := r.dedupeAgainstPluginFindings(observations)

	slices.SortStableFunc(hygiene, func(a, b analysis.Observation) int {
		if sevDiff := severityOrder[a.Severity] - severityOrder[b.Severity]; sevDiff != 0 {
			return sevDiff
		}

		return reachabilityOrder[a.Reachability] - reachabilityOrder[b.Reachability]
	})

	findings := make([]Finding, 0, len(hygiene))
	for _, obs := range hygiene {
		findings = append(findings, Finding{Finding: obs.ToFinding()})
	}

	r.Findings = append(r.Findings, findings...)

	r.Metadata["security_scan_completed"] = true
	r.Metadata["security_findings_count"] = r.TotalFindingsCount()
}

// addComplianceAnalysis derives the compliance-frameworks list from the
// plugins actually executed (keys of report.Compliance, populated by
// generateBlueReport), replacing the hardcoded three-framework list (R10).
func (r *Report) addComplianceAnalysis() {
	frameworks := make([]string, 0, len(r.Compliance))
	for name := range r.Compliance {
		frameworks = append(frameworks, strings.ToUpper(name))
	}

	slices.Sort(frameworks)

	// Report completion honestly: with an empty Compliance map no compliance
	// plugin actually executed, so the check is not "completed".
	r.Metadata["compliance_check_completed"] = len(r.Compliance) > 0
	r.Metadata["compliance_frameworks"] = frameworks
}

// Recommendation groups the recommendation text synthesized for a single
// configuration component across hygiene findings and compliance-plugin
// findings (R11).
type Recommendation struct {
	// Component identifies the configuration component the recommendations apply to.
	Component string `json:"component"`
	// Recommendations lists the distinct recommendation strings for this component.
	Recommendations []string `json:"recommendations"`
}

// addRecommendations synthesizes recommendations from the union of blue
// hygiene findings (report.Findings) and compliance-plugin findings
// (report.Compliance[*].Findings), grouped by Component, with a count
// reflecting the real number of distinct recommendations (R11).
func (r *Report) addRecommendations() {
	grouped := make(map[string][]string)
	order := make([]string, 0)

	record := func(component, recommendation string) {
		if recommendation == "" {
			return
		}

		if _, exists := grouped[component]; !exists {
			order = append(order, component)
		}

		if slices.Contains(grouped[component], recommendation) {
			return
		}

		grouped[component] = append(grouped[component], recommendation)
	}

	for _, f := range r.Findings {
		record(f.Component, f.Recommendation)
	}

	for _, cr := range r.Compliance {
		for _, f := range cr.Findings {
			record(f.Component, f.Recommendation)
		}
	}

	slices.Sort(order)

	recommendations := make([]Recommendation, 0, len(order))
	count := 0

	for _, component := range order {
		recs := grouped[component]
		// Sort within each component: recs accumulate from r.Compliance, whose
		// map iteration order is non-deterministic, so unsorted output would
		// vary run to run (§3.1 map-iteration determinism).
		slices.Sort(recs)
		recommendations = append(recommendations, Recommendation{Component: component, Recommendations: recs})
		count += len(recs)
	}

	r.Metadata["recommendations_generated"] = true
	r.Metadata["recommendation_count"] = count
	r.Metadata["recommendations"] = recommendations
}

// ConfigSummary captures per-category configuration-element counts from the
// normalized configuration using explicit named fields rather than
// category/count rows (R13). This keeps the structured-config surface typed
// (AGENTS.md: prefer structured config data over flat summary tables); any
// future audit overlays belong in their own metadata keys rather than being
// encoded as additional summary rows.
type ConfigSummary struct {
	// Interfaces is the number of configured interfaces.
	Interfaces int `json:"interfaces"`
	// FirewallRules is the number of configured firewall rules.
	FirewallRules int `json:"firewallRules"`
	// NATRules is the combined number of inbound and outbound NAT rules.
	NATRules int `json:"natRules"`
	// Users is the number of configured user accounts.
	Users int `json:"users"`
}

// addStructuredConfigurationTables builds the configuration summary from
// actual configuration counts (interfaces, firewall rules, NAT rules,
// users), replacing the hardcoded table count (R13).
func (r *Report) addStructuredConfigurationTables() {
	var summary ConfigSummary

	if cfg := r.Configuration; cfg != nil {
		summary = ConfigSummary{
			Interfaces:    len(cfg.Interfaces),
			FirewallRules: len(cfg.FirewallRules),
			NATRules:      len(cfg.NAT.InboundRules) + len(cfg.NAT.OutboundRules),
			Users:         len(cfg.Users),
		}
	}

	r.Metadata["structured_tables_generated"] = true
	r.Metadata["configuration_summary"] = summary
}

// stubMarker returns the canonical "not yet implemented" metadata value for
// red-mode stub analysis methods. Emitting an explicit marker (rather than
// fabricated non-zero counters) guarantees consumers cannot confuse stub
// output for real analysis. See GOTCHAS §8.4.
func stubMarker() map[string]any {
	return map[string]any{
		"not_implemented": true,
		"stub":            true,
	}
}

// addWANExposedServices adds WAN-exposed services analysis to the red team report.
//
// STUB: not yet implemented; emits only the stub marker. See GOTCHAS §8.4.
func (r *Report) addWANExposedServices() {
	r.Metadata["wan_exposed_services"] = stubMarker()
}

// addWeakNATRules adds weak NAT rules analysis to the red team report.
//
// STUB: not yet implemented; emits only the stub marker. See GOTCHAS §8.4.
func (r *Report) addWeakNATRules() {
	r.Metadata["weak_nat_rules"] = stubMarker()
}

// addAdminPortals adds admin portals analysis to the red team report.
//
// STUB: not yet implemented; emits only the stub marker. See GOTCHAS §8.4.
func (r *Report) addAdminPortals() {
	r.Metadata["admin_portals"] = stubMarker()
}

// addAttackSurfaces adds attack surfaces analysis to the red team report.
//
// STUB: not yet implemented; emits only the stub marker. See GOTCHAS §8.4.
func (r *Report) addAttackSurfaces() {
	r.Metadata["attack_surfaces"] = stubMarker()
}

// addEnumerationData adds enumeration data to the red team report.
//
// STUB: not yet implemented; emits only the stub marker. See GOTCHAS §8.4.
func (r *Report) addEnumerationData() {
	r.Metadata["enumeration_data"] = stubMarker()
}

// ParseReportMode parses a string into a ReportMode, returning an error if invalid.
//
// This is the single source of truth (SSOT) for valid ReportMode names. All
// mode-name validation elsewhere in the package (including
// ModeController.ValidateModeConfig) must delegate here so new modes only need
// to be added in this switch.
func ParseReportMode(s string) (ReportMode, error) {
	mode := ReportMode(strings.ToLower(s))
	switch mode {
	case ModeBlue, ModeRed:
		return mode, nil
	default:
		return "", fmt.Errorf("%w: %s", ErrUnsupportedMode, s)
	}
}

// String returns the string representation of the ReportMode.
func (rm ReportMode) String() string {
	return string(rm)
}
