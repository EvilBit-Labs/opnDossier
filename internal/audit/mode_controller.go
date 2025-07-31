// Package audit provides security audit functionality for OPNsense configurations
// against industry-standard compliance frameworks through a plugin-based architecture.
package audit

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"time"

	"github.com/unclesp1d3r/opnFocus/internal/model"
	"github.com/unclesp1d3r/opnFocus/internal/processor"
)

// Static errors for better error handling.
var (
	ErrModeConfigNil    = errors.New("mode config cannot be nil")
	ErrUnsupportedMode  = errors.New("unsupported report mode")
	ErrPluginNotFound   = errors.New("plugin not found")
	ErrConfigurationNil = errors.New("configuration cannot be nil")
)

// ReportMode represents the different types of audit reports that can be generated.
type ReportMode string

const (
	// ModeStandard represents a neutral, comprehensive documentation report.
	ModeStandard ReportMode = "standard"
	// ModeBlue represents a defensive audit report with security findings and recommendations.
	ModeBlue ReportMode = "blue"
	// ModeRed represents an attacker-focused recon report highlighting attack surfaces.
	ModeRed ReportMode = "red"
)

// ModeController manages the generation of different types of audit reports
// based on the selected mode and configuration.
type ModeController struct {
	registry *PluginRegistry
	logger   *slog.Logger
}

// NewModeController creates a new mode controller with the given plugin registry and logger.
func NewModeController(registry *PluginRegistry, logger *slog.Logger) *ModeController {
	return &ModeController{
		registry: registry,
		logger:   logger,
	}
}

// ModeConfig holds configuration options for report generation.
type ModeConfig struct {
	Mode            ReportMode
	BlackhatMode    bool
	Comprehensive   bool
	SelectedPlugins []string
	TemplateDir     string
}

// ValidateModeConfig validates the mode configuration.
func (mc *ModeController) ValidateModeConfig(config *ModeConfig) error {
	if config == nil {
		return ErrModeConfigNil
	}

	switch config.Mode {
	case ModeStandard, ModeBlue, ModeRed:
		// Valid modes
	default:
		return fmt.Errorf("%w: %s", ErrUnsupportedMode, config.Mode)
	}

	// Validate plugin selection if specified
	if len(config.SelectedPlugins) > 0 {
		availablePlugins := mc.registry.ListPlugins()
		for _, pluginName := range config.SelectedPlugins {
			if !slices.Contains(availablePlugins, pluginName) {
				return fmt.Errorf("%w: %s", ErrPluginNotFound, pluginName)
			}
		}
	}

	return nil
}

// GenerateReport generates an audit report based on the specified mode and configuration.
func (mc *ModeController) GenerateReport(ctx context.Context, cfg *model.OpnSenseDocument, config *ModeConfig) (*Report, error) {
	if err := mc.ValidateModeConfig(config); err != nil {
		return nil, fmt.Errorf("invalid mode config: %w", err)
	}

	if cfg == nil {
		return nil, ErrConfigurationNil
	}

	mc.logger.InfoContext(ctx, "Generating audit report", "mode", config.Mode, "comprehensive", config.Comprehensive)

	// Create base report structure
	report := &Report{
		Mode:          config.Mode,
		BlackhatMode:  config.BlackhatMode,
		Comprehensive: config.Comprehensive,
		Configuration: cfg,
		Findings:      make([]Finding, 0),
		Compliance:    make(map[string]ComplianceResult),
		Metadata:      make(map[string]any),
	}

	// Generate mode-specific content
	switch config.Mode {
	case ModeStandard:
		return mc.generateStandardReport(ctx, report)
	case ModeBlue:
		return mc.generateBlueReport(ctx, report, config)
	case ModeRed:
		return mc.generateRedReport(ctx, report, config)
	default:
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedMode, config.Mode)
	}
}

// generateStandardReport generates a neutral, comprehensive documentation report.
func (mc *ModeController) generateStandardReport(ctx context.Context, report *Report) (*Report, error) {
	mc.logger.DebugContext(ctx, "Generating standard report")

	// Add system metadata
	report.Metadata["report_type"] = "standard"
	report.Metadata["generation_time"] = time.Now().Format(time.RFC3339)

	// Add basic configuration analysis
	report.addSystemMetadata()
	report.addInterfaceAnalysis()
	report.addFirewallRuleAnalysis()
	report.addNATAnalysis()
	report.addDHCPAnalysis()
	report.addCertificateAnalysis()
	report.addVPNAnalysis()
	report.addStaticRouteAnalysis()
	report.addHighAvailabilityAnalysis()

	return report, nil
}

// generateBlueReport generates a defensive audit report with security findings and recommendations.
func (mc *ModeController) generateBlueReport(ctx context.Context, report *Report, config *ModeConfig) (*Report, error) {
	mc.logger.DebugContext(ctx, "Generating blue team report")

	// Add blue team specific metadata
	report.Metadata["report_type"] = "blue_team"
	report.Metadata["generation_time"] = time.Now().Format(time.RFC3339)

	// Run compliance checks if plugins are selected
	if len(config.SelectedPlugins) > 0 {
		complianceResult, err := mc.registry.RunComplianceChecks(report.Configuration, config.SelectedPlugins)
		if err != nil {
			mc.logger.WarnContext(ctx, "Failed to run compliance checks", "error", err)
			// Add metadata to report indicating compliance check failure
			report.Metadata["compliance_check_status"] = "failed"
			report.Metadata["compliance_check_error"] = err.Error()
			report.Metadata["compliance_check_time"] = time.Now().Format(time.RFC3339)
		} else {
			report.Compliance["plugin_results"] = *complianceResult
			// Add metadata to report indicating successful compliance checks
			report.Metadata["compliance_check_status"] = "completed"
			report.Metadata["compliance_check_time"] = time.Now().Format(time.RFC3339)
		}
	}

	// Add blue team specific analysis
	report.addSecurityFindings()
	report.addComplianceAnalysis()
	report.addRecommendations()
	report.addStructuredConfigurationTables()

	return report, nil
}

// generateRedReport generates an attacker-focused recon report highlighting attack surfaces.
func (mc *ModeController) generateRedReport(ctx context.Context, report *Report, config *ModeConfig) (*Report, error) {
	mc.logger.DebugContext(ctx, "Generating red team report", "blackhat_mode", config.BlackhatMode)

	// Add red team specific metadata
	report.Metadata["report_type"] = "red_team"
	report.Metadata["blackhat_mode"] = config.BlackhatMode
	report.Metadata["generation_time"] = time.Now().Format(time.RFC3339)

	// Add red team specific analysis
	report.addWANExposedServices()
	report.addWeakNATRules()
	report.addAdminPortals()
	report.addAttackSurfaces()
	report.addEnumerationData()

	if config.BlackhatMode {
		report.addSnarkyCommentary()
	}

	return report, nil
}

// Report represents a comprehensive audit report with findings and analysis.
type Report struct {
	Mode          ReportMode                  `json:"mode"`
	BlackhatMode  bool                        `json:"blackhatMode"`
	Comprehensive bool                        `json:"comprehensive"`
	Configuration *model.OpnSenseDocument     `json:"configuration"`
	Findings      []Finding                   `json:"findings"`
	Compliance    map[string]ComplianceResult `json:"compliance"`
	Metadata      map[string]any              `json:"metadata"`
}

// Finding represents a security finding or audit result.
type Finding struct {
	Title          string             `json:"title"`
	Severity       processor.Severity `json:"severity"`
	Description    string             `json:"description"`
	Recommendation string             `json:"recommendation"`
	Tags           []string           `json:"tags"`
	AttackSurface  *AttackSurface     `json:"attackSurface,omitempty"`
	ExploitNotes   string             `json:"exploitNotes,omitempty"`
	Component      string             `json:"component"`
	Control        string             `json:"control,omitempty"`
}

// AttackSurface represents attack surface information for red team findings.
type AttackSurface struct {
	Type            string   `json:"type"`
	Ports           []int    `json:"ports"`
	Services        []string `json:"services"`
	Vulnerabilities []string `json:"vulnerabilities"`
}

// addSystemMetadata adds system metadata to the report.
func (r *Report) addSystemMetadata() {
	// TODO: Implement system metadata analysis
}

// addInterfaceAnalysis adds interface analysis to the report.
func (r *Report) addInterfaceAnalysis() {
	// TODO: Implement interface analysis
}

// addFirewallRuleAnalysis adds firewall rule analysis to the report.
func (r *Report) addFirewallRuleAnalysis() {
	// TODO: Implement firewall rule analysis
}

// addNATAnalysis adds NAT analysis to the report.
func (r *Report) addNATAnalysis() {
	// TODO: Implement NAT analysis
}

// addDHCPAnalysis adds DHCP analysis to the report.
func (r *Report) addDHCPAnalysis() {
	// TODO: Implement DHCP analysis
}

// addCertificateAnalysis adds certificate analysis to the report.
func (r *Report) addCertificateAnalysis() {
	// TODO: Implement certificate analysis
}

// addVPNAnalysis adds VPN analysis to the report.
func (r *Report) addVPNAnalysis() {
	// TODO: Implement VPN analysis
}

// addStaticRouteAnalysis adds static route analysis to the report.
func (r *Report) addStaticRouteAnalysis() {
	// TODO: Implement static route analysis
}

// addHighAvailabilityAnalysis adds high availability analysis to the report.
func (r *Report) addHighAvailabilityAnalysis() {
	// TODO: Implement high availability analysis
}

// addSecurityFindings adds security findings to the blue team report.
func (r *Report) addSecurityFindings() {
	// TODO: Implement security findings analysis
}

// addComplianceAnalysis adds compliance analysis to the blue team report.
func (r *Report) addComplianceAnalysis() {
	// TODO: Implement compliance analysis
}

// addRecommendations adds recommendations to the blue team report.
func (r *Report) addRecommendations() {
	// TODO: Implement recommendations
}

// addStructuredConfigurationTables adds structured configuration tables to the blue team report.
func (r *Report) addStructuredConfigurationTables() {
	// TODO: Implement structured configuration tables
}

// addWANExposedServices adds WAN-exposed services analysis to the red team report.
func (r *Report) addWANExposedServices() {
	// TODO: Implement WAN-exposed services analysis
}

// addWeakNATRules adds weak NAT rules analysis to the red team report.
func (r *Report) addWeakNATRules() {
	// TODO: Implement weak NAT rules analysis
}

// addAdminPortals adds admin portals analysis to the red team report.
func (r *Report) addAdminPortals() {
	// TODO: Implement admin portals analysis
}

// addAttackSurfaces adds attack surfaces analysis to the red team report.
func (r *Report) addAttackSurfaces() {
	// TODO: Implement attack surfaces analysis
}

// addEnumerationData adds enumeration data to the red team report.
func (r *Report) addEnumerationData() {
	// TODO: Implement enumeration data analysis
}

// addSnarkyCommentary adds snarky commentary to the red team report when blackhat mode is enabled.
func (r *Report) addSnarkyCommentary() {
	// TODO: Implement snarky commentary
}

// ParseReportMode parses a string into a ReportMode, returning an error if invalid.
func ParseReportMode(s string) (ReportMode, error) {
	mode := ReportMode(strings.ToLower(s))
	switch mode {
	case ModeStandard, ModeBlue, ModeRed:
		return mode, nil
	default:
		return "", fmt.Errorf("%w: %s", ErrUnsupportedMode, s)
	}
}

// String returns the string representation of the ReportMode.
func (rm ReportMode) String() string {
	return string(rm)
}
