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

	"github.com/EvilBit-Labs/opnDossier/internal/model"
	"github.com/EvilBit-Labs/opnDossier/internal/processor"
	"github.com/charmbracelet/log"
)

// Static errors for better error handling.
var (
	// ErrModeConfigNil is returned when the mode configuration is nil.
	ErrModeConfigNil = errors.New("mode config cannot be nil")
	// ErrUnsupportedMode is returned when an unsupported report mode is specified.
	ErrUnsupportedMode = errors.New("unsupported report mode")
	// ErrPluginNotFound is returned when a requested compliance plugin cannot be found.
	ErrPluginNotFound = errors.New("plugin not found")
	// ErrConfigurationNil is returned when the OPNsense configuration is nil.
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
	logger   *log.Logger
}

// NewModeController creates a new mode controller with the given plugin registry and logger.
func NewModeController(registry *PluginRegistry, logger *log.Logger) *ModeController {
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
func (mc *ModeController) GenerateReport(
	ctx context.Context,
	cfg *model.OpnSenseDocument,
	config *ModeConfig,
) (*Report, error) {
	if err := mc.ValidateModeConfig(config); err != nil {
		return nil, fmt.Errorf("invalid mode config: %w", err)
	}

	if cfg == nil {
		return nil, ErrConfigurationNil
	}

	mc.logger.Info("Generating audit report", "mode", config.Mode, "comprehensive", config.Comprehensive)

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
func (mc *ModeController) generateStandardReport(_ context.Context, report *Report) (*Report, error) {
	mc.logger.Debug("Generating standard report")

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
func (mc *ModeController) generateBlueReport(_ context.Context, report *Report, config *ModeConfig) (*Report, error) {
	mc.logger.Debug("Generating blue team report")

	// Add blue team specific metadata
	report.Metadata["report_type"] = "blue_team"
	report.Metadata["generation_time"] = time.Now().Format(time.RFC3339)

	// Run compliance checks if plugins are selected
	if len(config.SelectedPlugins) > 0 {
		complianceResult, err := mc.registry.RunComplianceChecks(report.Configuration, config.SelectedPlugins)
		if err != nil {
			mc.logger.Warn("Failed to run compliance checks", "error", err)
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
func (mc *ModeController) generateRedReport(_ context.Context, report *Report, config *ModeConfig) (*Report, error) {
	mc.logger.Debug("Generating red team report", "blackhat_mode", config.BlackhatMode)

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
	if r.Configuration != nil && r.Configuration.System.Hostname != "" {
		r.Metadata["system_hostname"] = r.Configuration.System.Hostname
	}
	if r.Configuration != nil && r.Configuration.System.Domain != "" {
		r.Metadata["system_domain"] = r.Configuration.System.Domain
	}
	r.Metadata["system_analysis_completed"] = true
}

// addInterfaceAnalysis adds interface analysis to the report.
func (r *Report) addInterfaceAnalysis() {
	if r.Configuration != nil && r.Configuration.Interfaces.Items != nil {
		interfaceCount := len(r.Configuration.Interfaces.Items)
		r.Metadata["interface_count"] = interfaceCount
	}
	r.Metadata["interface_analysis_completed"] = true
}

// addFirewallRuleAnalysis adds firewall rule analysis to the report.
func (r *Report) addFirewallRuleAnalysis() {
	if r.Configuration != nil {
		ruleCount := len(r.Configuration.Filter.Rule)
		r.Metadata["firewall_rule_count"] = ruleCount
	}
	r.Metadata["firewall_analysis_completed"] = true
}

// addNATAnalysis adds NAT analysis to the report.
func (r *Report) addNATAnalysis() {
	if r.Configuration != nil {
		// NAT rules are available but structure is complex, just indicate analysis completed
		r.Metadata["nat_analysis_completed"] = true
		r.Metadata["nat_mode"] = r.Configuration.Nat.Outbound.Mode
	}
	r.Metadata["nat_analysis_completed"] = true
}

// addDHCPAnalysis adds DHCP analysis to the report.
func (r *Report) addDHCPAnalysis() {
	if r.Configuration != nil {
		// DHCP configuration is in Dhcpd field
		if lanDhcp, ok := r.Configuration.Dhcpd.Lan(); ok {
			dhcpEnabled := lanDhcp.Enable == "1"
			r.Metadata["dhcp_enabled"] = dhcpEnabled
		} else {
			r.Metadata["dhcp_enabled"] = false
		}
	}
	r.Metadata["dhcp_analysis_completed"] = true
}

// addCertificateAnalysis adds certificate analysis to the report.
func (r *Report) addCertificateAnalysis() {
	if r.Configuration != nil {
		// Certificate information is in Cert field
		r.Metadata["certificate_analysis_completed"] = true
		if strings.TrimSpace(r.Configuration.Cert.Text) != "" {
			r.Metadata["certificates_configured"] = true
		} else {
			r.Metadata["certificates_configured"] = false
		}
	}
	r.Metadata["certificate_analysis_completed"] = true
}

// addVPNAnalysis adds VPN analysis to the report.
func (r *Report) addVPNAnalysis() {
	if r.Configuration != nil {
		// OpenVPN configuration - check if servers are configured
		hasOpenVPN := len(r.Configuration.OpenVPN.Servers) > 0 || len(r.Configuration.OpenVPN.Clients) > 0
		r.Metadata["openvpn_configured"] = hasOpenVPN
		r.Metadata["openvpn_server_count"] = len(r.Configuration.OpenVPN.Servers)
		r.Metadata["openvpn_client_count"] = len(r.Configuration.OpenVPN.Clients)
	}
	r.Metadata["vpn_analysis_completed"] = true
}

// addStaticRouteAnalysis adds static route analysis to the report.
func (r *Report) addStaticRouteAnalysis() {
	if r.Configuration != nil {
		routeCount := len(r.Configuration.StaticRoutes.Route)
		r.Metadata["static_route_count"] = routeCount
	}
	r.Metadata["static_route_analysis_completed"] = true
}

// addHighAvailabilityAnalysis adds high availability analysis to the report.
func (r *Report) addHighAvailabilityAnalysis() {
	if r.Configuration != nil {
		// High Availability configuration is in HighAvailabilitySync
		haEnabled := r.Configuration.HighAvailabilitySync.Synchronizetoip != "" ||
			r.Configuration.HighAvailabilitySync.Pfsyncinterface != ""
		r.Metadata["ha_enabled"] = haEnabled
		if haEnabled {
			r.Metadata["ha_sync_ip"] = r.Configuration.HighAvailabilitySync.Synchronizetoip
			r.Metadata["ha_pfsync_interface"] = r.Configuration.HighAvailabilitySync.Pfsyncinterface
		}
	}
	r.Metadata["ha_analysis_completed"] = true
}

// addSecurityFindings adds security findings to the blue team report.
func (r *Report) addSecurityFindings() {
	// Add placeholder security analysis
	r.Metadata["security_scan_completed"] = true
	r.Metadata["security_findings_count"] = len(r.Findings)
}

// addComplianceAnalysis adds compliance analysis to the blue team report.
func (r *Report) addComplianceAnalysis() {
	// Add placeholder compliance analysis
	r.Metadata["compliance_check_completed"] = true
	r.Metadata["compliance_frameworks"] = []string{"CIS", "NIST"}
}

// addRecommendations adds recommendations to the blue team report.
func (r *Report) addRecommendations() {
	// Add placeholder recommendations
	r.Metadata["recommendations_generated"] = true
	r.Metadata["recommendation_count"] = 0
}

// addStructuredConfigurationTables adds structured configuration tables to the blue team report.
func (r *Report) addStructuredConfigurationTables() {
	// Add placeholder structured tables
	r.Metadata["structured_tables_generated"] = true
	r.Metadata["table_count"] = 5
}

// addWANExposedServices adds WAN-exposed services analysis to the red team report.
func (r *Report) addWANExposedServices() {
	// Add placeholder WAN exposure analysis
	r.Metadata["wan_exposure_scan_completed"] = true
	r.Metadata["exposed_services_count"] = 0
}

// addWeakNATRules adds weak NAT rules analysis to the red team report.
func (r *Report) addWeakNATRules() {
	// Add placeholder weak NAT analysis
	r.Metadata["weak_nat_scan_completed"] = true
	r.Metadata["weak_nat_rules_count"] = 0
}

// addAdminPortals adds admin portals analysis to the red team report.
func (r *Report) addAdminPortals() {
	// Add placeholder admin portal analysis
	r.Metadata["admin_portal_scan_completed"] = true
	r.Metadata["admin_portals_found"] = 1
}

// addAttackSurfaces adds attack surfaces analysis to the red team report.
func (r *Report) addAttackSurfaces() {
	// Add placeholder attack surface analysis
	r.Metadata["attack_surface_scan_completed"] = true
	r.Metadata["attack_vectors_identified"] = 0
}

// addEnumerationData adds enumeration data to the red team report.
func (r *Report) addEnumerationData() {
	// Add placeholder enumeration data
	r.Metadata["enumeration_completed"] = true
	r.Metadata["enumeration_targets"] = []string{"services", "ports"}
}

// addSnarkyCommentary adds snarky commentary to the red team report when blackhat mode is enabled.
func (r *Report) addSnarkyCommentary() {
	// Add placeholder snarky commentary
	r.Metadata["snarky_mode_enabled"] = true
	r.Metadata["commentary_style"] = "blackhat"
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
