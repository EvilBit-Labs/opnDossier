package processor

import (
	"context"
	"fmt"

	"github.com/unclesp1d3r/opnFocus/internal/model"
)

// ExampleProcessor provides a basic implementation of the Processor interface.
// This serves as a reference implementation and can be extended with more sophisticated analysis.
type ExampleProcessor struct{}

// NewExampleProcessor creates a new instance of ExampleProcessor.
func NewExampleProcessor() *ExampleProcessor {
	return &ExampleProcessor{}
}

// Process analyzes the given OPNsense configuration and returns a comprehensive report.
func (p *ExampleProcessor) Process(ctx context.Context, cfg *model.Opnsense, opts ...Option) (*Report, error) {
	if cfg == nil {
		return nil, ErrConfigurationNil
	}

	// Create processor configuration with default settings
	config := DefaultConfig()
	config.ApplyOptions(opts...)

	// Create the report
	report := NewReport(cfg, *config)

	// Perform basic analysis
	if err := p.performBasicAnalysis(ctx, cfg, report, *config); err != nil {
		return nil, fmt.Errorf("failed to perform basic analysis: %w", err)
	}

	// Perform optional analyses based on configuration
	if config.EnableDeadRuleCheck {
		if err := p.performDeadRuleAnalysis(ctx, cfg, report); err != nil {
			return nil, fmt.Errorf("failed to perform dead rule analysis: %w", err)
		}
	}

	if config.EnableSecurityAnalysis {
		if err := p.performSecurityAnalysis(ctx, cfg, report); err != nil {
			return nil, fmt.Errorf("failed to perform security analysis: %w", err)
		}
	}

	if config.EnablePerformanceAnalysis {
		if err := p.performPerformanceAnalysis(ctx, cfg, report); err != nil {
			return nil, fmt.Errorf("failed to perform performance analysis: %w", err)
		}
	}

	if config.EnableComplianceCheck {
		if err := p.performComplianceCheck(ctx, cfg, report); err != nil {
			return nil, fmt.Errorf("failed to perform compliance check: %w", err)
		}
	}

	return report, nil
}

// performBasicAnalysis performs basic configuration validation and analysis.
func (p *ExampleProcessor) performBasicAnalysis(ctx context.Context, cfg *model.Opnsense, report *Report, _ Config) error {
	// Check for context cancellation
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	// Basic configuration checks
	if cfg.System.Hostname == "" {
		report.AddFinding(SeverityCritical, Finding{
			Type:           "configuration",
			Title:          "Missing Hostname",
			Description:    "The system hostname is not configured.",
			Recommendation: "Configure a hostname for the system to improve identification and management.",
			Component:      "system",
		})
	}

	if cfg.System.Domain == "" {
		report.AddFinding(SeverityMedium, Finding{
			Type:           "configuration",
			Title:          "Missing Domain Name",
			Description:    "The system domain name is not configured.",
			Recommendation: "Configure a domain name for proper FQDN resolution.",
			Component:      "system",
		})
	}

	// Check for default/weak configurations
	if cfg.System.Webgui.Protocol == "http" {
		report.AddFinding(SeverityHigh, Finding{
			Type:           "security",
			Title:          "Insecure Web GUI Protocol",
			Description:    "The web GUI is configured to use HTTP instead of HTTPS.",
			Recommendation: "Configure the web GUI to use HTTPS for secure access.",
			Component:      "webgui",
			Reference:      "https://docs.opnsense.org/manual/how-tos/self-signed-cert.html",
		})
	}

	return nil
}

// performDeadRuleAnalysis analyzes firewall rules for potential dead/unused rules.
func (p *ExampleProcessor) performDeadRuleAnalysis(ctx context.Context, cfg *model.Opnsense, report *Report) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	rules := cfg.FilterRules()
	if len(rules) == 0 {
		report.AddFinding(SeverityInfo, Finding{
			Type:           "configuration",
			Title:          "No Firewall Rules Configured",
			Description:    "No firewall rules are configured in the system.",
			Recommendation: "Consider configuring appropriate firewall rules for security.",
			Component:      "firewall",
		})
		return nil
	}

	// Basic check for rules without descriptions
	rulesWithoutDescriptions := 0
	for _, rule := range rules {
		if rule.Descr == "" {
			rulesWithoutDescriptions++
		}
	}

	if rulesWithoutDescriptions > 0 {
		report.AddFinding(SeverityLow, Finding{
			Type:           "maintenance",
			Title:          "Firewall Rules Missing Descriptions",
			Description:    fmt.Sprintf("%d firewall rules are missing descriptions, making them difficult to maintain.", rulesWithoutDescriptions),
			Recommendation: "Add meaningful descriptions to all firewall rules for better maintainability.",
			Component:      "firewall",
		})
	}

	return nil
}

// performSecurityAnalysis performs security-related analysis of the configuration.
func (p *ExampleProcessor) performSecurityAnalysis(ctx context.Context, cfg *model.Opnsense, report *Report) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	// Check for SSH configuration
	if cfg.System.SSH.Group != "" {
		report.AddFinding(SeverityInfo, Finding{
			Type:           "security",
			Title:          "SSH Access Enabled",
			Description:    "SSH access is enabled for the system.",
			Recommendation: "Ensure SSH access is properly secured with key-based authentication and restricted to authorized users only.",
			Component:      "ssh",
		})
	}

	// Check for SNMP configuration
	if cfg.Snmpd.ROCommunity != "" {
		if cfg.Snmpd.ROCommunity == "public" {
			report.AddFinding(SeverityHigh, Finding{
				Type:           "security",
				Title:          "Default SNMP Community String",
				Description:    "SNMP is configured with the default 'public' community string.",
				Recommendation: "Change the SNMP community string to a secure, non-default value.",
				Component:      "snmp",
			})
		} else {
			report.AddFinding(SeverityLow, Finding{
				Type:           "security",
				Title:          "SNMP Enabled",
				Description:    "SNMP is enabled on the system.",
				Recommendation: "Ensure SNMP access is restricted to authorized networks and users.",
				Component:      "snmp",
			})
		}
	}

	return nil
}

// performPerformanceAnalysis performs performance-related analysis of the configuration.
func (p *ExampleProcessor) performPerformanceAnalysis(ctx context.Context, cfg *model.Opnsense, report *Report) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	// Check system optimization settings
	if cfg.System.Optimization == "" {
		report.AddFinding(SeverityInfo, Finding{
			Type:           "performance",
			Title:          "System Optimization Not Configured",
			Description:    "System optimization level is not explicitly configured.",
			Recommendation: "Consider configuring an appropriate optimization level based on your system's hardware and usage patterns.",
			Component:      "system",
		})
	}

	// Check for hardware offloading settings
	if cfg.System.DisableChecksumOffloading != "" {
		report.AddFinding(SeverityInfo, Finding{
			Type:           "performance",
			Title:          "Checksum Offloading Disabled",
			Description:    "Hardware checksum offloading is disabled.",
			Recommendation: "Evaluate whether enabling checksum offloading would improve performance in your environment.",
			Component:      "network",
		})
	}

	return nil
}

// performComplianceCheck performs compliance-related checks of the configuration.
func (p *ExampleProcessor) performComplianceCheck(ctx context.Context, cfg *model.Opnsense, report *Report) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	// Check for required administrative users
	if len(cfg.System.User) == 0 {
		report.AddFinding(SeverityCritical, Finding{
			Type:           "compliance",
			Title:          "No Administrative Users Configured",
			Description:    "No administrative users are configured in the system.",
			Recommendation: "Configure at least one administrative user account for system management.",
			Component:      "users",
		})
	}

	// Check for time synchronization
	if cfg.System.Timeservers == "" && cfg.Ntpd.Prefer == "" {
		report.AddFinding(SeverityMedium, Finding{
			Type:           "compliance",
			Title:          "Time Synchronization Not Configured",
			Description:    "No time servers or NTP configuration is present.",
			Recommendation: "Configure time synchronization to ensure accurate timestamps for logging and security.",
			Component:      "ntp",
		})
	}

	return nil
}
