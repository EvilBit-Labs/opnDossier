// Package stig provides a compliance plugin for STIG security controls.
package stig

import (
	"slices"

	"github.com/EvilBit-Labs/opnDossier/internal/model"
	"github.com/EvilBit-Labs/opnDossier/internal/plugin"
)

const (
	// NetworkAny represents "any" network in firewall rules.
	NetworkAny = "any"
	// MaxDHCPInterfaces represents the maximum number of DHCP interfaces before flagging as unnecessary.
	MaxDHCPInterfaces = 2
)

// Plugin implements the CompliancePlugin interface for STIG compliance.
type Plugin struct {
	controls []plugin.Control
}

// NewPlugin creates a new STIG compliance plugin.
func NewPlugin() *Plugin {
	p := &Plugin{
		controls: []plugin.Control{
			{
				ID:          "V-206694",
				Title:       "Firewall must deny network communications traffic by default",
				Description: "Firewall must implement a default deny policy for all traffic",
				Category:    "Default Deny Policy",
				Severity:    "high",
				Rationale:   "A default deny policy ensures that only explicitly allowed traffic is permitted",
				Remediation: "Configure firewall to deny all traffic by default and only allow necessary traffic through explicit rules",
				Tags:        []string{"default-deny", "firewall-rules", "security-posture"},
			},
			{
				ID:          "V-206674",
				Title:       "Firewall must use packet headers and attributes for filtering",
				Description: "Firewall must use specific packet headers and attributes for filtering",
				Category:    "Packet Filtering",
				Severity:    "high",
				Rationale:   "Specific packet filtering ensures precise control over network traffic",
				Remediation: "Review and tighten firewall rules to use specific source/destination addresses and ports",
				Tags:        []string{"packet-filtering", "access-control", "network-segmentation"},
			},
			{
				ID:          "V-206690",
				Title:       "Firewall must disable unnecessary network services",
				Description: "Firewall must have unnecessary network services disabled",
				Category:    "Service Hardening",
				Severity:    "medium",
				Rationale:   "Disabling unnecessary services reduces attack surface",
				Remediation: "Disable or remove unnecessary network services and functions",
				Tags:        []string{"service-hardening", "unnecessary-services", "security-hardening"},
			},
			{
				ID:          "V-206682",
				Title:       "Firewall must generate comprehensive traffic logs",
				Description: "Firewall must generate comprehensive logs for all traffic",
				Category:    "Logging",
				Severity:    "medium",
				Rationale:   "Comprehensive logging enables security analysis and incident response",
				Remediation: "Enable comprehensive logging for all firewall rules and ensure logs capture success/failure outcomes",
				Tags:        []string{"logging", "audit-trail", "security-monitoring"},
			},
		},
	}

	return p
}

// Name returns the plugin name.
func (sp *Plugin) Name() string {
	return "stig"
}

// Version returns the plugin version.
func (sp *Plugin) Version() string {
	return "1.0.0"
}

// Description returns the plugin description.
func (sp *Plugin) Description() string {
	return "STIG (Security Technical Implementation Guide) compliance checks for firewall security"
}

// RunChecks performs STIG compliance checks.
func (sp *Plugin) RunChecks(config *model.OpnSenseDocument) []plugin.Finding {
	var findings []plugin.Finding

	// V-206694: Default deny policy
	if !sp.hasDefaultDenyPolicy(config) {
		findings = append(findings, plugin.Finding{
			Type:           "compliance",
			Title:          "Missing Default Deny Policy",
			Description:    "Firewall does not implement a default deny policy for all traffic",
			Recommendation: "Configure firewall to deny all traffic by default and only allow necessary traffic through explicit rules",
			Component:      "firewall-rules",
			Reference:      "STIG V-206694",
			References:     []string{"V-206694"},
			Tags:           []string{"default-deny", "firewall-rules", "security-posture", "stig"},
		})
	}

	// V-206674: Specific packet filtering
	if sp.hasOverlyPermissiveRules(config) {
		findings = append(findings, plugin.Finding{
			Type:           "compliance",
			Title:          "Overly Permissive Firewall Rules",
			Description:    "Firewall contains rules that are too broad or permissive",
			Recommendation: "Review and tighten firewall rules to use specific source/destination addresses and ports",
			Component:      "firewall-rules",
			Reference:      "STIG V-206674",
			References:     []string{"V-206674"},
			Tags:           []string{"packet-filtering", "access-control", "network-segmentation", "stig"},
		})
	}

	// V-206690: Unnecessary services
	if sp.hasUnnecessaryServices(config) {
		findings = append(findings, plugin.Finding{
			Type:           "compliance",
			Title:          "Unnecessary Network Services Enabled",
			Description:    "Firewall has unnecessary network services enabled",
			Recommendation: "Disable or remove unnecessary network services and functions",
			Component:      "service-config",
			Reference:      "STIG V-206690",
			References:     []string{"V-206690"},
			Tags:           []string{"service-hardening", "unnecessary-services", "security-hardening", "stig"},
		})
	}

	// V-206682: Comprehensive logging
	if !sp.hasComprehensiveLogging(config) {
		findings = append(findings, plugin.Finding{
			Type:           "compliance",
			Title:          "Insufficient Firewall Logging",
			Description:    "Firewall does not generate comprehensive logs for all traffic",
			Recommendation: "Enable comprehensive logging for all firewall rules and ensure logs capture success/failure outcomes",
			Component:      "logging-config",
			Reference:      "STIG V-206682",
			References:     []string{"V-206682"},
			Tags:           []string{"logging", "audit-trail", "security-monitoring", "stig"},
		})
	}

	return findings
}

// GetControls returns all STIG controls.
func (sp *Plugin) GetControls() []plugin.Control {
	return sp.controls
}

// GetControlByID returns a specific control by ID.
func (sp *Plugin) GetControlByID(id string) (*plugin.Control, error) {
	for _, control := range sp.controls {
		if control.ID == id {
			return &control, nil
		}
	}

	return nil, plugin.ErrControlNotFound
}

// ValidateConfiguration validates the plugin configuration.
func (sp *Plugin) ValidateConfiguration() error {
	if len(sp.controls) == 0 {
		return plugin.ErrNoControlsDefined
	}

	return nil
}

// Helper methods for compliance checks

func (sp *Plugin) hasDefaultDenyPolicy(config *model.OpnSenseDocument) bool {
	// Check for default deny policy configuration
	rules := config.FilterRules()

	// If no rules exist, assume default deny (conservative approach)
	if len(rules) == 0 {
		return true
	}

	// Look for explicit deny rules at the end of rule sets
	hasExplicitDeny := false

	for _, rule := range rules {
		// Look for rules that explicitly deny traffic
		if rule.Type == "block" || rule.Type == "reject" {
			hasExplicitDeny = true
			break
		}
	}

	// Check if there are any "any/any" allow rules that would override default deny
	hasAnyAnyAllow := false

	for _, rule := range rules {
		if rule.Type == "pass" {
			// Check if source is "any"
			if rule.Source.IsAny() || rule.Source.Network == NetworkAny {
				// Check if destination is "any" or if protocol allows broad access
				if rule.Destination.IsAny() || rule.Destination.Network == NetworkAny {
					hasAnyAnyAllow = true
					break
				}
			}
		}
	}

	// Conservative approach: if there are explicit deny rules and no overly broad allow rules,
	// consider it as having a default deny policy
	return hasExplicitDeny && !hasAnyAnyAllow
}

func (sp *Plugin) hasOverlyPermissiveRules(config *model.OpnSenseDocument) bool {
	// Check for overly permissive firewall rules
	rules := config.FilterRules()

	for _, rule := range rules {
		if rule.Type != "pass" {
			continue
		}

		// Check for "any/any" rules (most permissive)
		if (rule.Source.IsAny() || rule.Source.Network == NetworkAny) &&
			(rule.Destination.IsAny() || rule.Destination.Network == NetworkAny) {
			return true
		}

		// Check for broad network ranges (e.g., entire subnets without specific restrictions)
		srcTarget := rule.Source.EffectiveAddress()
		dstTarget := rule.Destination.EffectiveAddress()
		if srcTarget != "" && (srcTarget == NetworkAny ||
			slices.Contains(sp.broadNetworkRanges(), srcTarget)) {
			// If destination is also broad, this is overly permissive
			if dstTarget == "" || dstTarget == NetworkAny ||
				slices.Contains(sp.broadNetworkRanges(), dstTarget) {
				return true
			}
		}

		// Check for rules without specific port restrictions
		if rule.Destination.Port == "" || rule.Destination.Port == NetworkAny {
			return true
		}
	}

	return false
}

func (sp *Plugin) hasUnnecessaryServices(config *model.OpnSenseDocument) bool {
	// Check for unnecessary network services

	// Check SNMP configuration - SNMP with community strings can be a security risk
	if config.Snmpd.ROCommunity != "" {
		// SNMP is enabled with community string - could be unnecessary
		return true
	}

	// Check for enabled services that might be unnecessary
	// Unbound DNS resolver with DNSSEC stripping
	if config.Unbound.Enable == "1" {
		// Check if it's configured with insecure settings
		if config.Unbound.Dnssecstripped == "1" {
			return true // DNSSEC stripping is a security concern
		}
	}

	// Check for DHCP server on interfaces that might not need it
	dhcpInterfaces := config.Dhcpd.Names()
	if len(dhcpInterfaces) > 0 {
		// Multiple DHCP interfaces might indicate unnecessary services
		if len(dhcpInterfaces) > MaxDHCPInterfaces {
			return true
		}
	}

	// Check for load balancer services
	if len(config.LoadBalancer.MonitorType) > 0 {
		// Load balancer is configured - check if it's necessary
		// This is a conservative check - load balancers can be necessary
		// but also represent additional attack surface
		return true
	}

	// Check for RRD (Round Robin Database) - usually necessary for monitoring
	// but could be disabled in high-security environments
	// RRD is generally necessary for monitoring, so we won't flag it as unnecessary
	return false
}

// LoggingStatus represents the result of logging configuration analysis.
type LoggingStatus int

const (
	// LoggingStatusNotConfigured indicates no logging configuration is detected.
	LoggingStatusNotConfigured LoggingStatus = iota
	// LoggingStatusComprehensive indicates comprehensive logging is properly configured.
	LoggingStatusComprehensive
	// LoggingStatusPartial indicates logging is partially configured but missing critical components.
	LoggingStatusPartial
	// LoggingStatusUnableToDetermine indicates logging status cannot be determined due to model limitations.
	LoggingStatusUnableToDetermine
)

func (sp *Plugin) hasComprehensiveLogging(config *model.OpnSenseDocument) bool {
	status := sp.analyzeLoggingConfiguration(config)
	return status == LoggingStatusComprehensive
}

// analyzeLoggingConfiguration provides detailed analysis of logging configuration
// and returns a LoggingStatus indicating the level of logging coverage.
func (sp *Plugin) analyzeLoggingConfiguration(config *model.OpnSenseDocument) LoggingStatus {
	// Check syslog configuration
	if config.Syslog.Enable.Bool() {
		// Syslog is enabled - good
		// Check if it's configured to log important events
		if config.Syslog.System.Bool() && config.Syslog.Auth.Bool() {
			// System and auth logging are enabled
			return LoggingStatusComprehensive
		}
		// Syslog enabled but missing critical logging categories
		return LoggingStatusPartial
	}

	// Check for firewall rule logging
	rules := config.FilterRules()
	if len(rules) > 0 {
		// CRITICAL ASSUMPTION: When firewall rules exist and syslog is not explicitly
		// configured, we cannot definitively determine if logging is enabled.
		// The current model doesn't expose individual rule logging settings,
		// so we must return "unable to determine" rather than making assumptions
		// about logging being enabled or disabled.
		//
		// This assumption affects compliance assessment accuracy and should be
		// addressed by enhancing the model to expose rule-level logging configuration.
		return LoggingStatusUnableToDetermine
	}

	// Check for IDS/IPS logging if available
	if config.OPNsense.Firewall != nil {
		// Firewall is configured - this provides additional logging capabilities
		// but without syslog, we cannot determine if logging is actually enabled
		return LoggingStatusUnableToDetermine
	}

	// No logging configuration detected
	return LoggingStatusNotConfigured
}

// broadNetworkRanges returns a slice of common broad network ranges.
func (sp *Plugin) broadNetworkRanges() []string {
	return []string{
		"0.0.0.0/0",      // All IPv4
		"::/0",           // All IPv6
		"10.0.0.0/8",     // Large private network
		"172.16.0.0/12",  // Large private network
		"192.168.0.0/16", // Large private network
		NetworkAny,       // Any network
	}
}
