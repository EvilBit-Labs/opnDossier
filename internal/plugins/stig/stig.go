// Package stig provides a compliance plugin for STIG security controls.
package stig

import (
	"slices"

	"github.com/EvilBit-Labs/opnDossier/internal/compliance"
	"github.com/EvilBit-Labs/opnDossier/internal/constants"
	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
)

// STIG compliance thresholds used to evaluate service hardening controls.
const (
	// MaxDHCPInterfaces represents the maximum number of DHCP interfaces before flagging as unnecessary.
	MaxDHCPInterfaces = 2
)

// Plugin implements the compliance.Plugin interface for STIG plugin.
type Plugin struct {
	controls []compliance.Control
}

// NewPlugin creates a new STIG compliance plugin.
func NewPlugin() *Plugin {
	p := &Plugin{
		controls: []compliance.Control{
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
func (sp *Plugin) RunChecks(device *common.CommonDevice) []compliance.Finding {
	var findings []compliance.Finding

	// V-206694: Default deny policy
	if !sp.hasDefaultDenyPolicy(device) {
		findings = append(findings, compliance.Finding{
			Type:           "compliance",
			Severity:       sp.controlSeverity("V-206694"),
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
	if sp.hasOverlyPermissiveRules(device) {
		findings = append(findings, compliance.Finding{
			Type:           "compliance",
			Severity:       sp.controlSeverity("V-206674"),
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
	if sp.hasUnnecessaryServices(device) {
		findings = append(findings, compliance.Finding{
			Type:           "compliance",
			Severity:       sp.controlSeverity("V-206690"),
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
	if !sp.hasComprehensiveLogging(device) {
		findings = append(findings, compliance.Finding{
			Type:           "compliance",
			Severity:       sp.controlSeverity("V-206682"),
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

// GetControls returns all STIG controls. The returned slice is a deep copy to
// prevent callers from mutating the plugin's internal state, including nested
// reference types (References, Tags, Metadata).
func (sp *Plugin) GetControls() []compliance.Control {
	return compliance.CloneControls(sp.controls)
}

// EvaluatedControlIDs returns the IDs of controls this plugin can evaluate.
// The STIG plugin can evaluate all of its controls from config.xml data.
func (sp *Plugin) EvaluatedControlIDs(_ *common.CommonDevice) []string {
	ids := make([]string, len(sp.controls))
	for i, c := range sp.controls {
		ids[i] = c.ID
	}

	return ids
}

// GetControlByID returns a specific control by ID.
func (sp *Plugin) GetControlByID(id string) (*compliance.Control, error) {
	for _, control := range sp.controls {
		if control.ID == id {
			return &control, nil
		}
	}

	return nil, compliance.ErrControlNotFound
}

// ValidateConfiguration validates the plugin configuration.
func (sp *Plugin) ValidateConfiguration() error {
	if len(sp.controls) == 0 {
		return compliance.ErrNoControlsDefined
	}

	return nil
}

// controlSeverity returns the severity for a control ID from the control
// definitions. This ensures findings derive severity from the single source
// of truth (the control metadata) rather than hard-coding literals.
func (sp *Plugin) controlSeverity(id string) string {
	for _, c := range sp.controls {
		if c.ID == id {
			return c.Severity
		}
	}

	return ""
}

// hasDefaultDenyPolicy checks whether the device's firewall implements a default deny
// posture by verifying explicit block or reject rules exist and that no overly broad
// any-to-any allow rules override the deny policy.
func (sp *Plugin) hasDefaultDenyPolicy(device *common.CommonDevice) bool {
	// Check for default deny policy configuration
	rules := device.FirewallRules

	// If no rules exist, assume default deny (conservative approach)
	if len(rules) == 0 {
		return true
	}

	// Look for explicit deny rules at the end of rule sets
	hasExplicitDeny := false

	for _, rule := range rules {
		// Look for rules that explicitly deny traffic
		if rule.Type == common.RuleTypeBlock || rule.Type == common.RuleTypeReject {
			hasExplicitDeny = true
			break
		}
	}

	// Check if there are any "any/any" allow rules that would override default deny
	hasAnyAnyAllow := false

	for _, rule := range rules {
		if rule.Type == common.RuleTypePass {
			srcTarget := rule.Source.Address
			dstTarget := rule.Destination.Address

			if srcTarget == constants.NetworkAny && (dstTarget == "" || dstTarget == constants.NetworkAny) {
				hasAnyAnyAllow = true
				break
			}
		}
	}

	// Conservative approach: if there are explicit deny rules and no overly broad allow rules,
	// consider it as having a default deny policy
	return hasExplicitDeny && !hasAnyAnyAllow
}

// hasOverlyPermissiveRules checks whether the device contains firewall pass rules with
// overly broad source or destination addresses, wide network ranges, or missing port
// restrictions that violate STIG packet-filtering requirements.
func (sp *Plugin) hasOverlyPermissiveRules(device *common.CommonDevice) bool {
	// Check for overly permissive firewall rules
	rules := device.FirewallRules

	for _, rule := range rules {
		if rule.Type != common.RuleTypePass {
			continue
		}

		srcTarget := rule.Source.Address
		dstTarget := rule.Destination.Address

		srcBroad := srcTarget == constants.NetworkAny || slices.Contains(broadNetworks, srcTarget)
		dstBroad := dstTarget == "" || dstTarget == constants.NetworkAny ||
			slices.Contains(broadNetworks, dstTarget)

		// Check for "any/any" rules (most permissive)
		if srcTarget == constants.NetworkAny && (dstTarget == "" || dstTarget == constants.NetworkAny) {
			return true
		}

		// Check for broad network ranges (e.g., entire subnets without specific restrictions)
		if srcTarget != "" && srcBroad && dstBroad {
			return true
		}

		// Check for broad rules without specific port restrictions (TCP/UDP or unspecified protocol)
		if srcBroad && dstBroad &&
			(rule.Protocol == "" || rule.Protocol == "tcp" || rule.Protocol == "udp" || rule.Protocol == "tcp/udp") &&
			(rule.Destination.Port == "" || rule.Destination.Port == constants.NetworkAny) {
			return true
		}
	}

	return false
}

// hasUnnecessaryServices checks whether the device has network services enabled that
// increase the attack surface, including SNMP with community strings, insecure DNS
// settings, excessive DHCP interfaces, or load balancer configurations.
func (sp *Plugin) hasUnnecessaryServices(device *common.CommonDevice) bool {
	// Check for unnecessary network services

	// Check SNMP configuration - SNMP with community strings can be a security risk
	if device.SNMP.ROCommunity != "" {
		// SNMP is enabled with community string - could be unnecessary
		return true
	}

	// Check for enabled services that might be unnecessary
	// Unbound DNS resolver with DNSSEC stripping
	if device.DNS.Unbound.Enabled {
		// Check if it's configured with insecure settings
		if device.DNS.Unbound.DNSSECStripped {
			return true // DNSSEC stripping is a security concern
		}
	}

	// Check for DHCP server on interfaces that might not need it
	dhcpCount := len(device.DHCP)
	if dhcpCount > 0 {
		// Multiple DHCP interfaces might indicate unnecessary services
		if dhcpCount > MaxDHCPInterfaces {
			return true
		}
	}

	// Check for load balancer services
	if len(device.LoadBalancer.MonitorTypes) > 0 {
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

// LoggingStatus values classify the device's logging posture for STIG compliance evaluation.
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

// hasComprehensiveLogging checks whether the device is configured with comprehensive
// logging by delegating to analyzeLoggingConfiguration and requiring full coverage.
func (sp *Plugin) hasComprehensiveLogging(device *common.CommonDevice) bool {
	status := sp.analyzeLoggingConfiguration(device)
	return status == LoggingStatusComprehensive
}

// analyzeLoggingConfiguration provides detailed analysis of logging configuration
// and returns a LoggingStatus indicating the level of logging coverage.
func (sp *Plugin) analyzeLoggingConfiguration(device *common.CommonDevice) LoggingStatus {
	// Check syslog configuration
	if device.Syslog.Enabled {
		// Syslog is enabled - good
		// Check if it's configured to log important events
		if device.Syslog.SystemLogging && device.Syslog.AuthLogging {
			// System and auth logging are enabled
			return LoggingStatusComprehensive
		}
		// Syslog enabled but missing critical logging categories
		return LoggingStatusPartial
	}

	// Check for firewall rule logging
	rules := device.FirewallRules
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
	if device.IDS != nil {
		// IDS is configured - this provides additional logging capabilities
		// but without syslog, we cannot determine if logging is actually enabled
		return LoggingStatusUnableToDetermine
	}

	// No logging configuration detected
	return LoggingStatusNotConfigured
}

// broadNetworks contains common broad network ranges used to detect overly
// permissive firewall rules. Declared at package level to avoid allocation
// on every call within the rule-checking loop.
var broadNetworks = []string{
	"0.0.0.0/0",          // All IPv4
	"::/0",               // All IPv6
	"10.0.0.0/8",         // Large private network
	"172.16.0.0/12",      // Large private network
	"192.168.0.0/16",     // Large private network
	constants.NetworkAny, // Any network
}
