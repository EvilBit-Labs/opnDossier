// Package sans provides a compliance plugin for SANS security controls.
package sans

import (
	"github.com/EvilBit-Labs/opnDossier/internal/compliance"
	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
)

// checkResult holds the outcome of a compliance check helper. When Known is
// false the Result is meaningless — the check is skipped because config.xml
// does not contain the data needed to determine compliance.
type checkResult struct {
	Result bool
	Known  bool
}

// unknown is a convenience value for checks that cannot be evaluated.
var unknown = checkResult{Result: false, Known: false}

// Plugin implements the compliance.Plugin interface for SANS plugin.
type Plugin struct {
	controls []compliance.Control
}

// NewPlugin creates a new SANS compliance plugin.
func NewPlugin() *Plugin {
	return &Plugin{
		controls: allControls(),
	}
}

// Name returns the plugin name.
func (sp *Plugin) Name() string {
	return "sans"
}

// Version returns the plugin version.
func (sp *Plugin) Version() string {
	return "1.0.0"
}

// Description returns the plugin description.
func (sp *Plugin) Description() string {
	return "SANS Firewall Checklist compliance checks for firewall security"
}

// RunChecks performs SANS compliance checks against the device configuration.
// Each helper returns a checkResult. When Known is false the check is skipped
// because the data needed to determine compliance is not available in config.xml.
func (sp *Plugin) RunChecks(device *common.CommonDevice) []compliance.Finding {
	var findings []compliance.Finding

	// SANS-FW-001: Default deny — finding when missing.
	if cr := sp.checkDefaultDeny(device); cr.Known && !cr.Result {
		findings = append(findings, sp.finding("SANS-FW-001",
			"Missing Default Deny Policy (SANS)",
			"Firewall should implement a default deny policy for all traffic",
			"Configure firewall with default deny policy and explicit allow rules for necessary traffic",
			"firewall-rules"))
	}

	// SANS-FW-002: Explicit rules — finding when unclear rules exist.
	if cr := sp.checkExplicitRules(device); cr.Known && !cr.Result {
		findings = append(findings, sp.finding("SANS-FW-002",
			"Non-Explicit Firewall Rules",
			"Firewall contains pass rules without descriptions",
			"Replace any catch-all or overly permissive rules with explicit, documented rules",
			"firewall-rules"))
	}

	// SANS-FW-003: Zone separation — finding when insufficient.
	if cr := sp.checkZoneSeparation(device); cr.Known && !cr.Result {
		findings = append(findings, sp.finding("SANS-FW-003",
			"Insufficient Network Zone Separation",
			"Firewall does not enforce proper separation between different security zones",
			"Configure firewall rules to enforce proper network zone separation and access controls",
			"firewall-rules"))
	}

	// SANS-FW-004: Comprehensive logging — finding when missing.
	if cr := sp.checkComprehensiveLogging(device); cr.Known && !cr.Result {
		findings = append(findings, sp.finding("SANS-FW-004",
			"Insufficient Firewall Logging",
			"Firewall does not have comprehensive logging enabled",
			"Enable comprehensive logging for all firewall rules and security events",
			"syslog-config"))
	}

	// SANS-FW-005: Ruleset ordering — finding when misordered.
	if cr := sp.checkRulesetOrdering(device); cr.Known && !cr.Result {
		findings = append(findings, sp.finding("SANS-FW-005",
			"Improper Ruleset Ordering",
			"Block/reject rules do not precede pass rules for proper anti-spoofing ordering",
			"Reorder rules so block/reject rules appear before pass rules",
			"firewall-rules"))
	}

	// SANS-FW-006: App layer filtering — finding when missing.
	if cr := sp.checkAppLayerFiltering(device); cr.Known && !cr.Result {
		findings = append(findings, sp.finding("SANS-FW-006",
			"No Application Layer Filtering Detected",
			"No application-layer proxy packages are installed",
			"Install and configure an application-layer proxy such as HAProxy or Squid",
			"packages"))
	}

	// SANS-FW-007: Stateful inspection — finding when missing.
	if cr := sp.checkStatefulInspection(device); cr.Known && !cr.Result {
		findings = append(findings, sp.finding("SANS-FW-007",
			"Stateful Inspection Not Enforced",
			"TCP pass rules exist without stateful inspection enabled",
			"Set StateType to 'keep state' on all TCP pass rules",
			"firewall-rules"))
	}

	// SANS-FW-008: Firmware currency — finding when missing.
	if cr := sp.checkFirmwareCurrency(device); cr.Known && !cr.Result {
		findings = append(findings, sp.finding("SANS-FW-008",
			"Firmware Version Not Identified",
			"Firmware version is not set in the device configuration",
			"Ensure firmware is updated and version is recorded in configuration",
			"system-firmware"))
	}

	// SANS-FW-009: DMZ configuration — finding when missing.
	if cr := sp.checkDMZConfiguration(device); cr.Known && !cr.Result {
		findings = append(findings, sp.finding("SANS-FW-009",
			"No DMZ Interface Detected",
			"No DMZ or OPT interface is configured for network segmentation",
			"Configure a DMZ interface to isolate public-facing services",
			"interfaces"))
	}

	// SANS-FW-012: Anti-spoofing/bogon filtering — finding when missing.
	if cr := sp.checkAntiSpoofing(device); cr.Known && !cr.Result {
		findings = append(findings, sp.finding("SANS-FW-012",
			"Anti-Spoofing/Bogon Filtering Not Enabled on WAN",
			"WAN interface does not have BlockPrivate and BlockBogons enabled",
			"Enable BlockPrivate and BlockBogons on all WAN interfaces",
			"interfaces"))
	}

	// SANS-FW-013: Source routing prevention — finding when missing.
	if cr := sp.checkSourceRouting(device); cr.Known && !cr.Result {
		findings = append(findings, sp.finding("SANS-FW-013",
			"Source Routing Not Disabled",
			"IP source routing is not disabled via sysctl",
			"Set net.inet.ip.sourceroute=0 and net.inet.ip.accept_sourceroute=0 in sysctl",
			"sysctl"))
	}

	// SANS-FW-014: Dangerous port blocking — finding when dangerous ports exposed.
	if cr := sp.checkDangerousPorts(device); cr.Known && cr.Result {
		findings = append(findings, sp.finding("SANS-FW-014",
			"Dangerous Service Ports Allowed on WAN",
			"WAN pass rules allow traffic on known dangerous service ports",
			"Block NetBIOS, SNMP, Telnet, NFS and X11 ports on WAN interfaces",
			"firewall-rules"))
	}

	// SANS-FW-015: Secure remote access — finding when insecure.
	if cr := sp.checkSecureRemoteAccess(device); cr.Known && !cr.Result {
		findings = append(findings, sp.finding("SANS-FW-015",
			"Insecure Remote Access Configuration",
			"SSH is not enabled or telnet access is permitted by firewall rules",
			"Enable SSH and block telnet (port 23) on all interfaces",
			"system-ssh"))
	}

	// SANS-FW-016: FTP server isolation — finding when not isolated.
	if cr := sp.checkFTPIsolation(device); cr.Known && !cr.Result {
		findings = append(findings, sp.finding("SANS-FW-016",
			"FTP Server Not Isolated to DMZ",
			"FTP inbound rules do not target a DMZ interface",
			"Route FTP traffic to servers on a DMZ interface",
			"nat-rules"))
	}

	// SANS-FW-017: Mail traffic restriction — finding when unrestricted.
	if cr := sp.checkMailRestriction(device); cr.Known && !cr.Result {
		findings = append(findings, sp.finding("SANS-FW-017",
			"Unrestricted SMTP Traffic",
			"SMTP pass rules do not target specific destination IPs",
			"Restrict SMTP rules to target only designated mail server IPs",
			"firewall-rules"))
	}

	// SANS-FW-018: ICMP filtering — finding when allowed on WAN.
	if cr := sp.checkICMPFiltering(device); cr.Known && cr.Result {
		findings = append(findings, sp.finding("SANS-FW-018",
			"ICMP Allowed on WAN",
			"ICMP pass rules exist on WAN interfaces",
			"Block ICMP on WAN interfaces to prevent reconnaissance",
			"firewall-rules"))
	}

	// SANS-FW-019: NAT/IP masquerading — finding when not configured.
	if cr := sp.checkNATMasquerading(device); cr.Known && !cr.Result {
		findings = append(findings, sp.finding("SANS-FW-019",
			"NAT/IP Masquerading Not Configured",
			"Outbound NAT is disabled or not configured",
			"Enable outbound NAT to mask internal IP addresses",
			"nat-config"))
	}

	// SANS-FW-020: DNS zone transfer restriction — finding when unrestricted.
	if cr := sp.checkDNSZoneTransfer(device); cr.Known && cr.Result {
		findings = append(findings, sp.finding("SANS-FW-020",
			"DNS Zone Transfers Not Restricted on WAN",
			"TCP port 53 pass rules on WAN allow unrestricted DNS zone transfers",
			"Restrict TCP port 53 to authorized DNS servers only",
			"firewall-rules"))
	}

	// SANS-FW-021: Egress filtering — finding when missing.
	if cr := sp.checkEgressFiltering(device); cr.Known && !cr.Result {
		findings = append(findings, sp.finding("SANS-FW-021",
			"Egress Filtering Not Enforced",
			"Outbound pass rules do not restrict source addresses",
			"Configure outbound rules to restrict source to internal networks",
			"firewall-rules"))
	}

	// SANS-FW-022: Critical server protection — finding when missing.
	if cr := sp.checkCriticalServerProtection(device); cr.Known && !cr.Result {
		findings = append(findings, sp.finding("SANS-FW-022",
			"Critical Server Protection Insufficient",
			"No WAN-to-LAN deny rules detected to protect internal servers",
			"Add explicit deny rules for WAN-to-LAN traffic to protect critical servers",
			"firewall-rules"))
	}

	// SANS-FW-023: Default credential reset — finding when defaults exist.
	if cr := sp.checkDefaultCredentials(device); cr.Known && cr.Result {
		findings = append(findings, sp.finding("SANS-FW-023",
			"Default User Accounts Active",
			"Default user accounts (admin/root) are still active",
			"Disable or rename default accounts and set strong passwords",
			"users"))
	}

	// SANS-FW-024: TCP state enforcement — finding when missing.
	if cr := sp.checkTCPStateEnforcement(device); cr.Known && !cr.Result {
		findings = append(findings, sp.finding("SANS-FW-024",
			"TCP State Enforcement Missing",
			"TCP pass rules exist without state tracking configured",
			"Set StateType on all TCP pass rules to enforce connection state tracking",
			"firewall-rules"))
	}

	// SANS-FW-025: Firewall HA — finding when not configured.
	if cr := sp.checkFirewallHA(device); cr.Known && !cr.Result {
		findings = append(findings, sp.finding("SANS-FW-025",
			"Firewall High Availability Not Configured",
			"No HA/pfsync configuration detected",
			"Configure CARP/pfsync high availability for fault tolerance",
			"high-availability"))
	}

	return findings
}

// GetControls returns all SANS controls. The returned slice is a deep copy to
// prevent callers from mutating the plugin's internal state, including nested
// reference types (References, Tags, Metadata).
func (sp *Plugin) GetControls() []compliance.Control {
	return compliance.CloneControls(sp.controls)
}

// EvaluatedControlIDs returns the IDs of controls this plugin can evaluate
// given the device configuration. Controls that return Unknown (Known=false)
// are excluded — they cannot be assessed from config.xml data alone.
func (sp *Plugin) EvaluatedControlIDs(device *common.CommonDevice) []string {
	checks := map[string]func(*common.CommonDevice) checkResult{
		"SANS-FW-001": sp.checkDefaultDeny,
		"SANS-FW-002": sp.checkExplicitRules,
		"SANS-FW-003": sp.checkZoneSeparation,
		"SANS-FW-004": sp.checkComprehensiveLogging,
		"SANS-FW-005": sp.checkRulesetOrdering,
		"SANS-FW-006": sp.checkAppLayerFiltering,
		"SANS-FW-007": sp.checkStatefulInspection,
		"SANS-FW-008": sp.checkFirmwareCurrency,
		"SANS-FW-009": sp.checkDMZConfiguration,
		"SANS-FW-012": sp.checkAntiSpoofing,
		"SANS-FW-013": sp.checkSourceRouting,
		"SANS-FW-014": sp.checkDangerousPorts,
		"SANS-FW-015": sp.checkSecureRemoteAccess,
		"SANS-FW-016": sp.checkFTPIsolation,
		"SANS-FW-017": sp.checkMailRestriction,
		"SANS-FW-018": sp.checkICMPFiltering,
		"SANS-FW-019": sp.checkNATMasquerading,
		"SANS-FW-020": sp.checkDNSZoneTransfer,
		"SANS-FW-021": sp.checkEgressFiltering,
		"SANS-FW-022": sp.checkCriticalServerProtection,
		"SANS-FW-023": sp.checkDefaultCredentials,
		"SANS-FW-024": sp.checkTCPStateEnforcement,
		"SANS-FW-025": sp.checkFirewallHA,
	}

	var evaluated []string
	for _, ctrl := range sp.controls {
		if checkFn, exists := checks[ctrl.ID]; exists {
			if cr := checkFn(device); cr.Known {
				evaluated = append(evaluated, ctrl.ID)
			}
		}
	}

	return evaluated
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

// finding constructs a compliance.Finding with consistent structure.
func (sp *Plugin) finding(id, title, description, recommendation, component string) compliance.Finding {
	ctrl, err := sp.GetControlByID(id)

	var tags []string
	if err == nil && ctrl != nil {
		tags = make([]string, 0, len(ctrl.Tags)+1)
		tags = append(tags, ctrl.Tags...)
	}

	tags = append(tags, "sans")

	return compliance.Finding{
		Type:           "compliance",
		Severity:       sp.controlSeverity(id),
		Title:          title,
		Description:    description,
		Recommendation: recommendation,
		Component:      component,
		Reference:      id,
		References:     []string{id},
		Tags:           tags,
	}
}

// allControls returns the full set of SANS control definitions.
func allControls() []compliance.Control {
	return []compliance.Control{
		{
			ID:          "SANS-FW-001",
			Title:       "Default Deny Policy",
			Description: "Firewall should implement a default deny policy for all traffic",
			Category:    "Access Control",
			Severity:    "high",
			Rationale:   "A default deny policy ensures that only explicitly allowed traffic is permitted",
			Remediation: "Configure firewall with default deny policy and explicit allow rules for necessary traffic",
			Tags:        []string{"default-deny", "access-control", "security-policy"},
		},
		{
			ID:          "SANS-FW-002",
			Title:       "Explicit Rule Configuration",
			Description: "All firewall rules should be explicit and well-documented",
			Category:    "Rule Management",
			Severity:    "medium",
			Rationale:   "Explicit rules provide better security control and auditability",
			Remediation: "Replace any catch-all or overly permissive rules with explicit, documented rules",
			Tags:        []string{"rule-documentation", "explicit-rules", "rule-management"},
		},
		{
			ID:          "SANS-FW-003",
			Title:       "Network Zone Separation",
			Description: "Firewall should enforce proper separation between different security zones",
			Category:    "Network Segmentation",
			Severity:    "high",
			Rationale:   "Proper network zone separation prevents unauthorized access between security domains",
			Remediation: "Configure firewall rules to enforce proper network zone separation and access controls",
			Tags:        []string{"network-segmentation", "zone-separation", "access-control"},
		},
		{
			ID:          "SANS-FW-004",
			Title:       "Comprehensive Logging",
			Description: "Firewall should log all traffic and security events",
			Category:    "Logging and Monitoring",
			Severity:    "medium",
			Rationale:   "Comprehensive logging enables security analysis and incident response",
			Remediation: "Enable comprehensive logging for all firewall rules and security events",
			Tags:        []string{"logging", "security-monitoring", "audit-trail"},
		},
		{
			ID:          "SANS-FW-005",
			Title:       "Ruleset Ordering",
			Description: "Anti-spoofing and block rules should precede pass rules in the ruleset",
			Category:    "Ruleset and Filtering",
			Severity:    "high",
			Rationale:   "Proper rule ordering ensures anti-spoofing protections are applied before allowing traffic",
			Remediation: "Reorder rules so block/reject rules appear before pass rules",
			Tags:        []string{"ruleset-ordering", "anti-spoofing", "rule-management"},
		},
		{
			ID:          "SANS-FW-006",
			Title:       "Application Layer Filtering",
			Description: "Firewall should use application layer filtering via proxy packages",
			Category:    "Ruleset and Filtering",
			Severity:    "medium",
			Rationale:   "Application layer filtering provides deep packet inspection and content filtering",
			Remediation: "Install and configure an application-layer proxy such as HAProxy or Squid",
			Tags:        []string{"app-layer-filtering", "proxy", "deep-inspection"},
		},
		{
			ID:          "SANS-FW-007",
			Title:       "Stateful Inspection",
			Description: "All TCP pass rules should use stateful inspection",
			Category:    "Ruleset and Filtering",
			Severity:    "high",
			Rationale:   "Stateful inspection tracks connection state to prevent unauthorized packets",
			Remediation: "Set StateType to 'keep state' on all TCP pass rules",
			Tags:        []string{"stateful-inspection", "tcp-security", "connection-tracking"},
		},
		{
			ID:          "SANS-FW-008",
			Title:       "Firmware Currency",
			Description: "Firewall firmware version should be identifiable for currency verification",
			Category:    "Maintenance",
			Severity:    "high",
			Rationale:   "Current firmware ensures known vulnerabilities are patched",
			Remediation: "Ensure firmware is updated and version is recorded in configuration",
			Tags:        []string{"firmware", "patching", "maintenance"},
		},
		{
			ID:          "SANS-FW-009",
			Title:       "DMZ Configuration",
			Description: "A DMZ or OPT interface should be configured for public-facing services",
			Category:    "Network Architecture",
			Severity:    "high",
			Rationale:   "A DMZ isolates public-facing services from the internal network",
			Remediation: "Configure a DMZ interface to isolate public-facing services",
			Tags:        []string{"dmz", "network-architecture", "segmentation"},
		},
		{
			ID:          "SANS-FW-010",
			Title:       "Vulnerability Testing Procedure",
			Description: "Regular vulnerability testing should be performed on the firewall",
			Category:    "Maintenance",
			Severity:    "medium",
			Rationale:   "Regular vulnerability testing identifies weaknesses before exploitation",
			Remediation: "Establish a regular vulnerability testing schedule and procedure",
			Tags:        []string{"vulnerability-testing", "maintenance", "advisory"},
		},
		{
			ID:          "SANS-FW-011",
			Title:       "Security Policy Compliance",
			Description: "Firewall configuration should comply with organizational security policy",
			Category:    "Maintenance",
			Severity:    "high",
			Rationale:   "Policy compliance ensures consistent security posture across the organization",
			Remediation: "Review and align firewall configuration with organizational security policy",
			Tags:        []string{"security-policy", "compliance", "advisory"},
		},
		{
			ID:          "SANS-FW-012",
			Title:       "Anti-Spoofing/Bogon Filtering",
			Description: "WAN interface should block private and bogon networks",
			Category:    "Anti-Spoofing",
			Severity:    "critical",
			Rationale:   "Blocking private and bogon addresses on WAN prevents IP spoofing attacks",
			Remediation: "Enable BlockPrivate and BlockBogons on all WAN interfaces",
			Tags:        []string{"anti-spoofing", "bogon-filtering", "wan-security"},
		},
		{
			ID:          "SANS-FW-013",
			Title:       "Source Routing Prevention",
			Description: "IP source routing should be disabled via sysctl",
			Category:    "Anti-Spoofing",
			Severity:    "high",
			Rationale:   "Source routing allows attackers to specify packet paths, bypassing security controls",
			Remediation: "Set net.inet.ip.sourceroute=0 and net.inet.ip.accept_sourceroute=0 in sysctl",
			Tags:        []string{"source-routing", "anti-spoofing", "sysctl"},
		},
		{
			ID:          "SANS-FW-014",
			Title:       "Dangerous Service Port Blocking",
			Description: "Dangerous service ports should be blocked on WAN interfaces",
			Category:    "Port Filtering",
			Severity:    "high",
			Rationale:   "Blocking dangerous ports prevents exploitation of vulnerable services",
			Remediation: "Block NetBIOS, SNMP, Telnet, NFS and X11 ports on WAN interfaces",
			Tags:        []string{"port-filtering", "dangerous-ports", "wan-security"},
		},
		{
			ID:          "SANS-FW-015",
			Title:       "Secure Remote Access",
			Description: "SSH should be enabled and telnet should be blocked",
			Category:    "Port Filtering",
			Severity:    "high",
			Rationale:   "SSH provides encrypted remote access while telnet transmits credentials in cleartext",
			Remediation: "Enable SSH and block telnet (port 23) on all interfaces",
			Tags:        []string{"secure-access", "ssh", "telnet-blocking"},
		},
		{
			ID:          "SANS-FW-016",
			Title:       "FTP Server Isolation",
			Description: "FTP servers should be isolated on a DMZ interface",
			Category:    "Network Architecture",
			Severity:    "medium",
			Rationale:   "Isolating FTP on a DMZ prevents lateral movement to internal networks",
			Remediation: "Route FTP traffic to servers on a DMZ interface",
			Tags:        []string{"ftp-isolation", "dmz", "network-architecture"},
		},
		{
			ID:          "SANS-FW-017",
			Title:       "Mail Traffic Restriction",
			Description: "SMTP traffic should be restricted to designated mail servers",
			Category:    "Port Filtering",
			Severity:    "medium",
			Rationale:   "Restricting SMTP prevents unauthorized mail relaying and data exfiltration",
			Remediation: "Restrict SMTP rules to target only designated mail server IPs",
			Tags:        []string{"mail-restriction", "smtp", "port-filtering"},
		},
		{
			ID:          "SANS-FW-018",
			Title:       "ICMP Filtering",
			Description: "ICMP should be blocked on WAN interfaces",
			Category:    "Port Filtering",
			Severity:    "medium",
			Rationale:   "ICMP on WAN enables network reconnaissance and potential DoS attacks",
			Remediation: "Block ICMP on WAN interfaces to prevent reconnaissance",
			Tags:        []string{"icmp-filtering", "wan-security", "reconnaissance-prevention"},
		},
		{
			ID:          "SANS-FW-019",
			Title:       "NAT/IP Masquerading",
			Description: "Outbound NAT should be configured to mask internal IP addresses",
			Category:    "Network Architecture",
			Severity:    "high",
			Rationale:   "NAT hides internal IP addresses from external networks",
			Remediation: "Enable outbound NAT to mask internal IP addresses",
			Tags:        []string{"nat", "ip-masquerading", "network-architecture"},
		},
		{
			ID:          "SANS-FW-020",
			Title:       "DNS Zone Transfer Restriction",
			Description: "TCP port 53 should be restricted on WAN to prevent unauthorized zone transfers",
			Category:    "Port Filtering",
			Severity:    "high",
			Rationale:   "Unrestricted TCP 53 allows DNS zone transfers leaking internal network topology",
			Remediation: "Restrict TCP port 53 to authorized DNS servers only",
			Tags:        []string{"dns-zone-transfer", "tcp-53", "port-filtering"},
		},
		{
			ID:          "SANS-FW-021",
			Title:       "Egress Filtering",
			Description: "Outbound rules should restrict source addresses to internal networks",
			Category:    "Anti-Spoofing",
			Severity:    "high",
			Rationale:   "Egress filtering prevents spoofed outbound traffic from the network",
			Remediation: "Configure outbound rules to restrict source to internal networks",
			Tags:        []string{"egress-filtering", "anti-spoofing", "outbound-rules"},
		},
		{
			ID:          "SANS-FW-022",
			Title:       "Critical Server Protection",
			Description: "Explicit deny rules should protect internal servers from WAN traffic",
			Category:    "Server Protection",
			Severity:    "high",
			Rationale:   "Explicit deny rules provide defense-in-depth for critical servers",
			Remediation: "Add explicit deny rules for WAN-to-LAN traffic to protect critical servers",
			Tags:        []string{"server-protection", "wan-to-lan", "defense-in-depth"},
		},
		{
			ID:          "SANS-FW-023",
			Title:       "Default Credential Reset",
			Description: "Default user accounts should be disabled or renamed",
			Category:    "Server Protection",
			Severity:    "critical",
			Rationale:   "Default credentials are the first target for automated attacks",
			Remediation: "Disable or rename default accounts and set strong passwords",
			Tags:        []string{"default-credentials", "account-security", "hardening"},
		},
		{
			ID:          "SANS-FW-024",
			Title:       "TCP State Enforcement",
			Description: "TCP rules should enforce connection state tracking",
			Category:    "Server Protection",
			Severity:    "high",
			Rationale:   "State enforcement prevents out-of-state packets from reaching servers",
			Remediation: "Set StateType on all TCP pass rules to enforce connection state tracking",
			Tags:        []string{"tcp-state", "connection-tracking", "server-protection"},
		},
		{
			ID:          "SANS-FW-025",
			Title:       "Firewall High Availability",
			Description: "Firewall HA/pfsync should be configured for fault tolerance",
			Category:    "Availability",
			Severity:    "medium",
			Rationale:   "High availability prevents single points of failure in network security",
			Remediation: "Configure CARP/pfsync high availability for fault tolerance",
			Tags:        []string{"high-availability", "pfsync", "fault-tolerance"},
		},
	}
}
