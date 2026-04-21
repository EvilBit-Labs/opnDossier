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
	// severityByID maps control ID -> severity for O(1) lookups during finding
	// construction (previously O(n) linear scan over controls).
	severityByID map[string]string
}

// NewPlugin creates a new SANS compliance plugin.
func NewPlugin() *Plugin {
	controls := allControls()

	severityByID := make(map[string]string, len(controls))
	for _, c := range controls {
		severityByID[c.ID] = c.Severity
	}

	return &Plugin{
		controls:     controls,
		severityByID: severityByID,
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

// sansCheckEntry describes a single SANS check and the finding text to emit
// when it fails. failOnTrue inverts the polarity: for most checks Result==false
// indicates a non-compliant posture, but a few (dangerous ports, ICMP on WAN,
// DNS zone transfers) are flagged when Result==true.
type sansCheckEntry struct {
	controlID      string
	checkFn        func(*common.CommonDevice) checkResult
	failOnTrue     bool
	title          string
	description    string
	recommendation string
	component      string
}

// sansChecks returns the full table of SANS checks. Controls that cannot be
// evaluated from config.xml (e.g., SANS-FW-010/011 advisory controls) are
// intentionally absent — they never return Known=true and therefore produce
// neither findings nor evaluated entries.
//
//nolint:funlen // declarative control table; length is data, not branching
func (sp *Plugin) sansChecks() []sansCheckEntry {
	return []sansCheckEntry{
		{
			controlID:      "SANS-FW-001",
			checkFn:        sp.checkDefaultDeny,
			title:          "Missing Default Deny Policy (SANS)",
			description:    "Firewall should implement a default deny policy for all traffic",
			recommendation: "Configure firewall with default deny policy and explicit allow rules for necessary traffic",
			component:      "firewall-rules",
		},
		{
			controlID: "SANS-FW-002", checkFn: sp.checkExplicitRules,
			title:          "Non-Explicit Firewall Rules",
			description:    "Firewall contains pass rules without descriptions",
			recommendation: "Replace any catch-all or overly permissive rules with explicit, documented rules",
			component:      "firewall-rules",
		},
		{
			controlID: "SANS-FW-003", checkFn: sp.checkZoneSeparation,
			title:          "Insufficient Network Zone Separation",
			description:    "Firewall does not enforce proper separation between different security zones",
			recommendation: "Configure firewall rules to enforce proper network zone separation and access controls",
			component:      "firewall-rules",
		},
		{
			controlID: "SANS-FW-004", checkFn: sp.checkComprehensiveLogging,
			title:          "Insufficient Firewall Logging",
			description:    "Firewall does not have comprehensive logging enabled",
			recommendation: "Enable comprehensive logging for all firewall rules and security events",
			component:      "syslog-config",
		},
		{
			controlID: "SANS-FW-005", checkFn: sp.checkRulesetOrdering,
			title:          "Improper Ruleset Ordering",
			description:    "Block/reject rules do not precede pass rules for proper anti-spoofing ordering",
			recommendation: "Reorder rules so block/reject rules appear before pass rules",
			component:      "firewall-rules",
		},
		{
			controlID: "SANS-FW-006", checkFn: sp.checkAppLayerFiltering,
			title:          "No Application Layer Filtering Detected",
			description:    "No application-layer proxy packages are installed",
			recommendation: "Install and configure an application-layer proxy such as HAProxy or Squid",
			component:      "packages",
		},
		{
			controlID: "SANS-FW-007", checkFn: sp.checkStatefulInspection,
			title:          "Stateful Inspection Not Enforced",
			description:    "TCP pass rules exist without stateful inspection enabled",
			recommendation: "Set StateType to 'keep state' on all TCP pass rules",
			component:      "firewall-rules",
		},
		{
			controlID: "SANS-FW-008", checkFn: sp.checkFirmwareCurrency,
			title:          "Firmware Version Not Identified",
			description:    "Firmware version is not set in the device configuration",
			recommendation: "Ensure firmware is updated and version is recorded in configuration",
			component:      "system-firmware",
		},
		{
			controlID: "SANS-FW-009", checkFn: sp.checkDMZConfiguration,
			title:          "No DMZ Interface Detected",
			description:    "No DMZ or OPT interface is configured for network segmentation",
			recommendation: "Configure a DMZ interface to isolate public-facing services",
			component:      "interfaces",
		},
		{
			controlID: "SANS-FW-012", checkFn: sp.checkAntiSpoofing,
			title:          "Anti-Spoofing/Bogon Filtering Not Enabled on WAN",
			description:    "WAN interface does not have BlockPrivate and BlockBogons enabled",
			recommendation: "Enable BlockPrivate and BlockBogons on all WAN interfaces",
			component:      "interfaces",
		},
		{
			controlID: "SANS-FW-013", checkFn: sp.checkSourceRouting,
			title:          "Source Routing Not Disabled",
			description:    "IP source routing is not disabled via sysctl",
			recommendation: "Set net.inet.ip.sourceroute=0 and net.inet.ip.accept_sourceroute=0 in sysctl",
			component:      "sysctl",
		},
		{
			controlID: "SANS-FW-014", checkFn: sp.checkDangerousPorts,
			failOnTrue:     true,
			title:          "Dangerous Service Ports Allowed on WAN",
			description:    "WAN pass rules allow traffic on known dangerous service ports",
			recommendation: "Block NetBIOS, SNMP, Telnet, NFS and X11 ports on WAN interfaces",
			component:      "firewall-rules",
		},
		{
			controlID: "SANS-FW-015", checkFn: sp.checkSecureRemoteAccess,
			title:          "Insecure Remote Access Configuration",
			description:    "SSH is not enabled or telnet access is permitted by firewall rules",
			recommendation: "Enable SSH and block telnet (port 23) on all interfaces",
			component:      "system-ssh",
		},
		{
			controlID: "SANS-FW-016", checkFn: sp.checkFTPIsolation,
			title:          "FTP Server Not Isolated to DMZ",
			description:    "FTP inbound rules do not target a DMZ interface",
			recommendation: "Route FTP traffic to servers on a DMZ interface",
			component:      "nat-rules",
		},
		{
			controlID: "SANS-FW-017", checkFn: sp.checkMailRestriction,
			title:          "Unrestricted SMTP Traffic",
			description:    "SMTP pass rules do not target specific destination IPs",
			recommendation: "Restrict SMTP rules to target only designated mail server IPs",
			component:      "firewall-rules",
		},
		{
			controlID: "SANS-FW-018", checkFn: sp.checkICMPFiltering,
			failOnTrue:     true,
			title:          "ICMP Allowed on WAN",
			description:    "ICMP pass rules exist on WAN interfaces",
			recommendation: "Block ICMP on WAN interfaces to prevent reconnaissance",
			component:      "firewall-rules",
		},
		{
			controlID: "SANS-FW-019", checkFn: sp.checkNATMasquerading,
			title:          "NAT/IP Masquerading Not Configured",
			description:    "Outbound NAT is disabled or not configured",
			recommendation: "Enable outbound NAT to mask internal IP addresses",
			component:      "nat-config",
		},
		{
			controlID: "SANS-FW-020", checkFn: sp.checkDNSZoneTransfer,
			failOnTrue:     true,
			title:          "DNS Zone Transfers Not Restricted on WAN",
			description:    "TCP port 53 pass rules on WAN allow unrestricted DNS zone transfers",
			recommendation: "Restrict TCP port 53 to authorized DNS servers only",
			component:      "firewall-rules",
		},
		{
			controlID: "SANS-FW-021", checkFn: sp.checkEgressFiltering,
			title:          "Egress Filtering Not Enforced",
			description:    "Outbound pass rules do not restrict source addresses",
			recommendation: "Configure outbound rules to restrict source to internal networks",
			component:      "firewall-rules",
		},
		{
			controlID: "SANS-FW-022", checkFn: sp.checkCriticalServerProtection,
			title:          "Critical Server Protection Insufficient",
			description:    "No WAN-to-LAN deny rules detected to protect internal servers",
			recommendation: "Add explicit deny rules for WAN-to-LAN traffic to protect critical servers",
			component:      "firewall-rules",
		},
		{
			controlID: "SANS-FW-023", checkFn: sp.checkDefaultCredentials,
			failOnTrue:     true,
			title:          "Default User Accounts Active",
			description:    "Default user accounts (admin/root) are still active",
			recommendation: "Disable or rename default accounts and set strong passwords",
			component:      "users",
		},
		{
			controlID: "SANS-FW-024", checkFn: sp.checkTCPStateEnforcement,
			title:          "TCP State Enforcement Missing",
			description:    "TCP pass rules exist without state tracking configured",
			recommendation: "Set StateType on all TCP pass rules to enforce connection state tracking",
			component:      "firewall-rules",
		},
		{
			controlID: "SANS-FW-025", checkFn: sp.checkFirewallHA,
			title:          "Firewall High Availability Not Configured",
			description:    "No HA/pfsync configuration detected",
			recommendation: "Configure CARP/pfsync high availability for fault tolerance",
			component:      "high-availability",
		},
	}
}

// RunChecks performs SANS compliance checks against the device configuration in
// a single traversal. Returns (findings, evaluated, err). Each check is invoked
// exactly once — its result determines both whether a finding is emitted and
// whether the control ID is appended to evaluated.
//
// err is currently always nil; reserved for future unrecoverable conditions.
//
//nolint:gocritic // nonamedreturns enforced project-wide; docstring clarifies return shape.
func (sp *Plugin) RunChecks(
	device *common.CommonDevice,
) ([]compliance.Finding, []string, error) {
	table := sp.sansChecks()

	findings := make([]compliance.Finding, 0, len(table))
	evaluated := make([]string, 0, len(table))

	for _, entry := range table {
		cr := entry.checkFn(device)
		if !cr.Known {
			continue
		}

		evaluated = append(evaluated, entry.controlID)

		failed := !cr.Result
		if entry.failOnTrue {
			failed = cr.Result
		}

		if !failed {
			continue
		}

		findings = append(findings, sp.finding(
			entry.controlID,
			entry.title,
			entry.description,
			entry.recommendation,
			entry.component,
		))
	}

	return findings, evaluated, nil
}

// GetControls returns all SANS controls. The returned slice is a deep copy to
// prevent callers from mutating the plugin's internal state, including nested
// reference types (References, Tags, Metadata).
func (sp *Plugin) GetControls() []compliance.Control {
	return compliance.CloneControls(sp.controls)
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

// controlSeverity returns the severity for a control ID from the pre-built
// severityByID map populated in NewPlugin. Returns "" when the ID is unknown.
// O(1) — replaces the historical O(n) linear scan over sp.controls.
func (sp *Plugin) controlSeverity(id string) string {
	return sp.severityByID[id]
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
//
//nolint:funlen // declarative control table; length is data, not branching
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
