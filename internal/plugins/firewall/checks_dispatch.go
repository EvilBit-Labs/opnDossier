// Package firewall provides a compliance plugin for firewall-specific security checks.
package firewall

import (
	"github.com/EvilBit-Labs/opnDossier/internal/compliance"
	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
)

// newCheckEntry defines a single compliance check and the finding to emit
// when the check fails.
type newCheckEntry struct {
	controlID      string
	checkFn        func(*Plugin, *common.CommonDevice) checkResult
	failOnTrue     bool // when true, finding is emitted when Result==true (inverse checks)
	title          string
	description    string
	recommendation string
	component      string
	tags           []string
}

// newChecksTable returns the table of checks for FIREWALL-009 through -061.
// Extracted as a method to keep RunChecks readable.
//
//nolint:funlen // 53 controls require a large dispatch table
func (fp *Plugin) newChecksTable() []newCheckEntry {
	return []newCheckEntry{
		// Management Plane (009-021)
		// 009-013, 015, 019: return unknown — not in table (no finding possible)
		{
			controlID:      "FIREWALL-014",
			checkFn:        (*Plugin).checkConsoleMenuProtection,
			title:          "Console Menu Not Protected",
			description:    "Console menu is not disabled",
			recommendation: "Disable console menu in System > Settings > Administration",
			component:      "console-config",
			tags:           []string{"management-access", "console-security", "firewall-controls"},
		},
		{
			controlID:      "FIREWALL-016",
			checkFn:        (*Plugin).checkDefaultCredentialReset,
			title:          "Default Credentials in Use",
			description:    "Default admin/root accounts are still enabled",
			recommendation: "Disable or rename default admin/root accounts",
			component:      "user-accounts",
			tags:           []string{"authentication", "default-credentials", "firewall-controls"},
		},
		{
			controlID:      "FIREWALL-017",
			checkFn:        (*Plugin).checkUniqueAdministratorAccounts,
			title:          "Shared Admin Account in Use",
			description:    "Generic admin account is enabled instead of unique named accounts",
			recommendation: "Create individual named accounts and disable the generic admin account",
			component:      "user-accounts",
			tags:           []string{"authentication", "accountability", "firewall-controls"},
		},
		{
			controlID: "FIREWALL-018", checkFn: (*Plugin).checkLeastPrivilegeAccess,
			title: "Overly Broad Privileges", description: "Groups are configured with page-all unrestricted access",
			recommendation: "Replace page-all privileges with specific page-level permissions",
			component:      "user-privileges", tags: []string{"authentication", "least-privilege", "firewall-controls"},
		},
		{
			controlID: "FIREWALL-020", checkFn: (*Plugin).checkDisabledUnusedAccounts,
			title: "Default System Accounts Active", description: "System accounts with default names remain enabled",
			recommendation: "Disable system accounts with default names that are no longer needed",
			component:      "user-accounts", tags: []string{"authentication", "account-hygiene", "firewall-controls"},
		},
		{
			controlID:      "FIREWALL-021",
			checkFn:        (*Plugin).checkGroupBasedPrivileges,
			title:          "No Group-Based Privileges",
			description:    "Privileges are not assigned through groups",
			recommendation: "Create groups with appropriate privileges and assign users to groups",
			component:      "user-privileges",
			tags:           []string{"authentication", "group-privileges", "firewall-controls"},
		},
		// Rule Hygiene (022-035)
		{
			controlID: "FIREWALL-022", checkFn: (*Plugin).checkNoAnyAnyPassRules,
			title: "Any-Any Pass Rule Detected", description: "Firewall contains pass rules with all fields set to any",
			recommendation: "Replace any-any rules with specific restrictions",
			component:      "firewall-rules", tags: []string{"rule-hygiene", "overly-permissive", "firewall-controls"},
		},
		{
			controlID: "FIREWALL-023", checkFn: (*Plugin).checkNoAnySourceOnWANInbound,
			title: "Any Source on WAN Inbound", description: "WAN pass rules allow any source address",
			recommendation: "Restrict WAN inbound rules to specific source addresses",
			component:      "firewall-rules", tags: []string{"rule-hygiene", "wan-security", "firewall-controls"},
		},
		{
			controlID: "FIREWALL-024", checkFn: (*Plugin).checkSpecificPortRules,
			title: "Non-Specific Port Rules", description: "Pass rules exist without explicit destination ports",
			recommendation: "Specify explicit destination ports on all TCP/UDP pass rules",
			component:      "firewall-rules", tags: []string{"rule-hygiene", "port-specificity", "firewall-controls"},
		},
		{
			controlID: "FIREWALL-025", checkFn: (*Plugin).checkRuleDocumentation,
			title: "Undocumented Firewall Rules", description: "Enabled firewall rules exist without descriptions",
			recommendation: "Add meaningful descriptions to all firewall rules",
			component:      "firewall-rules", tags: []string{"rule-hygiene", "documentation", "firewall-controls"},
		},
		{
			controlID:      "FIREWALL-026",
			checkFn:        (*Plugin).checkDisabledRuleCleanup,
			title:          "Excessive Disabled Rules",
			description:    "More than 10 disabled firewall rules indicate stale configuration",
			recommendation: "Review and remove disabled rules that are no longer needed",
			component:      "firewall-rules",
			tags:           []string{"rule-hygiene", "cleanup", "firewall-controls"},
		},
		{
			controlID:      "FIREWALL-027",
			checkFn:        (*Plugin).checkProtocolSpecification,
			title:          "Unspecified Protocol Rules",
			description:    "Pass rules exist without explicit protocol specification",
			recommendation: "Specify TCP, UDP, or ICMP protocol on all pass rules",
			component:      "firewall-rules",
			tags:           []string{"rule-hygiene", "protocol-specificity", "firewall-controls"},
		},
		{
			controlID: "FIREWALL-028", checkFn: (*Plugin).checkPassRuleLogging,
			title: "Pass Rules Without Logging", description: "Pass rules exist without logging enabled",
			recommendation: "Enable logging on pass rules for traffic visibility",
			component:      "firewall-rules", tags: []string{"rule-hygiene", "logging", "firewall-controls"},
		},
		{
			controlID:      "FIREWALL-029",
			checkFn:        (*Plugin).checkPrivateAddressFilteringOnWAN,
			title:          "Private Addresses Not Blocked on WAN",
			description:    "WAN interface does not block RFC 1918 private addresses",
			recommendation: "Enable Block private networks on WAN interfaces",
			component:      "wan-interfaces",
			tags:           []string{"network-segmentation", "private-addresses", "firewall-controls"},
		},
		{
			controlID:      "FIREWALL-030",
			checkFn:        (*Plugin).checkBogonFilteringOnWAN,
			title:          "Bogon Addresses Not Blocked on WAN",
			description:    "WAN interface does not block bogon addresses",
			recommendation: "Enable Block bogon networks on WAN interfaces",
			component:      "wan-interfaces",
			tags:           []string{"network-segmentation", "bogon-filtering", "firewall-controls"},
		},
		{
			controlID: "FIREWALL-031", checkFn: (*Plugin).checkUnusedInterfaceDisablement,
			title: "Disabled Interfaces Present", description: "Configured interfaces exist that are not enabled",
			recommendation: "Disable or remove unused interfaces",
			component:      "interfaces", tags: []string{"network-segmentation", "attack-surface", "firewall-controls"},
		},
		{
			controlID: "FIREWALL-032", checkFn: (*Plugin).checkVLANSegmentation,
			title: "No VLAN Segmentation", description: "Network does not use VLAN segmentation",
			recommendation: "Configure VLANs to segment the network",
			component:      "vlans", tags: []string{"network-segmentation", "vlans", "firewall-controls"},
		},
		{
			controlID: "FIREWALL-033", checkFn: (*Plugin).checkSourceRouteRejection,
			title: "Source Routing Not Disabled", description: "IP source routing is not disabled via sysctl",
			recommendation: "Set net.inet.ip.sourceroute to 0 in System > Settings > Tunables",
			component:      "sysctl", tags: []string{"anti-spoofing", "source-routing", "firewall-controls"},
		},
		{
			controlID: "FIREWALL-034", checkFn: (*Plugin).checkSYNFloodProtection,
			title: "SYN Cookies Not Enabled", description: "TCP SYN cookie protection is not enabled",
			recommendation: "Set net.inet.tcp.syncookies to 1 in System > Settings > Tunables",
			component:      "sysctl", tags: []string{"anti-spoofing", "syn-flood", "firewall-controls"},
		},
		// 035: returns unknown — not in table
		// Encryption & Monitoring (036-053)
		{
			controlID:      "FIREWALL-036",
			checkFn:        (*Plugin).checkValidWebGUICertificate,
			title:          "No Web GUI Certificate",
			description:    "Web GUI does not have a TLS certificate reference configured",
			recommendation: "Configure a valid TLS certificate for the web GUI",
			component:      "web-gui-cert",
			tags:           []string{"encryption", "certificates", "firewall-controls"},
		},
		// 037, 038: return unknown — not in table
		{
			controlID: "FIREWALL-039", checkFn: (*Plugin).checkRemoteSyslog,
			title: "Remote Syslog Not Configured", description: "Remote syslog forwarding is not configured",
			recommendation: "Configure remote syslog in System > Settings > Logging / targets",
			component:      "syslog-config", tags: []string{"logging", "remote-syslog", "firewall-controls"},
		},
		{
			controlID:      "FIREWALL-040",
			checkFn:        (*Plugin).checkAuthenticationEventLogging,
			title:          "Auth Event Logging Not Enabled",
			description:    "Authentication event logging is not forwarded to syslog",
			recommendation: "Enable authentication logging in syslog settings",
			component:      "syslog-config",
			tags:           []string{"logging", "auth-logging", "firewall-controls"},
		},
		{
			controlID:      "FIREWALL-041",
			checkFn:        (*Plugin).checkFirewallFilterLogging,
			title:          "Filter Logging Not Enabled",
			description:    "Firewall filter event logging is not forwarded to syslog",
			recommendation: "Enable filter logging in syslog settings",
			component:      "syslog-config",
			tags:           []string{"logging", "filter-logging", "firewall-controls"},
		},
		{
			controlID: "FIREWALL-042", checkFn: (*Plugin).checkLogRetention,
			title: "Log Retention Not Configured", description: "Log retention settings are not configured",
			recommendation: "Configure log file size and rotation in System > Settings > Logging",
			component:      "syslog-config", tags: []string{"logging", "log-retention", "firewall-controls"},
		},
		{
			controlID: "FIREWALL-043", checkFn: (*Plugin).checkNTPConfiguration,
			title: "Insufficient NTP Servers", description: "Fewer than two NTP servers are configured",
			recommendation: "Configure at least two NTP servers",
			component:      "time-config", tags: []string{"time-sync", "ntp", "firewall-controls"},
		},
		{
			controlID: "FIREWALL-044", checkFn: (*Plugin).checkTimezoneConfiguration,
			title: "Timezone Not Configured", description: "System timezone is not explicitly configured",
			recommendation: "Set timezone in System > Settings > General",
			component:      "time-config", tags: []string{"time-sync", "timezone", "firewall-controls"},
		},
		{
			controlID: "FIREWALL-045", checkFn: (*Plugin).checkSNMPDisabledIfUnused,
			title: "SNMP Enabled", description: "SNMP is configured with a community string",
			recommendation: "Remove SNMP community string if SNMP is not required",
			component:      "snmp-config", tags: []string{"snmp-security", "attack-surface", "firewall-controls"},
		},
		{
			controlID:      "FIREWALL-046",
			checkFn:        (*Plugin).checkNoDefaultCommunityStrings,
			title:          "Default SNMP Community String",
			description:    "SNMP uses a default community string (public or private)",
			recommendation: "Change SNMP community string to a unique, complex value",
			component:      "snmp-config",
			tags:           []string{"snmp-security", "default-credentials", "firewall-controls"},
		},
		{
			controlID: "FIREWALL-047", checkFn: (*Plugin).checkStrongVPNEncryption,
			title: "Weak VPN Encryption", description: "IPsec Phase 2 tunnels use weak encryption algorithms",
			recommendation: "Configure AES-256-GCM or AES-128-GCM for IPsec Phase 2",
			component:      "vpn-ipsec", tags: []string{"vpn-config", "encryption", "firewall-controls"},
		},
		{
			controlID: "FIREWALL-048", checkFn: (*Plugin).checkStrongVPNIntegrity,
			title: "Weak VPN Integrity Algorithms", description: "IPsec Phase 2 tunnels use weak hash algorithms",
			recommendation: "Configure SHA-256 or stronger for IPsec Phase 2",
			component:      "vpn-ipsec", tags: []string{"vpn-config", "integrity", "firewall-controls"},
		},
		{
			controlID: "FIREWALL-049", checkFn: (*Plugin).checkPerfectForwardSecrecy,
			title: "PFS Not Configured", description: "IPsec Phase 2 tunnels do not use Perfect Forward Secrecy",
			recommendation: "Enable PFS with a DH group on IPsec Phase 2 tunnels",
			component:      "vpn-ipsec", tags: []string{"vpn-config", "pfs", "firewall-controls"},
		},
		{
			controlID: "FIREWALL-050", checkFn: (*Plugin).checkVPNKeyLifetime,
			title: "VPN Key Lifetime Not Set", description: "IPsec Phase 2 tunnels have no configured key lifetime",
			recommendation: "Configure an appropriate key lifetime for IPsec Phase 2",
			component:      "vpn-ipsec", tags: []string{"vpn-config", "key-lifetime", "firewall-controls"},
		},
		{
			controlID: "FIREWALL-051", checkFn: (*Plugin).checkNoIKEv1AggressiveMode,
			title: "IKEv1 Aggressive Mode in Use", description: "IPsec tunnels use IKEv1 aggressive mode",
			recommendation: "Switch to IKEv1 main mode or migrate to IKEv2",
			component:      "vpn-ipsec", tags: []string{"vpn-config", "ikev1", "firewall-controls"},
		},
		{
			controlID: "FIREWALL-052", checkFn: (*Plugin).checkIKEv2Preferred,
			title: "IKEv1 in Use Instead of IKEv2", description: "IPsec tunnels use IKEv1 instead of preferred IKEv2",
			recommendation: "Migrate IPsec tunnels to IKEv2",
			component:      "vpn-ipsec", tags: []string{"vpn-config", "ikev2", "firewall-controls"},
		},
		{
			controlID: "FIREWALL-053", checkFn: (*Plugin).checkDeadPeerDetection,
			title: "Dead Peer Detection Not Configured", description: "IPsec tunnels do not have DPD configured",
			recommendation: "Configure DPD delay and max failures on IPsec Phase 1",
			component:      "vpn-ipsec", tags: []string{"vpn-config", "dpd", "firewall-controls"},
		},
		// Services (054-061)
		{
			controlID: "FIREWALL-054", checkFn: (*Plugin).checkDocumentedPortForwards,
			title: "Undocumented Port Forwards", description: "Inbound NAT rules exist without descriptions",
			recommendation: "Add descriptions to all port-forward rules",
			component:      "nat-config", tags: []string{"nat-security", "documentation", "firewall-controls"},
		},
		{
			controlID: "FIREWALL-055", checkFn: (*Plugin).checkOutboundNATControl,
			title: "Automatic Outbound NAT", description: "Outbound NAT is in automatic mode without explicit control",
			recommendation: "Switch to hybrid or advanced outbound NAT mode",
			component:      "nat-config", tags: []string{"nat-security", "outbound-nat", "firewall-controls"},
		},
		{
			controlID: "FIREWALL-056", checkFn: (*Plugin).checkNATReflectionDisabled,
			title: "NAT Reflection Enabled", description: "NAT reflection is not disabled",
			recommendation: "Disable NAT reflection in Firewall > Settings > Advanced",
			component:      "nat-config", tags: []string{"nat-security", "nat-reflection", "firewall-controls"},
		},
		// 057: returns unknown — not in table
		{
			controlID: "FIREWALL-058", checkFn: (*Plugin).checkDNSSECValidation,
			title: "DNSSEC Not Enabled", description: "DNSSEC validation is not enabled on the DNS resolver",
			recommendation: "Enable DNSSEC in Services > Unbound DNS > General",
			component:      "dns-config", tags: []string{"dns-security", "dnssec", "firewall-controls"},
		},
		// 059, 060: return unknown — not in table
		{
			controlID:      "FIREWALL-061",
			checkFn:        (*Plugin).checkHAConfiguration,
			title:          "Incomplete HA Configuration",
			description:    "High availability is partially configured but missing pfsync peer",
			recommendation: "Complete HA configuration with pfsync peer and sync settings",
			component:      "ha-config",
			tags:           []string{"high-availability", "pfsync", "firewall-controls"},
		},
	}
}

// runNewChecks evaluates all checks from FIREWALL-009 through -061 in a single
// pass. Returns (findings, evaluated):
//   - findings: compliance findings for checks that failed.
//   - evaluated: control IDs for checks that could be evaluated (Known=true),
//     independent of pass/fail. Controls with Known=false (insufficient data
//     in config.xml) are excluded.
//
// The table itself enumerates only the controls where a finding is possible;
// controls that always return Unknown are in fp.controls but not in this
// table, and are intentionally absent from evaluated.
//
//nolint:gocritic // nonamedreturns enforced project-wide; docstring clarifies return shape.
func (fp *Plugin) runNewChecks(device *common.CommonDevice) ([]compliance.Finding, []string) {
	table := fp.newChecksTable()

	findings := make([]compliance.Finding, 0, len(table))
	evaluated := make([]string, 0, len(table))

	for _, entry := range table {
		cr := entry.checkFn(fp, device)
		if !cr.Known {
			continue
		}

		evaluated = append(evaluated, entry.controlID)

		// Determine if the check failed.
		// Most checks: Result==false means non-compliant.
		// Inverse checks (failOnTrue): Result==true means non-compliant.
		failed := !cr.Result
		if entry.failOnTrue {
			failed = cr.Result
		}

		if !failed {
			continue
		}

		findings = append(findings, compliance.Finding{
			Type:           "compliance",
			Severity:       fp.controlSeverity(entry.controlID),
			Title:          entry.title,
			Description:    entry.description,
			Recommendation: entry.recommendation,
			Component:      entry.component,
			Reference:      entry.controlID,
			References:     []string{entry.controlID},
			Tags:           entry.tags,
		})
	}

	return findings, evaluated
}
