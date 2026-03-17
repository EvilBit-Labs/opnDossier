package analysis

import (
	"fmt"
	"maps"
	"net"
	"slices"
	"strings"

	"github.com/EvilBit-Labs/opnDossier/internal/constants"
	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
)

// ComputeAnalysis performs lightweight analysis of the device configuration and returns
// an Analysis suitable for serialization in JSON/YAML exports. The returned Analysis is
// derived purely from cfg with no side effects. A nil cfg returns an empty Analysis.
func ComputeAnalysis(cfg *common.CommonDevice) *common.Analysis {
	if cfg == nil {
		return &common.Analysis{}
	}

	return &common.Analysis{
		DeadRules:         DetectDeadRules(cfg),
		UnusedInterfaces:  DetectUnusedInterfaces(cfg),
		SecurityIssues:    DetectSecurityIssues(cfg),
		PerformanceIssues: DetectPerformanceIssues(cfg),
		ConsistencyIssues: DetectConsistency(cfg),
	}
}

// DetectDeadRules detects unreachable and duplicate firewall rules by grouping
// rules per interface and analyzing each group independently. Each finding carries
// a Kind field ("unreachable" or "duplicate") for structured classification.
// Returns nil when no dead rules are found.
func DetectDeadRules(cfg *common.CommonDevice) []common.DeadRuleFinding {
	if cfg == nil || len(cfg.FirewallRules) == 0 {
		return nil
	}

	var findings []common.DeadRuleFinding

	// Group rules by interface.
	interfaceRules := make(map[string][]IndexedRule)
	for i, rule := range cfg.FirewallRules {
		for _, iface := range rule.Interfaces {
			interfaceRules[iface] = append(interfaceRules[iface], IndexedRule{Index: i, Rule: rule})
		}
	}

	for _, iface := range slices.Sorted(maps.Keys(interfaceRules)) {
		rules := interfaceRules[iface]
		for i, ir := range rules {
			// Block-all makes subsequent rules unreachable.
			srcAny := ir.Rule.Source.Address == constants.NetworkAny
			dstAny := ir.Rule.Destination.Address == constants.NetworkAny
			if ir.Rule.Type == "block" && srcAny && dstAny && i < len(rules)-1 {
				findings = append(findings, common.DeadRuleFinding{
					Kind:      common.DeadRuleKindUnreachable,
					RuleIndex: ir.Index,
					Interface: iface,
					Description: fmt.Sprintf(
						"Rules after position %d on interface %s are unreachable due to preceding block-all rule",
						ir.Index+1, iface,
					),
					Recommendation: "Remove unreachable rules or reorder them before the block-all rule",
				})
			}

			// Duplicate detection.
			for j := i + 1; j < len(rules); j++ {
				if RulesEquivalent(ir.Rule, rules[j].Rule) {
					findings = append(findings, common.DeadRuleFinding{
						Kind:      common.DeadRuleKindDuplicate,
						RuleIndex: rules[j].Index,
						Interface: iface,
						Description: fmt.Sprintf(
							"Rule at position %d is duplicate of rule at position %d on interface %s",
							rules[j].Index+1, ir.Index+1, iface,
						),
						Recommendation: "Remove duplicate rule to simplify configuration",
					})
				}
			}
		}
	}

	return findings
}

// DetectUnusedInterfaces detects enabled interfaces not referenced by firewall rules,
// DHCP scopes, DNS resolvers (Unbound/DNSMasq), OpenVPN instances, WireGuard, or the
// load balancer. DNS, WireGuard, and load balancer currently assume "lan" binding when
// enabled — this is a known limitation when these services are bound to non-LAN interfaces.
// Returns nil when no unused interfaces are found.
func DetectUnusedInterfaces(cfg *common.CommonDevice) []common.UnusedInterfaceFinding {
	if cfg == nil {
		return nil
	}

	used := make(map[string]bool)

	for _, rule := range cfg.FirewallRules {
		for _, iface := range rule.Interfaces {
			used[iface] = true
		}
	}
	for _, scope := range cfg.DHCP {
		if scope.Enabled {
			used[scope.Interface] = true
		}
	}
	if cfg.DNS.Unbound.Enabled || cfg.DNS.DNSMasq.Enabled {
		used["lan"] = true
	}
	for _, srv := range cfg.VPN.OpenVPN.Servers {
		if srv.Interface != "" {
			used[srv.Interface] = true
		}
	}
	for _, cli := range cfg.VPN.OpenVPN.Clients {
		if cli.Interface != "" {
			used[cli.Interface] = true
		}
	}
	if cfg.VPN.WireGuard.Enabled {
		used["lan"] = true
	}
	if len(cfg.LoadBalancer.MonitorTypes) > 0 {
		used["lan"] = true
	}

	var findings []common.UnusedInterfaceFinding
	for _, iface := range cfg.Interfaces {
		if iface.Enabled && !used[iface.Name] {
			findings = append(findings, common.UnusedInterfaceFinding{
				InterfaceName: iface.Name,
				Description: fmt.Sprintf(
					"Interface %s is enabled but not used in any rules or services",
					strings.ToUpper(iface.Name),
				),
				Recommendation: "Consider disabling unused interface or add appropriate rules",
			})
		}
	}

	return findings
}

// DetectSecurityIssues detects security configuration issues.
// Returns nil when no security issues are found.
func DetectSecurityIssues(cfg *common.CommonDevice) []common.SecurityFinding {
	if cfg == nil {
		return nil
	}

	var findings []common.SecurityFinding

	if cfg.System.WebGUI.Protocol != "" && cfg.System.WebGUI.Protocol != constants.ProtocolHTTPS {
		findings = append(findings, common.SecurityFinding{
			Component:      "system.webgui.protocol",
			Issue:          "Insecure Web GUI Protocol",
			Severity:       "critical",
			Description:    "Web GUI is configured to use HTTP instead of HTTPS",
			Recommendation: "Change web GUI protocol to HTTPS for secure administration",
		})
	}

	if cfg.SNMP.ROCommunity == "public" {
		findings = append(findings, common.SecurityFinding{
			Component:      "snmpd.rocommunity",
			Issue:          "Default SNMP Community String",
			Severity:       "high",
			Description:    "SNMP is using the default 'public' community string",
			Recommendation: "Change SNMP community string to a secure, non-default value",
		})
	}

	for i, rule := range cfg.FirewallRules {
		if rule.Type == constants.RuleTypePass && rule.Source.Address == constants.NetworkAny &&
			slices.Contains(rule.Interfaces, "wan") {
			findings = append(findings, common.SecurityFinding{
				Component:      fmt.Sprintf("filter.rule[%d]", i),
				Issue:          "Overly Permissive WAN Rule",
				Severity:       "high",
				Description:    fmt.Sprintf("Rule %d allows any source to pass traffic on WAN interface", i+1),
				Recommendation: "Restrict source networks or add specific destination restrictions",
			})
		}
	}

	return findings
}

// DetectPerformanceIssues detects performance configuration issues.
// Returns nil when no performance issues are found.
func DetectPerformanceIssues(cfg *common.CommonDevice) []common.PerformanceFinding {
	if cfg == nil {
		return nil
	}

	var findings []common.PerformanceFinding

	if cfg.System.DisableChecksumOffloading {
		findings = append(findings, common.PerformanceFinding{
			Component:      "system.disablechecksumoffloading",
			Issue:          "Checksum Offloading Disabled",
			Severity:       "low",
			Description:    "Hardware checksum offloading is disabled, which may impact performance",
			Recommendation: "Enable checksum offloading unless experiencing specific hardware issues",
		})
	}

	if cfg.System.DisableSegmentationOffloading {
		findings = append(findings, common.PerformanceFinding{
			Component:      "system.disablesegmentationoffloading",
			Issue:          "Segmentation Offloading Disabled",
			Severity:       "low",
			Description:    "Hardware segmentation offloading is disabled, which may impact performance",
			Recommendation: "Enable segmentation offloading unless experiencing specific hardware issues",
		})
	}

	if len(cfg.FirewallRules) > constants.LargeRuleCountThreshold {
		findings = append(findings, common.PerformanceFinding{
			Component: "filter.rule",
			Issue:     "High Number of Firewall Rules",
			Severity:  "medium",
			Description: fmt.Sprintf(
				"Configuration contains %d firewall rules, which may impact performance",
				len(cfg.FirewallRules),
			),
			Recommendation: "Consider consolidating rules or using aliases to reduce rule count",
		})
	}

	return findings
}

// DetectConsistency detects configuration consistency issues.
// Returns nil when no consistency issues are found.
func DetectConsistency(cfg *common.CommonDevice) []common.ConsistencyFinding {
	if cfg == nil {
		return nil
	}

	var findings []common.ConsistencyFinding

	// Gateway format consistency.
	for _, iface := range cfg.Interfaces {
		if iface.Gateway != "" && iface.IPAddress != "" && iface.Subnet != "" {
			if net.ParseIP(iface.Gateway) == nil {
				findings = append(findings, common.ConsistencyFinding{
					Component: fmt.Sprintf("interfaces.%s.gateway", iface.Name),
					Issue:     "Invalid Gateway Format",
					Severity:  "medium",
					Description: fmt.Sprintf(
						"Gateway %s for interface %s appears to be invalid",
						iface.Gateway, iface.Name,
					),
					Recommendation: "Verify gateway IP address format and reachability",
				})
			}
		}
	}

	// DHCP without interface IP.
	lanDHCP := FindDHCPScope(cfg.DHCP, "lan")
	if lanDHCP != nil && lanDHCP.Enabled && lanDHCP.Range.From != "" && lanDHCP.Range.To != "" {
		lanIface := FindInterface(cfg.Interfaces, "lan")
		if lanIface != nil && lanIface.IPAddress == "" {
			findings = append(findings, common.ConsistencyFinding{
				Component:      "dhcpd.lan",
				Issue:          "DHCP Enabled Without Interface IP",
				Severity:       "high",
				Description:    "DHCP is enabled on LAN interface but the interface has no IP address configured",
				Recommendation: "Configure LAN interface IP address or disable DHCP service",
			})
		}
	}

	// User-group consistency.
	existingGroups := make(map[string]bool)
	for _, group := range cfg.Groups {
		existingGroups[group.Name] = true
	}
	for i, user := range cfg.Users {
		if user.GroupName != "" && !existingGroups[user.GroupName] {
			findings = append(findings, common.ConsistencyFinding{
				Component: fmt.Sprintf("system.user[%d].groupname", i),
				Issue:     "User References Non-existent Group",
				Severity:  "medium",
				Description: fmt.Sprintf(
					"User %s references group %s which does not exist",
					user.Name, user.GroupName,
				),
				Recommendation: "Create the referenced group or update user's group assignment",
			})
		}
	}

	return findings
}
