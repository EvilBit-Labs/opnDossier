package processor

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/EvilBit-Labs/opnDossier/internal/constants"
	"github.com/EvilBit-Labs/opnDossier/internal/model/common"
)

// analyze performs comprehensive analysis of the device configuration based on enabled options.
func (p *CoreProcessor) analyze(_ context.Context, cfg *common.CommonDevice, config *Config, report *Report) {
	// Dead rule detection
	if config.EnableDeadRuleCheck {
		p.analyzeDeadRules(cfg, report)
	}

	// Unused interfaces analysis
	if config.EnableSecurityAnalysis || config.EnableComplianceCheck {
		p.analyzeUnusedInterfaces(cfg, report)
	}

	// Consistency checks
	if config.EnableComplianceCheck {
		p.analyzeConsistency(cfg, report)
	}

	// Security analysis
	if config.EnableSecurityAnalysis {
		p.analyzeSecurityIssues(cfg, report)
	}

	// Performance analysis
	if config.EnablePerformanceAnalysis {
		p.analyzePerformanceIssues(cfg, report)
	}
}

// analyzeDeadRules detects firewall rules that are never hit or are effectively dead.
func (p *CoreProcessor) analyzeDeadRules(cfg *common.CommonDevice, report *Report) {
	rules := cfg.FirewallRules
	if len(rules) == 0 {
		return
	}

	// Track rules by interface to detect unreachable rules
	interfaceRules := make(map[string][]common.FirewallRule)
	for _, rule := range rules {
		// Add the rule to each interface it applies to
		for _, iface := range rule.Interfaces {
			interfaceRules[iface] = append(interfaceRules[iface], rule)
		}
	}

	// Analyze each interface's rules
	for iface, ifaceRules := range interfaceRules {
		p.analyzeInterfaceRules(iface, ifaceRules, report)
	}
}

// analyzeInterfaceRules analyzes rules on a specific interface for dead rules.
func (p *CoreProcessor) analyzeInterfaceRules(iface string, rules []common.FirewallRule, report *Report) {
	for i, rule := range rules {
		// Check for "block all" rules that make subsequent rules unreachable
		srcAny := rule.Source.Address == constants.NetworkAny
		dstAny := rule.Destination.Address == constants.NetworkAny
		if rule.Type == "block" && srcAny && dstAny {
			// If there are rules after this block-all rule, they're dead
			if i < len(rules)-1 {
				report.AddFinding(SeverityMedium, Finding{
					Type:  "dead-rule",
					Title: "Unreachable Rules After Block All",
					Description: fmt.Sprintf(
						"Rules after position %d on interface %s are unreachable due to preceding block-all rule",
						i+1,
						iface,
					),
					Component:      fmt.Sprintf("filter.rule[%d+]", i+1),
					Recommendation: "Remove unreachable rules or reorder them before the block-all rule",
				})
			}
		}

		// Check for duplicate rules
		for j := i + 1; j < len(rules); j++ {
			if p.rulesAreEquivalent(rule, rules[j]) {
				report.AddFinding(SeverityLow, Finding{
					Type:  "duplicate-rule",
					Title: "Duplicate Firewall Rule",
					Description: fmt.Sprintf(
						"Rule at position %d is duplicate of rule at position %d on interface %s",
						j+1,
						i+1,
						iface,
					),
					Component:      fmt.Sprintf("filter.rule[%d]", j),
					Recommendation: "Remove duplicate rule to simplify configuration",
				})
			}
		}

		// Check for overly broad rules that might be unintentional
		if rule.Type == constants.RuleTypePass && rule.Source.Address == constants.NetworkAny &&
			rule.Description == "" {
			report.AddFinding(SeverityHigh, Finding{
				Type:  constants.FindingTypeSecurity,
				Title: "Overly Broad Pass Rule",
				Description: fmt.Sprintf(
					"Rule at position %d on interface %s allows all traffic without description",
					i+1,
					iface,
				),
				Component:      fmt.Sprintf("filter.rule[%d]", i),
				Recommendation: "Add description and consider restricting source or destination",
			})
		}
	}
}

// rulesAreEquivalent checks if two firewall rules are functionally equivalent.
// This function compares all relevant fields that determine rule behavior.
// Note: The model.FirewallRule struct is still limited compared to actual OPNsense configurations,
// but comparisons now include state, direction, protocol, quick, and port details where available.
func (p *CoreProcessor) rulesAreEquivalent(rule1, rule2 common.FirewallRule) bool {
	// Compare core rule properties (excluding description as it doesn't affect functionality)
	if rule1.Type != rule2.Type ||
		rule1.IPProtocol != rule2.IPProtocol ||
		strings.Join(rule1.Interfaces, ",") != strings.Join(rule2.Interfaces, ",") {
		return false
	}

	// Compare additional rule behavior fields
	if rule1.StateType != rule2.StateType ||
		rule1.Direction != rule2.Direction ||
		rule1.Protocol != rule2.Protocol ||
		rule1.Quick != rule2.Quick ||
		rule1.Source.Port != rule2.Source.Port {
		return false
	}

	// Compare source and destination configuration
	if rule1.Source.Address != rule2.Source.Address ||
		rule1.Source.Port != rule2.Source.Port ||
		rule1.Source.Negated != rule2.Source.Negated {
		return false
	}

	return rule1.Destination.Address == rule2.Destination.Address &&
		rule1.Destination.Port == rule2.Destination.Port &&
		rule1.Destination.Negated == rule2.Destination.Negated
}

// markDHCPInterfaces iterates through all DHCP scopes and marks enabled ones as used.
func markDHCPInterfaces(cfg *common.CommonDevice, used map[string]bool) {
	for _, scope := range cfg.DHCP {
		if scope.Enabled {
			used[scope.Interface] = true
		}
	}
}

// markDNSInterfaces marks interfaces as used when DNS services are enabled.
// DNS services (Unbound and DNSMasq) typically bind to the LAN interface by default,
// so "lan" is marked as used when either service is enabled.
// Note: This is a conservative heuristic; actual interface bindings may vary in custom configurations.
func markDNSInterfaces(cfg *common.CommonDevice, used map[string]bool) {
	if cfg.DNS.Unbound.Enabled {
		used["lan"] = true
	}

	if cfg.DNS.DNSMasq.Enabled {
		used["lan"] = true
	}
}

// markLoadBalancerInterfaces marks interfaces as used when load balancer is configured.
// Load balancers in OPNsense work through virtual servers (VIPs) and when monitors are configured,
// it indicates active load balancing services which typically serve internal networks.
// Note: Marks "lan" as a conservative heuristic since actual interface bindings depend on VIP configuration.
func markLoadBalancerInterfaces(cfg *common.CommonDevice, used map[string]bool) {
	if len(cfg.LoadBalancer.MonitorTypes) > 0 {
		used["lan"] = true
	}
}

// markVPNInterfaces marks interfaces as used when VPN services (OpenVPN or WireGuard) are configured.
// It iterates through OpenVPN servers and clients to mark their bound interfaces,
// and checks if WireGuard is enabled (marking "lan" as the default service interface).
func markVPNInterfaces(cfg *common.CommonDevice, used map[string]bool) {
	// Mark interfaces from OpenVPN servers
	for _, server := range cfg.VPN.OpenVPN.Servers {
		if server.Interface != "" {
			used[server.Interface] = true
		}
	}

	// Mark interfaces from OpenVPN clients
	for _, client := range cfg.VPN.OpenVPN.Clients {
		if client.Interface != "" {
			used[client.Interface] = true
		}
	}

	// Check WireGuard - if enabled, mark "lan" as the default service interface
	if cfg.VPN.WireGuard.Enabled {
		used["lan"] = true
	}
}

// analyzeUnusedInterfaces detects interfaces that are defined but not used in rules or services.
func (p *CoreProcessor) analyzeUnusedInterfaces(cfg *common.CommonDevice, report *Report) {
	// Track which interfaces are used
	usedInterfaces := make(map[string]bool)

	// Mark interfaces used in firewall rules
	for _, rule := range cfg.FirewallRules {
		for _, iface := range rule.Interfaces {
			usedInterfaces[iface] = true
		}
	}

	// Mark interfaces used in services (DHCP, DNS, VPN, Load Balancer)
	markDHCPInterfaces(cfg, usedInterfaces)
	markDNSInterfaces(cfg, usedInterfaces)
	markVPNInterfaces(cfg, usedInterfaces)
	markLoadBalancerInterfaces(cfg, usedInterfaces)

	// Check all configured interfaces
	for _, iface := range cfg.Interfaces {
		if iface.Enabled && !usedInterfaces[iface.Name] {
			report.AddFinding(SeverityLow, Finding{
				Type:  "unused-interface",
				Title: "Unused Network Interface",
				Description: fmt.Sprintf(
					"Interface %s is enabled but not used in any rules or services",
					strings.ToUpper(iface.Name),
				),
				Component:      "interfaces." + iface.Name,
				Recommendation: "Consider disabling unused interface or add appropriate rules",
			})
		}
	}
}

// analyzeConsistency performs consistency checks across the configuration.
func (p *CoreProcessor) analyzeConsistency(cfg *common.CommonDevice, report *Report) {
	// Check if gateways referenced in interfaces exist
	p.checkGatewayConsistency(cfg, report)

	// Check DHCP range consistency with interface subnets
	p.checkDHCPConsistency(cfg, report)

	// Check user-group consistency
	p.checkUserGroupConsistency(cfg, report)
}

// checkGatewayConsistency verifies that gateways referenced in interfaces are properly configured.
func (p *CoreProcessor) checkGatewayConsistency(cfg *common.CommonDevice, report *Report) {
	for _, iface := range cfg.Interfaces {
		if iface.Gateway != "" && iface.IPAddress != "" && iface.Subnet != "" {
			// Basic consistency check - gateway should be in the same subnet
			if !strings.Contains(iface.Gateway, ".") {
				report.AddFinding(SeverityMedium, Finding{
					Type:  "consistency",
					Title: "Invalid Gateway Format",
					Description: fmt.Sprintf(
						"Gateway %s for interface %s appears to be invalid",
						iface.Gateway,
						iface.Name,
					),
					Component:      fmt.Sprintf("interfaces.%s.gateway", iface.Name),
					Recommendation: "Verify gateway IP address format and reachability",
				})
			}
		}
	}
}

// checkDHCPConsistency verifies DHCP configuration consistency with interface settings.
func (p *CoreProcessor) checkDHCPConsistency(cfg *common.CommonDevice, report *Report) {
	// Check LAN DHCP configuration
	lanDhcp := findDHCPScope(cfg.DHCP, "lan")
	if lanDhcp != nil && lanDhcp.Enabled && lanDhcp.Range.From != "" && lanDhcp.Range.To != "" {
		lanIface := findInterface(cfg.Interfaces, "lan")
		if lanIface != nil && lanIface.IPAddress == "" {
			report.AddFinding(SeverityHigh, Finding{
				Type:           "consistency",
				Title:          "DHCP Enabled Without Interface IP",
				Description:    "DHCP is enabled on LAN interface but the interface has no IP address configured",
				Component:      "dhcpd.lan",
				Recommendation: "Configure LAN interface IP address or disable DHCP service",
			})
		}
	}
}

// checkUserGroupConsistency verifies user and group relationships.
func (p *CoreProcessor) checkUserGroupConsistency(cfg *common.CommonDevice, report *Report) {
	// Build set of existing groups
	existingGroups := make(map[string]bool)
	for _, group := range cfg.Groups {
		existingGroups[group.Name] = true
	}

	// Check if users reference existing groups
	for i, user := range cfg.Users {
		if user.GroupName != "" && !existingGroups[user.GroupName] {
			report.AddFinding(SeverityMedium, Finding{
				Type:  "consistency",
				Title: "User References Non-existent Group",
				Description: fmt.Sprintf(
					"User %s references group %s which does not exist",
					user.Name,
					user.GroupName,
				),
				Component:      fmt.Sprintf("system.user[%d].groupname", i),
				Recommendation: "Create the referenced group or update user's group assignment",
			})
		}
	}
}

// analyzeSecurityIssues performs security-focused analysis.
func (p *CoreProcessor) analyzeSecurityIssues(cfg *common.CommonDevice, report *Report) {
	// WebGUI configuration — only flag non-HTTPS protocols
	if cfg.System.WebGUI.Protocol != "" && cfg.System.WebGUI.Protocol != constants.ProtocolHTTPS {
		report.AddFinding(SeverityCritical, Finding{
			Type:           constants.FindingTypeSecurity,
			Title:          "Insecure Web GUI Protocol",
			Description:    "Web GUI is configured to use HTTP instead of HTTPS",
			Component:      "system.webgui.protocol",
			Recommendation: "Change web GUI protocol to HTTPS for secure administration",
			Reference:      "HTTPS provides encryption for administrative access",
		})
	}

	// Check for default SNMP community strings
	if cfg.SNMP.ROCommunity == "public" {
		report.AddFinding(SeverityHigh, Finding{
			Type:           constants.FindingTypeSecurity,
			Title:          "Default SNMP Community String",
			Description:    "SNMP is using the default 'public' community string",
			Component:      "snmpd.rocommunity",
			Recommendation: "Change SNMP community string to a secure, non-default value",
			Reference:      "Default community strings are well-known and pose security risks",
		})
	}

	// Check for overly permissive firewall rules
	for i, rule := range cfg.FirewallRules {
		if rule.Type == constants.RuleTypePass && rule.Source.Address == constants.NetworkAny &&
			slices.Contains(rule.Interfaces, "wan") {
			report.AddFinding(SeverityHigh, Finding{
				Type:           constants.FindingTypeSecurity,
				Title:          "Overly Permissive WAN Rule",
				Description:    fmt.Sprintf("Rule %d allows any source to pass traffic on WAN interface", i+1),
				Component:      fmt.Sprintf("filter.rule[%d]", i),
				Recommendation: "Restrict source networks or add specific destination restrictions",
				Reference:      "WAN interfaces should have restrictive inbound rules",
			})
		}
	}
}

// analyzePerformanceIssues performs performance-focused analysis.
func (p *CoreProcessor) analyzePerformanceIssues(cfg *common.CommonDevice, report *Report) {
	// Check for suboptimal hardware settings
	if cfg.System.DisableChecksumOffloading {
		report.AddFinding(SeverityLow, Finding{
			Type:           "performance",
			Title:          "Checksum Offloading Disabled",
			Description:    "Hardware checksum offloading is disabled, which may impact performance",
			Component:      "system.disablechecksumoffloading",
			Recommendation: "Enable checksum offloading unless experiencing specific hardware issues",
			Reference:      "Hardware offloading can improve network performance",
		})
	}

	if cfg.System.DisableSegmentationOffloading {
		report.AddFinding(SeverityLow, Finding{
			Type:           "performance",
			Title:          "Segmentation Offloading Disabled",
			Description:    "Hardware segmentation offloading is disabled, which may impact performance",
			Component:      "system.disablesegmentationoffloading",
			Recommendation: "Enable segmentation offloading unless experiencing specific hardware issues",
			Reference:      "Hardware offloading can improve network throughput",
		})
	}

	// Check for excessive firewall rules
	ruleCount := len(cfg.FirewallRules)
	if ruleCount > constants.LargeRuleCountThreshold {
		report.AddFinding(SeverityMedium, Finding{
			Type:  "performance",
			Title: "High Number of Firewall Rules",
			Description: fmt.Sprintf(
				"Configuration contains %d firewall rules, which may impact performance",
				ruleCount,
			),
			Component:      "filter.rule",
			Recommendation: "Consider consolidating rules or using aliases to reduce rule count",
			Reference:      "Large numbers of firewall rules can impact packet processing performance",
		})
	}
}
