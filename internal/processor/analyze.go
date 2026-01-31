package processor

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/EvilBit-Labs/opnDossier/internal/constants"
	"github.com/EvilBit-Labs/opnDossier/internal/model"
)

// interfaceListContains returns true if the interface list contains the given interface name exactly.
func interfaceListContains(list model.InterfaceList, name string) bool {
	return slices.Contains(list, name)
}

// analyze performs comprehensive analysis of the OPNsense configuration based on enabled options.
func (p *CoreProcessor) analyze(_ context.Context, cfg *model.OpnSenseDocument, config *Config, report *Report) {
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
func (p *CoreProcessor) analyzeDeadRules(cfg *model.OpnSenseDocument, report *Report) {
	rules := cfg.FilterRules()
	if len(rules) == 0 {
		return
	}

	// Track rules by interface to detect unreachable rules
	interfaceRules := make(map[string][]model.Rule)
	for _, rule := range rules {
		// Add the rule to each interface it applies to
		for _, iface := range rule.Interface {
			interfaceRules[iface] = append(interfaceRules[iface], rule)
		}
	}

	// Analyze each interface's rules
	for iface, ifaceRules := range interfaceRules {
		p.analyzeInterfaceRules(iface, ifaceRules, report)
	}
}

// analyzeInterfaceRules analyzes rules on a specific interface for dead rules.
func (p *CoreProcessor) analyzeInterfaceRules(iface string, rules []model.Rule, report *Report) {
	for i, rule := range rules {
		// Check for "block all" rules that make subsequent rules unreachable
		if rule.Type == "block" && rule.Source.Network == NetworkAny {
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
		if rule.Type == RuleTypePass && rule.Source.Network == NetworkAny && rule.Descr == "" {
			report.AddFinding(SeverityHigh, Finding{
				Type:  FindingTypeSecurity,
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
// Note: The model.Rule struct is still limited compared to actual OPNsense configurations,
// but comparisons now include state, direction, protocol, quick, and port details where available.
func (p *CoreProcessor) rulesAreEquivalent(rule1, rule2 model.Rule) bool {
	// Compare core rule properties (excluding description as it doesn't affect functionality)
	if rule1.Type != rule2.Type ||
		rule1.IPProtocol != rule2.IPProtocol ||
		rule1.Interface.String() != rule2.Interface.String() {
		return false
	}

	// Compare additional rule behavior fields
	if rule1.StateType != rule2.StateType ||
		rule1.Direction != rule2.Direction ||
		rule1.Protocol != rule2.Protocol ||
		rule1.Quick != rule2.Quick ||
		rule1.SourcePort != rule2.SourcePort {
		return false
	}

	// Compare source configuration
	if rule1.Source.Network != rule2.Source.Network {
		return false
	}

	// Compare destination configuration
	dest1 := p.getDestinationString(rule1.Destination)
	dest2 := p.getDestinationString(rule2.Destination)

	return dest1 == dest2
}

// getDestinationString converts the destination struct to a composite string for comparison.
// This preserves "any" vs explicit network/port values while treating empty fields as equivalent.
// Empty destinations (no Any, no Network, no Port) are treated as "any" for backward compatibility.
func (p *CoreProcessor) getDestinationString(destination model.Destination) string {
	network := ""
	switch {
	case destination.Any != "":
		network = NetworkAny
	case destination.Network != "":
		network = destination.Network
	case destination.Port == "":
		// Empty destination with no explicit fields is treated as "any"
		network = NetworkAny
	}

	return fmt.Sprintf("network:%s|port:%s", network, destination.Port)
}

// markDHCPInterfaces iterates through all DHCP interfaces and marks enabled ones as used.
// An interface is considered enabled if its Enable field is "1" (OPNsense convention:
// Enable="1" means enabled, Enable="" or Enable="0" means disabled).
func markDHCPInterfaces(cfg *model.OpnSenseDocument, used map[string]bool) {
	if cfg.Dhcpd.Items == nil {
		return
	}

	for name, dhcpIface := range cfg.Dhcpd.Items {
		if dhcpIface.Enable == "1" {
			used[name] = true
		}
	}
}

// markDNSInterfaces marks interfaces as used when DNS services are enabled.
// DNS services (Unbound and DNSMasquerade) typically bind to the LAN interface by default,
// so "lan" is marked as used when either service is enabled.
// Note: This is a conservative heuristic; actual interface bindings may vary in custom configurations.
func markDNSInterfaces(cfg *model.OpnSenseDocument, used map[string]bool) {
	// Check if Unbound DNS is enabled (Enable="1" means enabled per OPNsense convention)
	if cfg.Unbound.Enable == "1" {
		used["lan"] = true
	}

	// Check if DNSMasquerade is enabled (Enable is a BoolFlag type, which is bool)
	if cfg.DNSMasquerade.Enable {
		used["lan"] = true
	}
}

// markLoadBalancerInterfaces marks interfaces as used when load balancer is configured.
// Load balancers in OPNsense work through virtual servers (VIPs) and when monitors are configured,
// it indicates active load balancing services which typically serve internal networks.
// Note: Marks "lan" as a conservative heuristic since actual interface bindings depend on VIP configuration.
func markLoadBalancerInterfaces(cfg *model.OpnSenseDocument, used map[string]bool) {
	// Check if load balancer has any monitor types configured
	// Presence of monitors indicates an active load balancer configuration
	if len(cfg.LoadBalancer.MonitorType) > 0 {
		used["lan"] = true
	}
}

// markVPNInterfaces marks interfaces as used when VPN services (OpenVPN or WireGuard) are configured.
// It iterates through OpenVPN servers and clients to mark their bound interfaces,
// and checks if WireGuard is enabled (marking "lan" as the default service interface).
func markVPNInterfaces(cfg *model.OpnSenseDocument, used map[string]bool) {
	// Mark interfaces from OpenVPN servers
	for _, server := range cfg.OpenVPN.Servers {
		if server.Interface != "" {
			used[server.Interface] = true
		}
	}

	// Mark interfaces from OpenVPN clients
	for _, client := range cfg.OpenVPN.Clients {
		if client.Interface != "" {
			used[client.Interface] = true
		}
	}

	// Check WireGuard - if enabled, mark "lan" as the default service interface
	// WireGuard creates virtual tunnel interfaces (wgX), but we mark "lan" because
	// the WireGuard service daemon typically runs on the LAN for management/control.
	// Enabled="1" means enabled per OPNsense convention.
	if cfg.OPNsense.Wireguard != nil && cfg.OPNsense.Wireguard.General.Enabled == "1" {
		used["lan"] = true
	}
}

// analyzeUnusedInterfaces detects interfaces that are defined but not used in rules or services.
func (p *CoreProcessor) analyzeUnusedInterfaces(cfg *model.OpnSenseDocument, report *Report) {
	// Track which interfaces are used
	usedInterfaces := make(map[string]bool)

	// Mark interfaces used in firewall rules
	for _, rule := range cfg.FilterRules() {
		if !rule.Interface.IsEmpty() {
			// Mark all interfaces used by this rule
			for _, iface := range rule.Interface {
				usedInterfaces[iface] = true
			}
		}
	}

	// Mark interfaces used in services (DHCP, DNS, VPN, Load Balancer)
	// Note: Future enhancement could include routing, VLAN, bridge, monitoring, and logging services.
	markDHCPInterfaces(cfg, usedInterfaces)
	markDNSInterfaces(cfg, usedInterfaces)
	markVPNInterfaces(cfg, usedInterfaces)
	markLoadBalancerInterfaces(cfg, usedInterfaces)

	// Check WAN and LAN interfaces
	interfaces := map[string]model.Interface{}
	if wan, ok := cfg.Interfaces.Wan(); ok {
		interfaces["wan"] = wan
	}

	if lan, ok := cfg.Interfaces.Lan(); ok {
		interfaces["lan"] = lan
	}

	for name, iface := range interfaces {
		if iface.Enable != "" && !usedInterfaces[name] {
			report.AddFinding(SeverityLow, Finding{
				Type:  "unused-interface",
				Title: "Unused Network Interface",
				Description: fmt.Sprintf(
					"Interface %s is enabled but not used in any rules or services",
					strings.ToUpper(name),
				),
				Component:      "interfaces." + name,
				Recommendation: "Consider disabling unused interface or add appropriate rules",
			})
		}
	}
}

// analyzeConsistency performs consistency checks across the configuration.
func (p *CoreProcessor) analyzeConsistency(cfg *model.OpnSenseDocument, report *Report) {
	// Check if gateways referenced in interfaces exist
	p.checkGatewayConsistency(cfg, report)

	// Check DHCP range consistency with interface subnets
	p.checkDHCPConsistency(cfg, report)

	// Check user-group consistency
	p.checkUserGroupConsistency(cfg, report)
}

// checkGatewayConsistency verifies that gateways referenced in interfaces are properly configured.
func (p *CoreProcessor) checkGatewayConsistency(cfg *model.OpnSenseDocument, report *Report) {
	// For now, just check if gateway IPs are valid when specified
	interfaces := map[string]model.Interface{}
	if wan, ok := cfg.Interfaces.Wan(); ok {
		interfaces["wan"] = wan
	}

	if lan, ok := cfg.Interfaces.Lan(); ok {
		interfaces["lan"] = lan
	}

	for name, iface := range interfaces {
		if iface.Gateway != "" && iface.IPAddr != "" && iface.Subnet != "" {
			// Basic consistency check - gateway should be in the same subnet
			// This is a simplified check; real implementation might be more complex
			if !strings.Contains(iface.Gateway, ".") {
				report.AddFinding(SeverityMedium, Finding{
					Type:  "consistency",
					Title: "Invalid Gateway Format",
					Description: fmt.Sprintf(
						"Gateway %s for interface %s appears to be invalid",
						iface.Gateway,
						name,
					),
					Component:      fmt.Sprintf("interfaces.%s.gateway", name),
					Recommendation: "Verify gateway IP address format and reachability",
				})
			}
		}
	}
}

// checkDHCPConsistency verifies DHCP configuration consistency with interface settings.
func (p *CoreProcessor) checkDHCPConsistency(cfg *model.OpnSenseDocument, report *Report) {
	// Check LAN DHCP configuration
	if lanDhcp, exists := cfg.Dhcpd.Lan(); exists && lanDhcp.Enable != "" && lanDhcp.Range.From != "" &&
		lanDhcp.Range.To != "" {
		if lan, ok := cfg.Interfaces.Lan(); ok && lan.IPAddr == "" {
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
func (p *CoreProcessor) checkUserGroupConsistency(cfg *model.OpnSenseDocument, report *Report) {
	// Build set of existing groups
	existingGroups := make(map[string]bool)
	for _, group := range cfg.System.Group {
		existingGroups[group.Name] = true
	}

	// Check if users reference existing groups
	for i, user := range cfg.System.User {
		if user.Groupname != "" && !existingGroups[user.Groupname] {
			report.AddFinding(SeverityMedium, Finding{
				Type:  "consistency",
				Title: "User References Non-existent Group",
				Description: fmt.Sprintf(
					"User %s references group %s which does not exist",
					user.Name,
					user.Groupname,
				),
				Component:      fmt.Sprintf("system.user[%d].groupname", i),
				Recommendation: "Create the referenced group or update user's group assignment",
			})
		}
	}
}

// analyzeSecurityIssues performs security-focused analysis.
func (p *CoreProcessor) analyzeSecurityIssues(cfg *model.OpnSenseDocument, report *Report) {
	// WebGUI configuration
	if cfg.System.WebGUI.Protocol != "" {
		report.AddFinding(SeverityCritical, Finding{
			Type:           FindingTypeSecurity,
			Title:          "Insecure Web GUI Protocol",
			Description:    "Web GUI is configured to use HTTP instead of HTTPS",
			Component:      "system.webgui.protocol",
			Recommendation: "Change web GUI protocol to HTTPS for secure administration",
			Reference:      "HTTPS provides encryption for administrative access",
		})
	}

	// Check for default SNMP community strings
	if cfg.Snmpd.ROCommunity == "public" {
		report.AddFinding(SeverityHigh, Finding{
			Type:           FindingTypeSecurity,
			Title:          "Default SNMP Community String",
			Description:    "SNMP is using the default 'public' community string",
			Component:      "snmpd.rocommunity",
			Recommendation: "Change SNMP community string to a secure, non-default value",
			Reference:      "Default community strings are well-known and pose security risks",
		})
	}

	// Check for overly permissive firewall rules
	for i, rule := range cfg.FilterRules() {
		if rule.Type == RuleTypePass && rule.Source.Network == NetworkAny &&
			interfaceListContains(rule.Interface, "wan") {
			report.AddFinding(SeverityHigh, Finding{
				Type:           FindingTypeSecurity,
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
func (p *CoreProcessor) analyzePerformanceIssues(cfg *model.OpnSenseDocument, report *Report) {
	// Check for suboptimal hardware settings
	if cfg.System.DisableChecksumOffloading != 0 {
		report.AddFinding(SeverityLow, Finding{
			Type:           "performance",
			Title:          "Checksum Offloading Disabled",
			Description:    "Hardware checksum offloading is disabled, which may impact performance",
			Component:      "system.disablechecksumoffloading",
			Recommendation: "Enable checksum offloading unless experiencing specific hardware issues",
			Reference:      "Hardware offloading can improve network performance",
		})
	}

	if cfg.System.DisableSegmentationOffloading != 0 {
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
	ruleCount := len(cfg.FilterRules())
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
