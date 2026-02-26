package converter

import (
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/EvilBit-Labs/opnDossier/internal/constants"
	"github.com/EvilBit-Labs/opnDossier/internal/model/common"
)

// findCommonInterface returns the interface with the given name, or nil if not found.
func findCommonInterface(interfaces []common.Interface, name string) *common.Interface {
	for i := range interfaces {
		if interfaces[i].Name == name {
			return &interfaces[i]
		}
	}
	return nil
}

// findCommonDHCPScope returns the DHCP scope for the given interface, or nil if not found.
func findCommonDHCPScope(scopes []common.DHCPScope, ifaceName string) *common.DHCPScope {
	for i := range scopes {
		if scopes[i].Interface == ifaceName {
			return &scopes[i]
		}
	}
	return nil
}

// computeStatistics analyzes a device configuration and returns aggregated statistics
// using the common.Statistics type suitable for serialization in JSON/YAML exports.
func computeStatistics(cfg *common.CommonDevice) *common.Statistics {
	stats := &common.Statistics{
		InterfacesByType: make(map[string]int),
		InterfaceDetails: []common.InterfaceStatistics{},
		RulesByInterface: make(map[string]int),
		RulesByType:      make(map[string]int),
		DHCPScopeDetails: []common.DHCPScopeStatistics{},
		UsersByScope:     make(map[string]int),
		GroupsByScope:    make(map[string]int),
		EnabledServices:  []string{},
		ServiceDetails:   []common.ServiceStatistics{},
		SecurityFeatures: []string{},
	}

	// Interface statistics
	stats.TotalInterfaces = len(cfg.Interfaces)
	for _, iface := range cfg.Interfaces {
		stats.InterfacesByType[iface.Type]++

		dhcpScope := findCommonDHCPScope(cfg.DHCP, iface.Name)
		ifStats := common.InterfaceStatistics{
			Name:        iface.Name,
			Type:        iface.Type,
			Enabled:     iface.Enabled,
			HasIPv4:     iface.IPAddress != "",
			HasIPv6:     iface.IPv6Address != "",
			HasDHCP:     dhcpScope != nil && dhcpScope.Enabled,
			BlockPriv:   iface.BlockPrivate,
			BlockBogons: iface.BlockBogons,
		}
		stats.InterfaceDetails = append(stats.InterfaceDetails, ifStats)
	}

	// Network infrastructure statistics
	stats.TotalVLANs = len(cfg.VLANs)
	stats.TotalBridges = len(cfg.Bridges)
	stats.TotalCertificates = len(cfg.Certificates)
	stats.TotalCAs = len(cfg.CAs)

	// Firewall rule statistics
	stats.TotalFirewallRules = len(cfg.FirewallRules)
	for _, rule := range cfg.FirewallRules {
		for _, iface := range rule.Interfaces {
			stats.RulesByInterface[iface]++
		}
		stats.RulesByType[rule.Type]++
	}

	// NAT statistics
	stats.NATMode = cfg.NAT.OutboundMode
	stats.NATEntries = len(cfg.NAT.OutboundRules) + len(cfg.NAT.InboundRules)

	// Gateway statistics
	stats.TotalGateways = len(cfg.Routing.Gateways)
	stats.TotalGatewayGroups = len(cfg.Routing.GatewayGroups)

	// DHCP statistics
	dhcpScopes := 0
	for _, scope := range cfg.DHCP {
		if scope.Enabled {
			dhcpScopes++
			stats.DHCPScopeDetails = append(stats.DHCPScopeDetails, common.DHCPScopeStatistics{
				Interface: scope.Interface,
				Enabled:   true,
				From:      scope.Range.From,
				To:        scope.Range.To,
			})
		}
	}
	stats.DHCPScopes = dhcpScopes

	// User and group statistics
	stats.TotalUsers = len(cfg.Users)
	stats.TotalGroups = len(cfg.Groups)
	for _, user := range cfg.Users {
		stats.UsersByScope[user.Scope]++
	}
	for _, group := range cfg.Groups {
		stats.GroupsByScope[group.Scope]++
	}

	// Service statistics
	serviceCount := 0

	for _, scope := range cfg.DHCP {
		if scope.Enabled {
			serviceName := fmt.Sprintf("DHCP Server (%s)", strings.ToUpper(scope.Interface))
			stats.EnabledServices = append(stats.EnabledServices, serviceName)
			stats.ServiceDetails = append(stats.ServiceDetails, common.ServiceStatistics{
				Name:    serviceName,
				Enabled: true,
				Details: map[string]string{
					"interface": scope.Interface,
					"from":      scope.Range.From,
					"to":        scope.Range.To,
				},
			})
			serviceCount++
		}
	}

	if cfg.DNS.Unbound.Enabled {
		stats.EnabledServices = append(stats.EnabledServices, "Unbound DNS Resolver")
		stats.ServiceDetails = append(stats.ServiceDetails, common.ServiceStatistics{
			Name:    "Unbound DNS Resolver",
			Enabled: true,
		})
		serviceCount++
	}

	if cfg.SNMP.ROCommunity != "" {
		stats.EnabledServices = append(stats.EnabledServices, "SNMP Daemon")
		stats.ServiceDetails = append(stats.ServiceDetails, common.ServiceStatistics{
			Name:    "SNMP Daemon",
			Enabled: true,
			Details: map[string]string{
				"location":  cfg.SNMP.SysLocation,
				"contact":   cfg.SNMP.SysContact,
				"community": "[REDACTED]",
			},
		})
		serviceCount++
	}

	if cfg.System.SSH.Group != "" {
		stats.EnabledServices = append(stats.EnabledServices, "SSH Daemon")
		stats.ServiceDetails = append(stats.ServiceDetails, common.ServiceStatistics{
			Name:    "SSH Daemon",
			Enabled: true,
			Details: map[string]string{
				"group": cfg.System.SSH.Group,
			},
		})
		serviceCount++
	}

	if cfg.NTP.PreferredServer != "" {
		stats.EnabledServices = append(stats.EnabledServices, "NTP Daemon")
		stats.ServiceDetails = append(stats.ServiceDetails, common.ServiceStatistics{
			Name:    "NTP Daemon",
			Enabled: true,
			Details: map[string]string{
				"prefer": cfg.NTP.PreferredServer,
			},
		})
		serviceCount++
	}

	stats.TotalServices = serviceCount

	// System configuration statistics
	stats.SysctlSettings = len(cfg.Sysctl)
	stats.LoadBalancerMonitors = len(cfg.LoadBalancer.MonitorTypes)

	// Security features detection
	wan := findCommonInterface(cfg.Interfaces, "wan")
	if wan != nil {
		if wan.BlockPrivate {
			stats.SecurityFeatures = append(stats.SecurityFeatures, "Block Private Networks")
		}
		if wan.BlockBogons {
			stats.SecurityFeatures = append(stats.SecurityFeatures, "Block Bogon Networks")
		}
	}

	if cfg.System.WebGUI.Protocol == constants.ProtocolHTTPS {
		stats.SecurityFeatures = append(stats.SecurityFeatures, "HTTPS Web GUI")
	}

	if cfg.System.DisableNATReflection {
		stats.SecurityFeatures = append(stats.SecurityFeatures, "NAT Reflection Disabled")
	}

	// Calculate summary statistics
	securityScore := computeSecurityScore(cfg, stats)
	configComplexity := computeConfigComplexity(stats)

	stats.Summary = common.StatisticsSummary{
		TotalConfigItems:    computeTotalConfigItems(stats),
		SecurityScore:       securityScore,
		ConfigComplexity:    configComplexity,
		HasSecurityFeatures: len(stats.SecurityFeatures) > 0,
	}

	return stats
}

// computeTotalConfigItems calculates the total number of configuration items
// by summing all relevant components.
func computeTotalConfigItems(stats *common.Statistics) int {
	return stats.TotalInterfaces + stats.TotalFirewallRules + stats.TotalUsers + stats.TotalGroups +
		stats.TotalServices + stats.TotalGateways + stats.TotalGatewayGroups + stats.SysctlSettings +
		stats.DHCPScopes + stats.LoadBalancerMonitors +
		stats.TotalVLANs + stats.TotalBridges + stats.TotalCertificates + stats.TotalCAs
}

// computeSecurityScore returns a security score based on detected security features,
// firewall rules, HTTPS Web GUI usage, and SSH group configuration.
func computeSecurityScore(cfg *common.CommonDevice, stats *common.Statistics) int {
	score := 0

	// Security features contribute to score
	score += len(stats.SecurityFeatures) * constants.SecurityFeatureMultiplier

	// Firewall rules indicate active security configuration
	if stats.TotalFirewallRules > 0 {
		score += 20
	}

	// HTTPS web interface
	if cfg.System.WebGUI.Protocol == constants.ProtocolHTTPS {
		score += 15
	}

	// SSH configuration
	if cfg.System.SSH.Group != "" {
		score += 10
	}

	// IDS/IPS configuration
	if cfg.IDS != nil && cfg.IDS.Enabled {
		score += 15
		if cfg.IDS.IPSMode {
			score += 10
		}
	}

	// Cap at MaxSecurityScore
	if score > constants.MaxSecurityScore {
		score = constants.MaxSecurityScore
	}

	return score
}

// computeConfigComplexity returns a normalized complexity score for the configuration
// based on weighted counts of various configuration elements.
func computeConfigComplexity(stats *common.Statistics) int {
	complexity := 0

	complexity += stats.TotalInterfaces * constants.InterfaceComplexityWeight
	complexity += stats.TotalFirewallRules * constants.FirewallRuleComplexityWeight
	complexity += stats.TotalUsers * constants.UserComplexityWeight
	complexity += stats.TotalGroups * constants.GroupComplexityWeight
	complexity += stats.SysctlSettings * constants.SysctlComplexityWeight
	complexity += stats.TotalServices * constants.ServiceComplexityWeight
	complexity += stats.DHCPScopes * constants.DHCPComplexityWeight
	complexity += stats.LoadBalancerMonitors * constants.LoadBalancerComplexityWeight
	complexity += stats.TotalGateways * constants.GatewayComplexityWeight
	complexity += stats.TotalGatewayGroups * constants.GatewayGroupComplexityWeight

	// Normalize to 0-100 scale
	normalizedComplexity := min(
		(complexity*constants.MaxComplexityScore)/constants.MaxReasonableComplexity,
		constants.MaxComplexityScore,
	)

	return normalizedComplexity
}

// computeAnalysis performs lightweight analysis of the device configuration and returns
// an Analysis suitable for serialization in JSON/YAML exports. This provides analysis
// similar to, but independent of, the processor's logic, populating common.Analysis
// finding types instead of processor.Report.
func computeAnalysis(cfg *common.CommonDevice) *common.Analysis {
	analysis := &common.Analysis{}

	analyzeDeadRulesForExport(cfg, analysis)
	analyzeUnusedInterfacesForExport(cfg, analysis)
	analyzeSecurityIssuesForExport(cfg, analysis)
	analyzePerformanceIssuesForExport(cfg, analysis)
	analyzeConsistencyForExport(cfg, analysis)

	return analysis
}

// analyzeDeadRulesForExport detects unreachable and duplicate firewall rules.
func analyzeDeadRulesForExport(cfg *common.CommonDevice, analysis *common.Analysis) {
	if len(cfg.FirewallRules) == 0 {
		return
	}

	// Group rules by interface.
	interfaceRules := make(map[string][]indexedRule)
	for i, rule := range cfg.FirewallRules {
		for _, iface := range rule.Interfaces {
			interfaceRules[iface] = append(interfaceRules[iface], indexedRule{index: i, rule: rule})
		}
	}

	for _, iface := range slices.Sorted(maps.Keys(interfaceRules)) {
		rules := interfaceRules[iface]
		for i, ir := range rules {
			// Block-all makes subsequent rules unreachable.
			srcAny := ir.rule.Source.Address == constants.NetworkAny
			dstAny := ir.rule.Destination.Address == constants.NetworkAny
			if ir.rule.Type == "block" && srcAny && dstAny && i < len(rules)-1 {
				analysis.DeadRules = append(analysis.DeadRules, common.DeadRuleFinding{
					RuleIndex: ir.index,
					Interface: iface,
					Description: fmt.Sprintf(
						"Rules after position %d on interface %s are unreachable due to preceding block-all rule",
						ir.index+1, iface,
					),
					Recommendation: "Remove unreachable rules or reorder them before the block-all rule",
				})
			}

			// Duplicate detection.
			for j := i + 1; j < len(rules); j++ {
				if rulesEquivalent(ir.rule, rules[j].rule) {
					analysis.DeadRules = append(analysis.DeadRules, common.DeadRuleFinding{
						RuleIndex: rules[j].index,
						Interface: iface,
						Description: fmt.Sprintf(
							"Rule at position %d is duplicate of rule at position %d on interface %s",
							rules[j].index+1, ir.index+1, iface,
						),
						Recommendation: "Remove duplicate rule to simplify configuration",
					})
				}
			}
		}
	}
}

// indexedRule pairs a firewall rule with its original index in the flat rule list.
type indexedRule struct {
	index int
	rule  common.FirewallRule
}

// rulesEquivalent checks if two firewall rules are functionally equivalent.
func rulesEquivalent(a, b common.FirewallRule) bool {
	if a.Type != b.Type || a.IPProtocol != b.IPProtocol ||
		strings.Join(a.Interfaces, ",") != strings.Join(b.Interfaces, ",") {
		return false
	}
	if a.StateType != b.StateType || a.Direction != b.Direction ||
		a.Protocol != b.Protocol || a.Quick != b.Quick {
		return false
	}
	if a.Source.Address != b.Source.Address ||
		a.Source.Port != b.Source.Port ||
		a.Source.Negated != b.Source.Negated {
		return false
	}
	return a.Destination.Address == b.Destination.Address &&
		a.Destination.Port == b.Destination.Port &&
		a.Destination.Negated == b.Destination.Negated
}

// analyzeUnusedInterfacesForExport detects enabled interfaces not used in rules or services.
func analyzeUnusedInterfacesForExport(cfg *common.CommonDevice, analysis *common.Analysis) {
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

	for _, iface := range cfg.Interfaces {
		if iface.Enabled && !used[iface.Name] {
			analysis.UnusedInterfaces = append(analysis.UnusedInterfaces, common.UnusedInterfaceFinding{
				InterfaceName: iface.Name,
				Description: fmt.Sprintf(
					"Interface %s is enabled but not used in any rules or services",
					strings.ToUpper(iface.Name),
				),
				Recommendation: "Consider disabling unused interface or add appropriate rules",
			})
		}
	}
}

// analyzeSecurityIssuesForExport detects security configuration issues.
func analyzeSecurityIssuesForExport(cfg *common.CommonDevice, analysis *common.Analysis) {
	if cfg.System.WebGUI.Protocol != "" && cfg.System.WebGUI.Protocol != constants.ProtocolHTTPS {
		analysis.SecurityIssues = append(analysis.SecurityIssues, common.SecurityFinding{
			Component:      "system.webgui.protocol",
			Issue:          "Insecure Web GUI Protocol",
			Severity:       "critical",
			Description:    "Web GUI is configured to use HTTP instead of HTTPS",
			Recommendation: "Change web GUI protocol to HTTPS for secure administration",
		})
	}

	if cfg.SNMP.ROCommunity == "public" {
		analysis.SecurityIssues = append(analysis.SecurityIssues, common.SecurityFinding{
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
			analysis.SecurityIssues = append(analysis.SecurityIssues, common.SecurityFinding{
				Component:      fmt.Sprintf("filter.rule[%d]", i),
				Issue:          "Overly Permissive WAN Rule",
				Severity:       "high",
				Description:    fmt.Sprintf("Rule %d allows any source to pass traffic on WAN interface", i+1),
				Recommendation: "Restrict source networks or add specific destination restrictions",
			})
		}
	}
}

// analyzePerformanceIssuesForExport detects performance configuration issues.
func analyzePerformanceIssuesForExport(cfg *common.CommonDevice, analysis *common.Analysis) {
	if cfg.System.DisableChecksumOffloading {
		analysis.PerformanceIssues = append(analysis.PerformanceIssues, common.PerformanceFinding{
			Component:      "system.disablechecksumoffloading",
			Issue:          "Checksum Offloading Disabled",
			Severity:       "low",
			Description:    "Hardware checksum offloading is disabled, which may impact performance",
			Recommendation: "Enable checksum offloading unless experiencing specific hardware issues",
		})
	}

	if cfg.System.DisableSegmentationOffloading {
		analysis.PerformanceIssues = append(analysis.PerformanceIssues, common.PerformanceFinding{
			Component:      "system.disablesegmentationoffloading",
			Issue:          "Segmentation Offloading Disabled",
			Severity:       "low",
			Description:    "Hardware segmentation offloading is disabled, which may impact performance",
			Recommendation: "Enable segmentation offloading unless experiencing specific hardware issues",
		})
	}

	if len(cfg.FirewallRules) > constants.LargeRuleCountThreshold {
		analysis.PerformanceIssues = append(analysis.PerformanceIssues, common.PerformanceFinding{
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
}

// analyzeConsistencyForExport detects configuration consistency issues.
func analyzeConsistencyForExport(cfg *common.CommonDevice, analysis *common.Analysis) {
	// Gateway format consistency.
	for _, iface := range cfg.Interfaces {
		if iface.Gateway != "" && iface.IPAddress != "" && iface.Subnet != "" {
			if !strings.Contains(iface.Gateway, ".") {
				analysis.ConsistencyIssues = append(analysis.ConsistencyIssues, common.ConsistencyFinding{
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
	lanDHCP := findCommonDHCPScope(cfg.DHCP, "lan")
	if lanDHCP != nil && lanDHCP.Enabled && lanDHCP.Range.From != "" && lanDHCP.Range.To != "" {
		lanIface := findCommonInterface(cfg.Interfaces, "lan")
		if lanIface != nil && lanIface.IPAddress == "" {
			analysis.ConsistencyIssues = append(analysis.ConsistencyIssues, common.ConsistencyFinding{
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
			analysis.ConsistencyIssues = append(analysis.ConsistencyIssues, common.ConsistencyFinding{
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
}

// computeSecurityAssessment populates a SecurityAssessment from the already-computed statistics.
func computeSecurityAssessment(stats *common.Statistics) *common.SecurityAssessment {
	return &common.SecurityAssessment{
		OverallScore:     stats.Summary.SecurityScore,
		SecurityFeatures: stats.SecurityFeatures,
	}
}

// computePerformanceMetrics populates PerformanceMetrics from the already-computed statistics.
func computePerformanceMetrics(stats *common.Statistics) *common.PerformanceMetrics {
	return &common.PerformanceMetrics{
		ConfigComplexity: stats.Summary.ConfigComplexity,
	}
}

// redactedValue is the placeholder for sensitive fields in exported output.
const redactedValue = "[REDACTED]"

// prepareForExport returns a shallow copy of the device with default DeviceType,
// Statistics, Analysis, SecurityAssessment, and PerformanceMetrics populated when absent.
// Sensitive fields (passwords, private keys, API secrets, SNMP community strings,
// WireGuard PSKs, DHCPv6 authentication secrets) are redacted.
//
// NOTE: computeStatistics and computeAnalysis intentionally receive the original
// unredacted data so that presence checks (e.g., "is SNMP configured?") see real
// values. Their outputs never include raw secret values — any sensitive data in
// statistics output is independently redacted (e.g., SNMP community in ServiceDetails).
func prepareForExport(data *common.CommonDevice) *common.CommonDevice {
	cp := *data

	if cp.DeviceType == "" {
		cp.DeviceType = common.DeviceTypeOPNsense
	}

	redactSensitiveFields(&cp)

	if cp.Statistics == nil {
		cp.Statistics = computeStatistics(data)
	}

	if cp.Analysis == nil {
		cp.Analysis = computeAnalysis(data)
	}

	if cp.SecurityAssessment == nil {
		cp.SecurityAssessment = computeSecurityAssessment(cp.Statistics)
	}

	if cp.PerformanceMetrics == nil {
		cp.PerformanceMetrics = computePerformanceMetrics(cp.Statistics)
	}

	return &cp
}

// redactSensitiveFields replaces sensitive field values with a redaction marker.
// This must be called on the shallow copy, not the original, to avoid mutating
// the caller's data. Slice fields that contain sensitive data are deep-copied
// before redaction.
//
// SECURITY NOTE: The following sensitive fields are already excluded by the converter's
// field mapping and never appear in CommonDevice:
//   - OpenVPN TLS keys (schema.OpenVPNServer.TLS, schema.OpenVPNSystem.StaticKeys)
//   - IPsec pre-shared keys (schema.IPsec.PreSharedKeys)
//   - Certificate authority private keys
//   - WireGuard private keys (only public keys are mapped; PSKs are mapped but redacted below)
//
// If new secret fields are added to common.*, they MUST be added here.
func redactSensitiveFields(cp *common.CommonDevice) {
	// HA password
	if cp.HighAvailability.Password != "" {
		cp.HighAvailability.Password = redactedValue
	}

	// Certificate private keys
	if len(cp.Certificates) > 0 {
		cp.Certificates = slices.Clone(cp.Certificates)
		for i := range cp.Certificates {
			if cp.Certificates[i].PrivateKey != "" {
				cp.Certificates[i].PrivateKey = redactedValue
			}
		}
	}

	// API key secrets
	if len(cp.Users) > 0 {
		cp.Users = slices.Clone(cp.Users)
		for i := range cp.Users {
			if len(cp.Users[i].APIKeys) > 0 {
				cp.Users[i].APIKeys = slices.Clone(cp.Users[i].APIKeys)
				for j := range cp.Users[i].APIKeys {
					if cp.Users[i].APIKeys[j].Secret != "" {
						cp.Users[i].APIKeys[j].Secret = redactedValue
					}
				}
			}
		}
	}

	// SNMP community string
	if cp.SNMP.ROCommunity != "" {
		cp.SNMP.ROCommunity = redactedValue
	}

	// WireGuard pre-shared keys
	if len(cp.VPN.WireGuard.Clients) > 0 {
		cp.VPN.WireGuard.Clients = slices.Clone(cp.VPN.WireGuard.Clients)
		for i := range cp.VPN.WireGuard.Clients {
			if cp.VPN.WireGuard.Clients[i].PSK != "" {
				cp.VPN.WireGuard.Clients[i].PSK = redactedValue
			}
		}
	}

	// DHCPv6 authentication secrets
	if len(cp.DHCP) > 0 {
		cp.DHCP = slices.Clone(cp.DHCP)
		for i := range cp.DHCP {
			if cp.DHCP[i].AdvDHCP6KeyInfoStatementSecret != "" {
				cp.DHCP[i].AdvDHCP6KeyInfoStatementSecret = redactedValue
			}
		}
	}
}
