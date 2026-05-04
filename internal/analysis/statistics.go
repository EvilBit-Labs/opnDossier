package analysis

import (
	"fmt"
	"slices"
	"strings"

	"github.com/EvilBit-Labs/opnDossier/internal/constants"
	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
)

// ServiceNameSNMP is the display name for the SNMP service in statistics.
const ServiceNameSNMP = "SNMP Daemon"

// ComputeStatistics analyzes a device configuration and returns aggregated statistics
// using the common.Statistics type suitable for serialization in JSON/YAML exports.
// A nil cfg returns an initialized but empty Statistics.
func ComputeStatistics(cfg *common.CommonDevice) *common.Statistics {
	stats := newStatistics()
	if cfg == nil {
		return stats
	}

	populateInterfaceStats(stats, cfg)
	populateInfrastructureStats(stats, cfg)
	populateFirewallStats(stats, cfg)
	populateNATAndRoutingStats(stats, cfg)
	populateDHCPStats(stats, cfg)
	populateUserGroupStats(stats, cfg)
	populateServiceStats(stats, cfg)
	populateSystemStats(stats, cfg)
	populateSecurityFeatures(stats, cfg)
	sortStatisticsLists(stats)
	finalizeStatisticsSummary(stats, cfg)

	return stats
}

// newStatistics returns a fully-initialized (but empty) Statistics value.
// Factored out so the nil-cfg early return and the populated path both share
// the same initializer — any new map/slice added here is guaranteed to be
// non-nil on both paths.
//
// The maps intentionally use the no-hint form; pre-sizing with
// len(cfg.Interfaces) was measured to regress the common 3-30
// interface case. See BenchmarkComputeStatistics for the rationale.
func newStatistics() *common.Statistics {
	return &common.Statistics{
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
}

func populateInterfaceStats(stats *common.Statistics, cfg *common.CommonDevice) {
	stats.TotalInterfaces = len(cfg.Interfaces)
	for _, iface := range cfg.Interfaces {
		stats.InterfacesByType[iface.Type]++
		dhcpScope := FindDHCPScope(cfg.DHCP, iface.Name)
		stats.InterfaceDetails = append(stats.InterfaceDetails, common.InterfaceStatistics{
			Name:        iface.Name,
			Type:        iface.Type,
			Enabled:     iface.Enabled,
			HasIPv4:     iface.IPAddress != "",
			HasIPv6:     iface.IPv6Address != "",
			HasDHCP:     dhcpScope != nil && dhcpScope.Enabled,
			BlockPriv:   iface.BlockPrivate,
			BlockBogons: iface.BlockBogons,
		})
	}
}

func populateInfrastructureStats(stats *common.Statistics, cfg *common.CommonDevice) {
	stats.TotalVLANs = len(cfg.VLANs)
	stats.TotalBridges = len(cfg.Bridges)
	stats.TotalCertificates = len(cfg.Certificates)
	stats.TotalCAs = len(cfg.CAs)
}

func populateFirewallStats(stats *common.Statistics, cfg *common.CommonDevice) {
	stats.TotalFirewallRules = len(cfg.FirewallRules)
	for _, rule := range cfg.FirewallRules {
		for _, iface := range rule.Interfaces {
			stats.RulesByInterface[iface]++
		}
		stats.RulesByType[string(rule.Type)]++
	}
}

func populateNATAndRoutingStats(stats *common.Statistics, cfg *common.CommonDevice) {
	stats.NATMode = cfg.NAT.OutboundMode
	stats.NATEntries = len(cfg.NAT.OutboundRules) + len(cfg.NAT.InboundRules)
	stats.TotalGateways = len(cfg.Routing.Gateways)
	stats.TotalGatewayGroups = len(cfg.Routing.GatewayGroups)
}

func populateDHCPStats(stats *common.Statistics, cfg *common.CommonDevice) {
	dhcpScopes := 0
	for _, scope := range cfg.DHCP {
		if !scope.Enabled {
			continue
		}
		dhcpScopes++
		stats.DHCPScopeDetails = append(stats.DHCPScopeDetails, common.DHCPScopeStatistics{
			Interface: scope.Interface,
			Enabled:   true,
			From:      scope.Range.From,
			To:        scope.Range.To,
		})
	}
	stats.DHCPScopes = dhcpScopes
}

func populateUserGroupStats(stats *common.Statistics, cfg *common.CommonDevice) {
	stats.TotalUsers = len(cfg.Users)
	stats.TotalGroups = len(cfg.Groups)
	for _, user := range cfg.Users {
		stats.UsersByScope[user.Scope]++
	}
	for _, group := range cfg.Groups {
		stats.GroupsByScope[group.Scope]++
	}
}

func populateServiceStats(stats *common.Statistics, cfg *common.CommonDevice) {
	serviceCount := 0
	for _, scope := range cfg.DHCP {
		if !scope.Enabled {
			continue
		}
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

	if cfg.DNS.Unbound.Enabled {
		stats.EnabledServices = append(stats.EnabledServices, "Unbound DNS Resolver")
		stats.ServiceDetails = append(stats.ServiceDetails, common.ServiceStatistics{
			Name:    "Unbound DNS Resolver",
			Enabled: true,
		})
		serviceCount++
	}

	if cfg.SNMP.ROCommunity != "" {
		stats.EnabledServices = append(stats.EnabledServices, ServiceNameSNMP)
		stats.ServiceDetails = append(stats.ServiceDetails, common.ServiceStatistics{
			Name:    ServiceNameSNMP,
			Enabled: true,
			Details: map[string]string{
				"location":  cfg.SNMP.SysLocation,
				"contact":   cfg.SNMP.SysContact,
				"community": cfg.SNMP.ROCommunity,
			},
		})
		serviceCount++
	}

	if cfg.System.SSH.Group != "" {
		stats.EnabledServices = append(stats.EnabledServices, "SSH Daemon")
		stats.ServiceDetails = append(stats.ServiceDetails, common.ServiceStatistics{
			Name:    "SSH Daemon",
			Enabled: true,
			Details: map[string]string{"group": cfg.System.SSH.Group},
		})
		serviceCount++
	}

	if cfg.NTP.PreferredServer != "" {
		stats.EnabledServices = append(stats.EnabledServices, "NTP Daemon")
		stats.ServiceDetails = append(stats.ServiceDetails, common.ServiceStatistics{
			Name:    "NTP Daemon",
			Enabled: true,
			Details: map[string]string{"prefer": cfg.NTP.PreferredServer},
		})
		serviceCount++
	}

	stats.TotalServices = serviceCount
}

func populateSystemStats(stats *common.Statistics, cfg *common.CommonDevice) {
	stats.SysctlSettings = len(cfg.Sysctl)
	stats.LoadBalancerMonitors = len(cfg.LoadBalancer.MonitorTypes)
}

func populateSecurityFeatures(stats *common.Statistics, cfg *common.CommonDevice) {
	if wan := FindInterface(cfg.Interfaces, "wan"); wan != nil {
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
}

// sortStatisticsLists enforces deterministic ordering on every slice-typed
// field so JSON/YAML exports are byte-stable across runs.
func sortStatisticsLists(stats *common.Statistics) {
	slices.Sort(stats.EnabledServices)
	slices.Sort(stats.SecurityFeatures)
	slices.SortFunc(stats.InterfaceDetails, func(a, b common.InterfaceStatistics) int {
		return strings.Compare(a.Name, b.Name)
	})
	slices.SortFunc(stats.ServiceDetails, func(a, b common.ServiceStatistics) int {
		return strings.Compare(a.Name, b.Name)
	})
	slices.SortFunc(stats.DHCPScopeDetails, func(a, b common.DHCPScopeStatistics) int {
		return strings.Compare(a.Interface, b.Interface)
	})
}

func finalizeStatisticsSummary(stats *common.Statistics, cfg *common.CommonDevice) {
	stats.Summary = common.StatisticsSummary{
		TotalConfigItems:    ComputeTotalConfigItems(stats),
		SecurityScore:       ComputeSecurityScore(cfg, stats),
		ConfigComplexity:    ComputeConfigComplexity(stats),
		HasSecurityFeatures: len(stats.SecurityFeatures) > 0,
	}
}

// ComputeTotalConfigItems calculates the total number of configuration items
// by summing interfaces, rules, users, groups, services, gateways, sysctl,
// DHCP, load balancer, VLANs, bridges, certificates, and CAs.
func ComputeTotalConfigItems(stats *common.Statistics) int {
	if stats == nil {
		return 0
	}

	return stats.TotalInterfaces + stats.TotalFirewallRules + stats.TotalUsers + stats.TotalGroups +
		stats.TotalServices + stats.TotalGateways + stats.TotalGatewayGroups + stats.SysctlSettings +
		stats.DHCPScopes + stats.LoadBalancerMonitors +
		stats.TotalVLANs + stats.TotalBridges + stats.TotalCertificates + stats.TotalCAs
}

// ComputeSecurityScore returns a security score based on detected security features,
// firewall rules, HTTPS Web GUI usage, SSH group configuration, and IDS/IPS enablement.
// The score is capped at MaxSecurityScore. Returns 0 when cfg or stats is nil.
func ComputeSecurityScore(cfg *common.CommonDevice, stats *common.Statistics) int {
	if cfg == nil || stats == nil {
		return 0
	}

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

// ComputeConfigComplexity returns a normalized complexity score for the configuration
// based on weighted counts of various configuration elements. Returns 0 when stats is nil.
func ComputeConfigComplexity(stats *common.Statistics) int {
	if stats == nil {
		return 0
	}

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
