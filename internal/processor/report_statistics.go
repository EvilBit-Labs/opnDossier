package processor

import (
	"maps"

	"github.com/EvilBit-Labs/opnDossier/internal/analysis"
	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
)

// Statistics contains various statistics about the configuration.
type Statistics struct {
	// Interface statistics
	TotalInterfaces  int                   `json:"totalInterfaces"`
	InterfacesByType map[string]int        `json:"interfacesByType"`
	InterfaceDetails []InterfaceStatistics `json:"interfaceDetails"`

	// Firewall and NAT statistics
	TotalFirewallRules int            `json:"totalFirewallRules"`
	RulesByInterface   map[string]int `json:"rulesByInterface"`
	RulesByType        map[string]int `json:"rulesByType"`
	NATEntries         int            `json:"natEntries"`
	NATMode            string         `json:"natMode"`

	// Gateway statistics
	TotalGateways      int `json:"totalGateways"`
	TotalGatewayGroups int `json:"totalGatewayGroups"`

	// DHCP statistics
	DHCPScopes       int                   `json:"dhcpScopes"`
	DHCPScopeDetails []DHCPScopeStatistics `json:"dhcpScopeDetails"`

	// User and group statistics
	TotalUsers    int            `json:"totalUsers"`
	UsersByScope  map[string]int `json:"usersByScope"`
	TotalGroups   int            `json:"totalGroups"`
	GroupsByScope map[string]int `json:"groupsByScope"`

	// Service statistics
	EnabledServices []string            `json:"enabledServices"`
	TotalServices   int                 `json:"totalServices"`
	ServiceDetails  []ServiceStatistics `json:"serviceDetails"`

	// System configuration statistics
	SysctlSettings       int      `json:"sysctlSettings"`
	LoadBalancerMonitors int      `json:"loadBalancerMonitors"`
	SecurityFeatures     []string `json:"securityFeatures"`

	// IDS/IPS statistics
	IDSEnabled             bool     `json:"idsEnabled"`
	IDSMode                string   `json:"idsMode"`
	IDSMonitoredInterfaces []string `json:"idsMonitoredInterfaces,omitempty"`
	IDSDetectionProfile    string   `json:"idsDetectionProfile,omitempty"`
	IDSLoggingEnabled      bool     `json:"idsLoggingEnabled"`

	// Summary counts for quick reference
	Summary StatisticsSummary `json:"summary"`
}

// InterfaceStatistics contains detailed statistics for a single interface.
type InterfaceStatistics struct {
	Name        string `json:"name"`
	Type        string `json:"type"`
	Enabled     bool   `json:"enabled"`
	HasIPv4     bool   `json:"hasIpv4"`
	HasIPv6     bool   `json:"hasIpv6"`
	HasDHCP     bool   `json:"hasDhcp"`
	BlockPriv   bool   `json:"blockPriv"`
	BlockBogons bool   `json:"blockBogons"`
}

// DHCPScopeStatistics contains statistics for DHCP scopes.
type DHCPScopeStatistics struct {
	Interface string `json:"interface"`
	Enabled   bool   `json:"enabled"`
	From      string `json:"from"`
	To        string `json:"to"`
}

// ServiceStatistics contains statistics for individual services.
type ServiceStatistics struct {
	Name    string            `json:"name"`
	Enabled bool              `json:"enabled"`
	Details map[string]string `json:"details,omitempty"`
}

// StatisticsSummary provides high-level summary statistics.
type StatisticsSummary struct {
	TotalConfigItems    int  `json:"totalConfigItems"`
	SecurityScore       int  `json:"securityScore"`
	ConfigComplexity    int  `json:"configComplexity"`
	HasSecurityFeatures bool `json:"hasSecurityFeatures"`
}

// redactServiceDetails replaces sensitive values in the processor's ServiceDetails
// with the redaction marker. The shared analysis.ComputeStatistics intentionally
// returns raw values so callers can decide on redaction policy; the processor
// always redacts before rendering or serializing.
func redactServiceDetails(stats *Statistics) {
	if stats == nil {
		return
	}

	for i := range stats.ServiceDetails {
		if stats.ServiceDetails[i].Name == analysis.ServiceNameSNMP && stats.ServiceDetails[i].Details != nil {
			if _, ok := stats.ServiceDetails[i].Details["community"]; ok {
				// Deep-copy the map to avoid mutating shared state.
				stats.ServiceDetails[i].Details = maps.Clone(stats.ServiceDetails[i].Details)
				stats.ServiceDetails[i].Details["community"] = redactedValue
			}
		}
	}
}

// generateStatistics analyzes a device configuration and returns aggregated statistics.
// It delegates to analysis.ComputeStatistics for shared logic, translates the result
// into the processor's Statistics type, and adds IDS-specific fields.
func generateStatistics(cfg *common.CommonDevice) *Statistics {
	commonStats := analysis.ComputeStatistics(cfg)
	stats := translateCommonStats(commonStats)

	// IDS/IPS statistics — processor-specific fields not in common.Statistics
	ids := cfg.IDS
	if ids != nil && ids.Enabled {
		stats.IDSEnabled = true
		stats.IDSMonitoredInterfaces = ids.Interfaces
		stats.IDSDetectionProfile = ids.Detect.Profile
		stats.IDSLoggingEnabled = ids.SyslogEnabled || ids.SyslogEveEnabled

		if ids.IPSMode {
			stats.IDSMode = "IPS (Prevention)"
		} else {
			stats.IDSMode = "IDS (Detection Only)"
		}
	}

	// Redact sensitive service details before the report can be rendered or serialized.
	redactServiceDetails(stats)

	return stats
}

// translateCommonStats converts a common.Statistics into a processor.Statistics
// by copying all matching fields. The processor's Statistics type mirrors the
// common type but adds IDS-specific fields.
func translateCommonStats(cs *common.Statistics) *Statistics {
	stats := &Statistics{
		TotalInterfaces:  cs.TotalInterfaces,
		InterfacesByType: cs.InterfacesByType,
		RulesByInterface: cs.RulesByInterface,
		RulesByType:      cs.RulesByType,

		TotalFirewallRules: cs.TotalFirewallRules,
		NATEntries:         cs.NATEntries,
		NATMode:            string(cs.NATMode),

		TotalGateways:      cs.TotalGateways,
		TotalGatewayGroups: cs.TotalGatewayGroups,

		DHCPScopes: cs.DHCPScopes,

		TotalUsers:    cs.TotalUsers,
		UsersByScope:  cs.UsersByScope,
		TotalGroups:   cs.TotalGroups,
		GroupsByScope: cs.GroupsByScope,

		EnabledServices: cs.EnabledServices,
		TotalServices:   cs.TotalServices,

		SysctlSettings:       cs.SysctlSettings,
		LoadBalancerMonitors: cs.LoadBalancerMonitors,
		SecurityFeatures:     cs.SecurityFeatures,

		Summary: StatisticsSummary{
			TotalConfigItems:    cs.Summary.TotalConfigItems,
			SecurityScore:       cs.Summary.SecurityScore,
			ConfigComplexity:    cs.Summary.ConfigComplexity,
			HasSecurityFeatures: cs.Summary.HasSecurityFeatures,
		},
	}

	// Translate InterfaceDetails
	stats.InterfaceDetails = make([]InterfaceStatistics, len(cs.InterfaceDetails))
	for i, d := range cs.InterfaceDetails {
		stats.InterfaceDetails[i] = InterfaceStatistics{
			Name:        d.Name,
			Type:        d.Type,
			Enabled:     d.Enabled,
			HasIPv4:     d.HasIPv4,
			HasIPv6:     d.HasIPv6,
			HasDHCP:     d.HasDHCP,
			BlockPriv:   d.BlockPriv,
			BlockBogons: d.BlockBogons,
		}
	}

	// Translate DHCPScopeDetails
	stats.DHCPScopeDetails = make([]DHCPScopeStatistics, len(cs.DHCPScopeDetails))
	for i, d := range cs.DHCPScopeDetails {
		stats.DHCPScopeDetails[i] = DHCPScopeStatistics{
			Interface: d.Interface,
			Enabled:   d.Enabled,
			From:      d.From,
			To:        d.To,
		}
	}

	// Translate ServiceDetails
	stats.ServiceDetails = make([]ServiceStatistics, len(cs.ServiceDetails))
	for i, d := range cs.ServiceDetails {
		stats.ServiceDetails[i] = ServiceStatistics{
			Name:    d.Name,
			Enabled: d.Enabled,
			Details: d.Details,
		}
	}

	return stats
}
