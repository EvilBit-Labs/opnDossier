package processor

import (
	"net"
	"sort"
	"strings"

	"github.com/unclesp1d3r/opnFocus/internal/model"
)

// normalize normalizes the given OPNsense configuration by filling defaults, canonicalizing IP/CIDR, and sorting slices for determinism.
func (p *CoreProcessor) normalize(cfg *model.Opnsense) *model.Opnsense {
	// Create a copy to avoid modifying the original
	normalized := *cfg

	// Phase 1: Fill defaults
	p.fillDefaults(&normalized)

	// Phase 2: Canonicalize IP addresses and CIDR notation
	p.canonicalizeAddresses(&normalized)

	// Phase 3: Sort slices for determinism
	p.sortSlices(&normalized)

	return &normalized
}

// fillDefaults fills in default values for missing configuration elements.
func (p *CoreProcessor) fillDefaults(cfg *model.Opnsense) {
	// Fill system defaults
	if cfg.System.Optimization == "" {
		cfg.System.Optimization = "normal"
	}
	if cfg.System.Webgui.Protocol == "" {
		cfg.System.Webgui.Protocol = ProtocolHTTPS
	}
	if cfg.System.Timezone == "" {
		cfg.System.Timezone = "UTC"
	}
	if cfg.System.Bogons.Interval == "" {
		cfg.System.Bogons.Interval = "monthly"
	}

	// Note: Interface defaults are skipped due to model API limitations.
	// The current model returns interfaces by value from functions, making them
	// read-only. Consider model changes if interface defaults are needed.

	// Fill NAT defaults
	if cfg.Nat.Outbound.Mode == "" {
		cfg.Nat.Outbound.Mode = "automatic"
	}

	// Fill theme default
	if cfg.Theme == "" {
		cfg.Theme = "opnsense"
	}
}

// canonicalizeAddresses canonicalizes IP addresses and CIDR notation for consistency.
func (p *CoreProcessor) canonicalizeAddresses(cfg *model.Opnsense) {
	// Note: Interface canonicalization is skipped due to model API limitations.
	// The current model returns interfaces by value from functions, making them
	// read-only. Consider model changes if interface address canonicalization is needed.

	// Note: DHCP range canonicalization is skipped due to model API limitations.
	// The current model returns DHCP interfaces by value from functions, making them
	// read-only. Consider model changes if DHCP address canonicalization is needed.
	//
	// Previous code that no longer works with new model:
	// if cfg.Dhcpd.Lan.Range.From != "" {
	//     if ip := net.ParseIP(cfg.Dhcpd.Lan.Range.From); ip != nil {
	//         cfg.Dhcpd.Lan.Range.From = ip.String()
	//     }
	// }

	// Canonicalize firewall rule source networks
	for i := range cfg.Filter.Rule {
		rule := &cfg.Filter.Rule[i]
		if rule.Source.Network != "" && !isSpecialNetworkType(rule.Source.Network) {
			if _, cidr, err := net.ParseCIDR(rule.Source.Network); err == nil {
				// Store the canonical CIDR notation
				rule.Source.Network = cidr.String()
			} else if ip := net.ParseIP(rule.Source.Network); ip != nil {
				// Convert single IP to CIDR notation
				if ip.To4() != nil {
					rule.Source.Network = ip.String() + "/32"
				} else {
					rule.Source.Network = ip.String() + "/128"
				}
			}
		}
	}
}

// sortSlices sorts all slices in the configuration for deterministic output.
func (p *CoreProcessor) sortSlices(cfg *model.Opnsense) {
	// Sort users by name
	sort.Slice(cfg.System.User, func(i, j int) bool {
		return cfg.System.User[i].Name < cfg.System.User[j].Name
	})

	// Sort groups by name
	sort.Slice(cfg.System.Group, func(i, j int) bool {
		return cfg.System.Group[i].Name < cfg.System.Group[j].Name
	})

	// Sort sysctl items by tunable name
	sort.Slice(cfg.Sysctl, func(i, j int) bool {
		return cfg.Sysctl[i].Tunable < cfg.Sysctl[j].Tunable
	})

	// Sort firewall rules by interface, then by type, then by description for determinism
	sort.Slice(cfg.Filter.Rule, func(i, j int) bool {
		ruleA, ruleB := &cfg.Filter.Rule[i], &cfg.Filter.Rule[j]
		if ruleA.Interface != ruleB.Interface {
			return ruleA.Interface < ruleB.Interface
		}
		if ruleA.Type != ruleB.Type {
			return ruleA.Type < ruleB.Type
		}
		return ruleA.Descr < ruleB.Descr
	})

	// Sort load balancer monitor types by name
	sort.Slice(cfg.LoadBalancer.MonitorType, func(i, j int) bool {
		return cfg.LoadBalancer.MonitorType[i].Name < cfg.LoadBalancer.MonitorType[j].Name
	})
}

// isSpecialNetworkType checks if the network is a special type (any, lan, wan, etc.)
func isSpecialNetworkType(network string) bool {
	specialTypes := []string{"any", "lan", "wan", "localhost", "loopback"}
	for _, special := range specialTypes {
		if strings.EqualFold(network, special) {
			return true
		}
	}
	return false
}
