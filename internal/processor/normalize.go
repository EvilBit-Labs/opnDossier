package processor

import (
	"net"
	"slices"
	"strings"

	"github.com/EvilBit-Labs/opnDossier/internal/model/common"
)

// normalize normalizes the given device configuration by filling defaults, canonicalizing IP/CIDR, and sorting slices for determinism.
func (p *CoreProcessor) normalize(cfg *common.CommonDevice) *common.CommonDevice {
	// Create a shallow copy, then deep-copy slices that will be mutated
	normalized := *cfg

	// Deep-copy slices that normalize mutates or that contain sensitive data.
	// Mutated by sortSlices/canonicalizeAddresses — clone required for correctness:
	normalized.FirewallRules = slices.Clone(cfg.FirewallRules)
	normalized.Users = slices.Clone(cfg.Users)
	normalized.Groups = slices.Clone(cfg.Groups)
	normalized.Sysctl = slices.Clone(cfg.Sysctl)
	normalized.LoadBalancer.MonitorTypes = slices.Clone(cfg.LoadBalancer.MonitorTypes)
	// Defensive clones — not mutated by normalize phases, but contain sensitive
	// fields that downstream code must not accidentally leak back to the caller.
	normalized.Certificates = slices.Clone(cfg.Certificates)
	normalized.DHCP = slices.Clone(cfg.DHCP)
	normalized.VPN.WireGuard.Clients = slices.Clone(cfg.VPN.WireGuard.Clients)
	// Other CommonDevice slices (Interfaces, VLANs, Bridges, CAs, etc.) are
	// intentionally not cloned — normalize does not mutate them, and the
	// downstream analyze pipeline is read-only on the config.

	// Phase 1: Fill defaults
	p.fillDefaults(&normalized)

	// Phase 2: Canonicalize IP addresses and CIDR notation
	p.canonicalizeAddresses(&normalized)

	// Phase 3: Sort slices for determinism
	p.sortSlices(&normalized)

	return &normalized
}

// fillDefaults fills in default values for missing configuration elements.
func (p *CoreProcessor) fillDefaults(cfg *common.CommonDevice) {
	// Fill system defaults
	if cfg.System.Optimization == "" {
		cfg.System.Optimization = "normal"
	}
	// Normalize WebGUI configuration
	if cfg.System.WebGUI.Protocol == "" {
		cfg.System.WebGUI.Protocol = "https"
	}

	if cfg.System.Timezone == "" {
		cfg.System.Timezone = "UTC"
	}

	if cfg.System.Bogons.Interval == "" {
		cfg.System.Bogons.Interval = "monthly"
	}

	// Fill NAT defaults
	if cfg.NAT.OutboundMode == "" {
		cfg.NAT.OutboundMode = "automatic"
	}

	// Fill theme default
	if cfg.Theme == "" {
		cfg.Theme = "opnsense"
	}
}

// canonicalizeAddresses canonicalizes IP addresses and CIDR notation for consistency.
func (p *CoreProcessor) canonicalizeAddresses(cfg *common.CommonDevice) {
	// Canonicalize firewall rule source/destination addresses
	for i := range cfg.FirewallRules {
		rule := &cfg.FirewallRules[i]
		canonicalizeIPField(&rule.Source.Address)
		canonicalizeIPField(&rule.Destination.Address)
	}
}

// sortSlices sorts all slices in the configuration for deterministic output.
func (p *CoreProcessor) sortSlices(cfg *common.CommonDevice) {
	// Sort users by name
	slices.SortFunc(cfg.Users, func(a, b common.User) int {
		return strings.Compare(a.Name, b.Name)
	})

	// Sort groups by name
	slices.SortFunc(cfg.Groups, func(a, b common.Group) int {
		return strings.Compare(a.Name, b.Name)
	})

	// Sort sysctl items by tunable name
	slices.SortFunc(cfg.Sysctl, func(a, b common.SysctlItem) int {
		return strings.Compare(a.Tunable, b.Tunable)
	})

	// Sort firewall rules by interface, then by type, then by description for determinism
	slices.SortFunc(cfg.FirewallRules, func(a, b common.FirewallRule) int {
		ifacesA := strings.Join(a.Interfaces, ",")
		ifacesB := strings.Join(b.Interfaces, ",")
		if c := strings.Compare(ifacesA, ifacesB); c != 0 {
			return c
		}

		if c := strings.Compare(a.Type, b.Type); c != 0 {
			return c
		}

		return strings.Compare(a.Description, b.Description)
	})

	// Sort load balancer monitor types by name
	slices.SortFunc(cfg.LoadBalancer.MonitorTypes, func(a, b common.MonitorType) int {
		return strings.Compare(a.Name, b.Name)
	})
}

// canonicalizeIPField normalizes an IP/CIDR field in-place, converting bare IPs
// to CIDR notation and canonical form. Non-IP values (aliases, interface names) are left unchanged.
func canonicalizeIPField(field *string) {
	if field == nil || *field == "" || isSpecialNetworkType(*field) {
		return
	}
	if _, cidr, err := net.ParseCIDR(*field); err == nil {
		*field = cidr.String()
	} else if ip := net.ParseIP(*field); ip != nil {
		if ip.To4() != nil {
			*field = ip.String() + "/32"
		} else {
			*field = ip.String() + "/128"
		}
	}
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
