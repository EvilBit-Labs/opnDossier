package formatters

import (
	"sort"
	"strings"

	"github.com/EvilBit-Labs/opnDossier/internal/model/common"
)

const (
	securityTunableRatio = 4
	ruleTypeRatio        = 3
)

// FilterSystemTunables filters system tunables based on security-related prefixes.
// When includeTunables is false, only returns security-related tunables.
// When includeTunables is true, returns all tunables.
// Returns nil if tunables is nil, empty slice if no matches found.
func FilterSystemTunables(tunables []common.SysctlItem, includeTunables bool) []common.SysctlItem {
	if tunables == nil {
		return nil
	}

	if len(tunables) == 0 {
		return []common.SysctlItem{}
	}

	if includeTunables {
		result := make([]common.SysctlItem, len(tunables))
		copy(result, tunables)
		return result
	}

	securityPrefixes := []string{
		"net.inet.ip.forwarding",
		"net.inet6.ip6.forwarding",
		"kern.securelevel",
		"security.",
		"net.inet.tcp.blackhole",
		"net.inet.udp.blackhole",
	}

	estimatedSize := max(1, len(tunables)/securityTunableRatio)
	filtered := make([]common.SysctlItem, 0, estimatedSize)

	for _, item := range tunables {
		if item.Tunable == "" {
			continue
		}

		for _, prefix := range securityPrefixes {
			if strings.HasPrefix(item.Tunable, prefix) {
				filtered = append(filtered, item)
				break
			}
		}
	}
	return filtered
}

// AggregatePackageStats aggregates statistics about packages.
// Returns a map with total, installed, locked, and automatic package counts.
// Returns nil if packages is nil, stats with zero counts if packages is empty.
func AggregatePackageStats(packages []common.Package) map[string]int {
	if packages == nil {
		return nil
	}

	stats := map[string]int{
		"total":     len(packages),
		"installed": 0,
		"locked":    0,
		"automatic": 0,
	}

	if len(packages) == 0 {
		return stats
	}

	for _, pkg := range packages {
		if pkg.Name == "" {
			continue
		}

		if pkg.Installed {
			stats["installed"]++
		}
		if pkg.Locked {
			stats["locked"]++
		}
		if pkg.Automatic {
			stats["automatic"]++
		}
	}

	return stats
}

// FilterRulesByType filters firewall rules by their type.
// If ruleType is empty, returns all rules.
// Otherwise, returns only rules matching the specified type.
// Returns nil if rules is nil, empty slice if no matches found.
func FilterRulesByType(rules []common.FirewallRule, ruleType string) []common.FirewallRule {
	if rules == nil {
		return nil
	}

	if len(rules) == 0 {
		return []common.FirewallRule{}
	}

	if ruleType == "" {
		result := make([]common.FirewallRule, len(rules))
		copy(result, rules)
		return result
	}

	estimatedSize := max(1, len(rules)/ruleTypeRatio)
	filtered := make([]common.FirewallRule, 0, estimatedSize)

	for _, rule := range rules {
		if rule.Type == "" {
			continue
		}

		if rule.Type == ruleType {
			filtered = append(filtered, rule)
		}
	}
	return filtered
}

// ExtractUniqueValues extracts unique values from a slice of strings.
// Returns a sorted slice of unique strings with duplicates removed.
// Returns nil if items is nil, empty slice if items is empty.
func ExtractUniqueValues(items []string) []string {
	if items == nil {
		return nil
	}

	if len(items) == 0 {
		return []string{}
	}

	if len(items) == 1 {
		if items[0] == "" {
			return []string{}
		}
		return []string{items[0]}
	}

	seen := make(map[string]bool, len(items))
	unique := make([]string, 0, len(items))

	for _, item := range items {
		if item == "" {
			continue
		}

		if !seen[item] {
			seen[item] = true
			unique = append(unique, item)
		}
	}

	sort.Strings(unique)
	return unique
}
