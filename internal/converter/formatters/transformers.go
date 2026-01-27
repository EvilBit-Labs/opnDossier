package formatters

import (
	"sort"
	"strings"

	"github.com/EvilBit-Labs/opnDossier/internal/model"
)

const (
	securityTunableRatio = 4
	serviceBalanceRatio  = 2
	ruleTypeRatio        = 3
	statusRunning        = "running"
	statusStopped        = "stopped"
)

// FilterSystemTunables filters system tunables based on security-related prefixes.
// When includeTunables is false, only returns security-related tunables.
// When includeTunables is true, returns all tunables.
// Returns nil if tunables is nil, empty slice if no matches found.
func FilterSystemTunables(tunables []model.SysctlItem, includeTunables bool) []model.SysctlItem {
	if tunables == nil {
		return nil
	}

	if len(tunables) == 0 {
		return []model.SysctlItem{}
	}

	if includeTunables {
		result := make([]model.SysctlItem, len(tunables))
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

	estimatedSize := maxInt(1, len(tunables)/securityTunableRatio)
	filtered := make([]model.SysctlItem, 0, estimatedSize)

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

// GroupServicesByStatus groups services by their status (running/stopped).
// Returns a map with "running" and "stopped" keys containing sorted slices of services.
// Returns nil if services is nil, empty map with initialized slices if services is empty.
func GroupServicesByStatus(services []model.Service) map[string][]model.Service {
	if services == nil {
		return nil
	}

	estimatedCapacity := maxInt(1, len(services)/serviceBalanceRatio)

	grouped := map[string][]model.Service{
		statusRunning: make([]model.Service, 0, estimatedCapacity),
		statusStopped: make([]model.Service, 0, estimatedCapacity),
	}

	for _, service := range services {
		status := statusStopped
		if service.Status == statusRunning {
			status = statusRunning
		}

		if service.Name == "" {
			continue
		}

		grouped[status] = append(grouped[status], service)
	}

	for status := range grouped {
		sort.Slice(grouped[status], func(i, j int) bool {
			return grouped[status][i].Name < grouped[status][j].Name
		})
	}

	return grouped
}

// AggregatePackageStats aggregates statistics about packages.
// Returns a map with total, installed, locked, and automatic package counts.
// Returns nil if packages is nil, stats with zero counts if packages is empty.
func AggregatePackageStats(packages []model.Package) map[string]int {
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
func FilterRulesByType(rules []model.Rule, ruleType string) []model.Rule {
	if rules == nil {
		return nil
	}

	if len(rules) == 0 {
		return []model.Rule{}
	}

	if ruleType == "" {
		result := make([]model.Rule, len(rules))
		copy(result, rules)
		return result
	}

	estimatedSize := maxInt(1, len(rules)/ruleTypeRatio)
	filtered := make([]model.Rule, 0, estimatedSize)

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

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
