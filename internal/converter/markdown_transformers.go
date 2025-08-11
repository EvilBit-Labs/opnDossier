// Package converter provides functionality to convert OPNsense configurations to markdown.
package converter

import (
	"sort"
	"strings"

	"github.com/EvilBit-Labs/opnDossier/internal/model"
)

// FilterSystemTunables filters system tunables based on security-related prefixes.
// When includeTunables is false, only returns security-related tunables.
// When includeTunables is true, returns all tunables.
func (b *MarkdownBuilder) FilterSystemTunables(tunables []model.SysctlItem, includeTunables bool) []model.SysctlItem {
	if includeTunables {
		return tunables
	}

	securityPrefixes := []string{
		"net.inet.ip.forwarding",
		"net.inet6.ip6.forwarding",
		"kern.securelevel",
		"security.",
		"net.inet.tcp.blackhole",
		"net.inet.udp.blackhole",
	}

	filtered := make([]model.SysctlItem, 0)
	for _, item := range tunables {
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
func (b *MarkdownBuilder) GroupServicesByStatus(services []model.Service) map[string][]model.Service {
	grouped := make(map[string][]model.Service)

	for _, service := range services {
		status := "stopped"
		if service.Status == "running" {
			status = "running"
		}
		grouped[status] = append(grouped[status], service)
	}

	// Sort services within each group by name
	for status := range grouped {
		sort.Slice(grouped[status], func(i, j int) bool {
			return grouped[status][i].Name < grouped[status][j].Name
		})
	}

	return grouped
}

// AggregatePackageStats aggregates statistics about packages.
// Returns a map with total, installed, locked, and automatic package counts.
func (b *MarkdownBuilder) AggregatePackageStats(packages []model.Package) map[string]int {
	stats := map[string]int{
		"total":     len(packages),
		"installed": 0,
		"locked":    0,
		"automatic": 0,
	}

	for _, pkg := range packages {
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
func (b *MarkdownBuilder) FilterRulesByType(rules []model.Rule, ruleType string) []model.Rule {
	if ruleType == "" {
		return rules
	}

	filtered := make([]model.Rule, 0)
	for _, rule := range rules {
		if rule.Type == ruleType {
			filtered = append(filtered, rule)
		}
	}
	return filtered
}

// ExtractUniqueValues extracts unique values from a slice of strings.
// Returns a sorted slice of unique strings with duplicates removed.
func (b *MarkdownBuilder) ExtractUniqueValues(items []string) []string {
	seen := make(map[string]bool)
	unique := make([]string, 0)

	for _, item := range items {
		if !seen[item] {
			seen[item] = true
			unique = append(unique, item)
		}
	}

	sort.Strings(unique)
	return unique
}
