// Package converter provides functionality to convert OPNsense configurations to markdown.
package converter

import (
	"sort"
	"strings"

	"github.com/EvilBit-Labs/opnDossier/internal/model"
)

const (
	// Service status constants.
	statusRunning = "running"
	statusStopped = "stopped"

	// Capacity estimation ratios for performance optimization.
	securityTunableRatio = 4 // ~25% of tunables are security-related
	serviceBalanceRatio  = 2 // ~50% split between running/stopped services
	ruleTypeRatio        = 3 // ~33% of rules match a specific type
)

// FilterSystemTunables filters system tunables based on security-related prefixes.
// When includeTunables is false, only returns security-related tunables.
// When includeTunables is true, returns all tunables.
// Returns nil if tunables is nil, empty slice if no matches found.
func (b *MarkdownBuilder) FilterSystemTunables(tunables []model.SysctlItem, includeTunables bool) []model.SysctlItem {
	// Handle edge case: nil input
	if tunables == nil {
		return nil
	}

	// Handle edge case: empty input
	if len(tunables) == 0 {
		return []model.SysctlItem{}
	}

	if includeTunables {
		// Return a copy to avoid shared slice references
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

	// Pre-allocate with estimated capacity for performance
	// Estimate ~25% of tunables might be security-related
	estimatedSize := max(1, len(tunables)/securityTunableRatio)
	filtered := make([]model.SysctlItem, 0, estimatedSize)

	for _, item := range tunables {
		// Handle edge case: empty tunable name
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
func (b *MarkdownBuilder) GroupServicesByStatus(services []model.Service) map[string][]model.Service {
	// Handle edge case: nil input
	if services == nil {
		return nil
	}

	// Pre-allocate map with known keys and estimated capacity for performance
	// Estimate roughly 50/50 split between running and stopped services
	estimatedCapacity := max(1, len(services)/serviceBalanceRatio)

	grouped := map[string][]model.Service{
		statusRunning: make([]model.Service, 0, estimatedCapacity),
		statusStopped: make([]model.Service, 0, estimatedCapacity),
	}

	for _, service := range services {
		// Handle edge case: invalid status, default to stopped
		status := statusStopped
		if service.Status == statusRunning {
			status = statusRunning
		}

		// Handle edge case: empty service name
		if service.Name == "" {
			continue
		}

		grouped[status] = append(grouped[status], service)
	}

	// Sort services within each group by name for consistent output
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
func (b *MarkdownBuilder) AggregatePackageStats(packages []model.Package) map[string]int {
	// Handle edge case: nil input
	if packages == nil {
		return nil
	}

	// Initialize stats map with all required keys for consistent output
	stats := map[string]int{
		"total":     len(packages),
		"installed": 0,
		"locked":    0,
		"automatic": 0,
	}

	// Handle edge case: empty packages slice
	if len(packages) == 0 {
		return stats
	}

	// Single pass through packages for optimal performance O(n)
	for _, pkg := range packages {
		// Handle edge case: skip packages with empty names
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
func (b *MarkdownBuilder) FilterRulesByType(rules []model.Rule, ruleType string) []model.Rule {
	// Handle edge case: nil input
	if rules == nil {
		return nil
	}

	// Handle edge case: empty input
	if len(rules) == 0 {
		return []model.Rule{}
	}

	if ruleType == "" {
		// Return a copy to avoid shared slice references
		result := make([]model.Rule, len(rules))
		copy(result, rules)
		return result
	}

	// Pre-allocate with estimated capacity for performance
	// Estimate ~30% of rules might match a specific type
	estimatedSize := max(1, len(rules)/ruleTypeRatio)
	filtered := make([]model.Rule, 0, estimatedSize)

	for _, rule := range rules {
		// Handle edge case: skip rules with empty type
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
func (b *MarkdownBuilder) ExtractUniqueValues(items []string) []string {
	// Handle edge case: nil input
	if items == nil {
		return nil
	}

	// Handle edge case: empty input
	if len(items) == 0 {
		return []string{}
	}

	// Handle edge case: single item
	if len(items) == 1 {
		// Skip empty strings
		if items[0] == "" {
			return []string{}
		}
		return []string{items[0]}
	}

	// Pre-allocate map and slice with capacity for performance
	// Use len(items) as worst-case scenario (all unique)
	seen := make(map[string]bool, len(items))
	unique := make([]string, 0, len(items))

	for _, item := range items {
		// Handle edge case: skip empty strings
		if item == "" {
			continue
		}

		if !seen[item] {
			seen[item] = true
			unique = append(unique, item)
		}
	}

	// Sort for consistent output
	sort.Strings(unique)
	return unique
}
