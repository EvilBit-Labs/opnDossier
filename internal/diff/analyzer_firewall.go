package diff

import (
	"fmt"
	"maps"
	"slices"
	"strings"

	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
)

// CompareFirewallRules compares firewall rules between two configs.
func (a *Analyzer) CompareFirewallRules(old, newCfg []common.FirewallRule) []Change {
	var changes []Change

	// Build maps by UUID for matching
	oldByUUID := make(map[string]common.FirewallRule, len(old))
	newByUUID := make(map[string]common.FirewallRule, len(newCfg))

	for _, rule := range old {
		if rule.UUID != "" {
			oldByUUID[rule.UUID] = rule
		}
	}
	for _, rule := range newCfg {
		if rule.UUID != "" {
			newByUUID[rule.UUID] = rule
		}
	}

	// Sort keys for deterministic output
	oldUUIDs := slices.Sorted(maps.Keys(oldByUUID))
	newUUIDs := slices.Sorted(maps.Keys(newByUUID))

	// Find removed rules
	for _, uuid := range oldUUIDs {
		if _, exists := newByUUID[uuid]; !exists {
			oldRule := oldByUUID[uuid]
			changes = append(changes, Change{
				Type:           ChangeRemoved,
				Section:        SectionFirewall,
				Path:           fmt.Sprintf("filter.rule[uuid=%s]", uuid),
				Description:    "Removed rule: " + ruleDescription(oldRule),
				OldValue:       formatRule(oldRule),
				SecurityImpact: "medium",
			})
		}
	}

	// Find added rules and modified rules
	for _, uuid := range newUUIDs {
		newRule := newByUUID[uuid]
		oldRule, exists := oldByUUID[uuid]
		if !exists {
			impact := ""
			if isPermissiveRule(newRule) {
				impact = "high"
			}
			changes = append(changes, Change{
				Type:           ChangeAdded,
				Section:        SectionFirewall,
				Path:           fmt.Sprintf("filter.rule[uuid=%s]", uuid),
				Description:    "Added rule: " + ruleDescription(newRule),
				NewValue:       formatRule(newRule),
				SecurityImpact: impact,
			})
		} else if !rulesEqual(oldRule, newRule) {
			// Flag cases where the modified rule becomes permissive while the old rule was not
			impact := ""
			if isPermissiveRule(newRule) && !isPermissiveRule(oldRule) {
				impact = "high"
			}
			changes = append(changes, Change{
				Type:           ChangeModified,
				Section:        SectionFirewall,
				Path:           fmt.Sprintf("filter.rule[uuid=%s]", uuid),
				Description:    "Modified rule: " + ruleDescription(newRule),
				OldValue:       formatRule(oldRule),
				NewValue:       formatRule(newRule),
				SecurityImpact: impact,
			})
		}
	}

	// Also compare by position for rules without UUIDs
	changes = append(changes, a.compareRulesByPosition(old, newCfg)...)

	return changes
}

// compareRulesByPosition compares rules that don't have UUIDs by position.
func (a *Analyzer) compareRulesByPosition(old, newCfg []common.FirewallRule) []Change {
	var changes []Change

	// Filter to rules without UUIDs
	var oldNoUUID, newNoUUID []common.FirewallRule
	for _, r := range old {
		if r.UUID == "" {
			oldNoUUID = append(oldNoUUID, r)
		}
	}
	for _, r := range newCfg {
		if r.UUID == "" {
			newNoUUID = append(newNoUUID, r)
		}
	}

	// Simple length comparison for rules without UUIDs
	if len(oldNoUUID) != len(newNoUUID) {
		changes = append(changes, Change{
			Type:        ChangeModified,
			Section:     SectionFirewall,
			Path:        "filter.rules",
			Description: fmt.Sprintf("Rule count changed (without UUID): %d → %d", len(oldNoUUID), len(newNoUUID)),
			OldValue:    fmt.Sprintf("%d rules", len(oldNoUUID)),
			NewValue:    fmt.Sprintf("%d rules", len(newNoUUID)),
		})
	}

	return changes
}

// ruleDescription returns the rule's description if set, or a synthesized
// summary of the form "type source -> destination" as a fallback.
func ruleDescription(rule common.FirewallRule) string {
	if rule.Description != "" {
		return rule.Description
	}

	src := rule.Source.Address
	if src == "" {
		src = addressUnknown
	}

	dst := rule.Destination.Address
	if dst == "" {
		dst = addressUnknown
	}

	return fmt.Sprintf("%s %s → %s", string(rule.Type), src, dst)
}

// formatRule returns a compact, human-readable representation of a firewall rule
// including its type, interfaces, protocol, source, destination, and disabled state.
func formatRule(rule common.FirewallRule) string {
	parts := []string{
		"type=" + string(rule.Type),
	}
	if len(rule.Interfaces) > 0 {
		parts = append(parts, "if="+strings.Join(rule.Interfaces, ","))
	}
	if rule.Protocol != "" {
		parts = append(parts, "proto="+rule.Protocol)
	}
	parts = append(parts,
		"src="+formatEndpoint(rule.Source),
		"dst="+formatEndpoint(rule.Destination))
	if rule.Disabled {
		parts = append(parts, "disabled")
	}
	return strings.Join(parts, ", ")
}

// formatEndpoint returns a string representation of a rule endpoint in the form
// [!]address[:port], using "unknown" when the address is empty.
func formatEndpoint(ep common.RuleEndpoint) string {
	var prefix string
	if ep.Negated {
		prefix = "!"
	}
	addr := ep.Address
	if addr == "" {
		addr = addressUnknown
	}
	result := prefix + addr
	if ep.Port != "" {
		result += ":" + ep.Port
	}
	return result
}

// rulesEqual reports whether two firewall rules are semantically equal by comparing
// their type, description, protocol, disabled state, source, destination, and interfaces.
func rulesEqual(a, b common.FirewallRule) bool {
	return a.Type == b.Type &&
		a.Description == b.Description &&
		a.Protocol == b.Protocol &&
		a.Disabled == b.Disabled &&
		a.Source == b.Source &&
		a.Destination == b.Destination &&
		slices.Equal(a.Interfaces, b.Interfaces)
}

// isPermissiveRule reports whether a firewall rule is an unrestricted pass rule
// that allows all traffic from any source to any destination.
func isPermissiveRule(rule common.FirewallRule) bool {
	return rule.Type == common.RuleTypePass &&
		rule.Source.Address == "any" &&
		rule.Destination.Address == "any"
}
