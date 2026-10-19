package diff

import (
	"cmp"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/EvilBit-Labs/opnDossier/internal/analysis"
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

	// Rules without a UUID are compared separately; see compareRulesWithoutUUID.
	changes = append(changes, a.compareRulesWithoutUUID(old, newCfg)...)

	return changes
}

// Similarity weights for pairing leftover rules. A rule's description is the
// operator's own name for it and survives most edits, so it counts for more
// than any single match field; the interface list is the next strongest signal.
const (
	simWeightDescription = 4
	simWeightInterfaces  = 2
	simWeightField       = 1

	// simMinScore is the floor for calling two rules the same rule edited:
	// a matching description alone, or a matching interface list plus two
	// other fields.
	simMinScore = 4

	// simMaxPairs bounds the similarity scoring; see itemPairer.maxPairs.
	simMaxPairs = 512
)

// ruleSimilarity scores how likely a and b are the same rule after an edit.
func ruleSimilarity(a, b common.FirewallRule) int {
	score := 0

	if a.Description != "" && a.Description == b.Description {
		score += simWeightDescription
	}

	if slices.Equal(a.Interfaces, b.Interfaces) {
		score += simWeightInterfaces
	}

	for _, same := range []bool{
		a.Type == b.Type,
		a.Protocol == b.Protocol,
		a.Source.Address == b.Source.Address,
		a.Destination.Address == b.Destination.Address,
		a.Destination.Port == b.Destination.Port,
	} {
		if same {
			score += simWeightField
		}
	}

	return score
}

// compareRulesWithoutUUID compares the rules that carry no UUID.
//
// It previously compared only the rule COUNT, so any content change that left
// the count intact was invisible: flipping a rule from pass to block, widening
// a source to any, or disabling its logging all reported "no changes". That is
// the common case rather than an edge case -- pfSense rules never carry a
// <uuid>, and neither do older OPNsense ones.
func (a *Analyzer) compareRulesWithoutUUID(old, newCfg []common.FirewallRule) []Change {
	oldRules := rulesWithoutUUID(old)
	newRules := rulesWithoutUUID(newCfg)

	var changes []Change

	pairer := itemPairer[common.FirewallRule]{
		identity:   ruleIdentity,
		equal:      rulesEqual,
		similarity: ruleSimilarity,
		minScore:   simMinScore,
		maxPairs:   simMaxPairs,
	}

	res := pairer.pair(oldRules, newRules, func(oi, ni int) {
		if rulesEqual(oldRules[oi], newRules[ni]) {
			return
		}

		changes = append(changes, modifiedRuleChange(oldRules[oi], newRules[ni], ni))
	})

	for i, paired := range res.oldPaired {
		if !paired {
			changes = append(changes, removedRuleChange(oldRules[i], i))
		}
	}

	for i, paired := range res.newPaired {
		if !paired {
			changes = append(changes, addedRuleChange(newRules[i], i))
		}
	}

	return changes
}

// rulesWithoutUUID returns the subset of rules carrying no UUID, preserving
// config order.
func rulesWithoutUUID(rules []common.FirewallRule) []common.FirewallRule {
	var out []common.FirewallRule

	for _, r := range rules {
		if r.UUID == "" {
			out = append(out, r)
		}
	}

	return out
}

// rulePath renders the diff path for a rule without a UUID, falling back from
// its tracker to its position.
func rulePath(rule common.FirewallRule, index int) string {
	if rule.Tracker != "" {
		return fmt.Sprintf("filter.rule[tracker=%s]", rule.Tracker)
	}

	return fmt.Sprintf("filter.rule[%d]", index)
}

// modifiedRuleChange builds the Change for a rule whose content differs.
func modifiedRuleChange(oldRule, newRule common.FirewallRule, index int) Change {
	impact := ""
	if isPermissiveRule(newRule) && !isPermissiveRule(oldRule) {
		impact = "high"
	}

	return Change{
		Type:           ChangeModified,
		Section:        SectionFirewall,
		Path:           rulePath(newRule, index),
		Description:    "Modified rule: " + ruleDescription(newRule),
		OldValue:       formatRule(oldRule),
		NewValue:       formatRule(newRule),
		SecurityImpact: impact,
	}
}

// addedRuleChange builds the Change for a rule present only in the new config.
func addedRuleChange(rule common.FirewallRule, index int) Change {
	impact := ""
	if isPermissiveRule(rule) {
		impact = "high"
	}

	return Change{
		Type:           ChangeAdded,
		Section:        SectionFirewall,
		Path:           rulePath(rule, index),
		Description:    "Added rule: " + ruleDescription(rule),
		NewValue:       formatRule(rule),
		SecurityImpact: impact,
	}
}

// removedRuleChange builds the Change for a rule present only in the old config.
func removedRuleChange(rule common.FirewallRule, index int) Change {
	return Change{
		Type:           ChangeRemoved,
		Section:        SectionFirewall,
		Path:           rulePath(rule, index),
		Description:    "Removed rule: " + ruleDescription(rule),
		OldValue:       formatRule(rule),
		SecurityImpact: "medium",
	}
}

// ruleDescription returns the rule's description if set, or a synthesized
// summary of the form "type source -> destination" as a fallback.
func ruleDescription(rule common.FirewallRule) string {
	if rule.Description != "" {
		return rule.Description
	}

	src := cmp.Or(rule.Source.Address, addressUnknown)
	dst := cmp.Or(rule.Destination.Address, addressUnknown)

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
	result := prefix + cmp.Or(ep.Address, addressUnknown)
	if ep.Port != "" {
		result += ":" + ep.Port
	}
	return result
}

// rulesEqual reports whether two firewall rules are semantically identical.
//
// Every field that changes what the rule matches, where it sits in pf
// evaluation order, or whether it is recorded is compared. It previously
// covered seven of the model's thirty-three, so a diff stayed silent when an
// operator flipped a rule's direction, made it floating or quick, moved it to
// another gateway, switched its state type, or turned its logging off -- the
// last of which is how a rule change hides from the very logs an audit reads.
//
// UUID and Tracker are deliberately excluded: they identify the rule and are
// what CompareFirewallRules pairs on, so comparing them here would report every
// paired rule as modified.
//
// When a field is added to common.FirewallRule it belongs here.
// TestRulesEqual_ComparesEveryFirewallRuleField fails until it is.
func rulesEqual(a, b common.FirewallRule) bool {
	return rulesMatchEqual(a, b) && rulesPrecedenceEqual(a, b) && rulesOptionsEqual(a, b)
}

// rulesMatchEqual compares the fields deciding which packets the rule matches.
func rulesMatchEqual(a, b common.FirewallRule) bool {
	return a.Type == b.Type &&
		a.Description == b.Description &&
		a.Protocol == b.Protocol &&
		a.Disabled == b.Disabled &&
		endpointsEqual(a.Source, b.Source) &&
		endpointsEqual(a.Destination, b.Destination) &&
		slices.Equal(a.Interfaces, b.Interfaces) &&
		a.IPProtocol == b.IPProtocol &&
		a.ICMPType == b.ICMPType &&
		a.ICMP6Type == b.ICMP6Type &&
		a.TCPFlags1 == b.TCPFlags1 &&
		a.TCPFlags2 == b.TCPFlags2 &&
		a.TCPFlagsAny == b.TCPFlagsAny
}

// rulesPrecedenceEqual compares the fields deciding where the rule sits in pf
// evaluation order and where matched traffic is sent.
func rulesPrecedenceEqual(a, b common.FirewallRule) bool {
	return a.Direction == b.Direction &&
		a.Floating == b.Floating &&
		a.Quick == b.Quick &&
		a.Target == b.Target &&
		objectRefsEqual(a.TargetRef, b.TargetRef) &&
		a.Gateway == b.Gateway &&
		a.AssociatedRuleID == b.AssociatedRuleID
}

// rulesOptionsEqual compares logging, state handling and connection limits.
func rulesOptionsEqual(a, b common.FirewallRule) bool {
	return a.Log == b.Log &&
		a.StateType == b.StateType &&
		a.StateTimeout == b.StateTimeout &&
		a.MaxSrcNodes == b.MaxSrcNodes &&
		a.MaxSrcConn == b.MaxSrcConn &&
		a.MaxSrcConnRate == b.MaxSrcConnRate &&
		a.MaxSrcConnRates == b.MaxSrcConnRates &&
		a.AllowOpts == b.AllowOpts &&
		a.DisableReplyTo == b.DisableReplyTo &&
		a.NoPfSync == b.NoPfSync &&
		a.NoSync == b.NoSync &&
		a.Tag == b.Tag &&
		a.Tagged == b.Tagged
}

// endpointsEqual compares two rule endpoints by value. RuleEndpoint holds its
// alias references as pointers, so == compares the pointers: two parses of the
// same rule then differ whenever an endpoint names an alias, and an unchanged
// rule is reported as modified.
func endpointsEqual(a, b common.RuleEndpoint) bool {
	return a.Address == b.Address &&
		a.Port == b.Port &&
		a.Negated == b.Negated &&
		objectRefsEqual(a.AddressRef, b.AddressRef) &&
		objectRefsEqual(a.PortRef, b.PortRef)
}

// objectRefsEqual compares two optional named-object references by value, so a
// rule that switches from one alias to another is reported as modified.
func objectRefsEqual(a, b *common.ObjectRef) bool {
	if a == nil || b == nil {
		return a == b
	}

	return *a == *b
}

// isPermissiveRule reports whether a firewall rule is an unrestricted pass rule
// that allows all traffic from any source to any destination.
//
// Disabled rules are excluded: they forward nothing, so reporting one as
// permissive overstates the impact of a diff. This matters more now that an
// omitted address counts as a wildcard, which makes a disabled rule with no
// source or destination look maximally permissive rather than unset.
func isPermissiveRule(rule common.FirewallRule) bool {
	return !rule.Disabled &&
		rule.Type == common.RuleTypePass &&
		analysis.IsAnyEndpoint(rule.Source) &&
		analysis.IsAnyEndpoint(rule.Destination)
}
