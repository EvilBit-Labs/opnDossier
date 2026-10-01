package diff

import (
	"cmp"
	"fmt"
	"slices"
	"strconv"
	"strings"

	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
)

// CompareNAT compares NAT configuration between two configs.
func (a *Analyzer) CompareNAT(old, newCfg common.NATConfig) []Change {
	oldHas := old.HasData()
	newHas := newCfg.HasData()

	if !oldHas && !newHas {
		return nil
	}
	if !oldHas && newHas {
		return []Change{{
			Type:        ChangeAdded,
			Section:     SectionNAT,
			Path:        "nat",
			Description: "NAT configuration section added",
		}}
	}
	if oldHas && !newHas {
		return []Change{{
			Type:        ChangeRemoved,
			Section:     SectionNAT,
			Path:        "nat",
			Description: "NAT configuration section removed",
		}}
	}

	var changes []Change

	// Compare outbound NAT mode
	if old.OutboundMode != newCfg.OutboundMode {
		changes = append(changes, Change{
			Type:           ChangeModified,
			Section:        SectionNAT,
			Path:           "nat.outbound.mode",
			Description:    "Outbound NAT mode changed",
			OldValue:       string(old.OutboundMode),
			NewValue:       string(newCfg.OutboundMode),
			SecurityImpact: "medium",
		})
	}

	// Compare outbound and inbound rules per rule, not by list length.
	changes = append(changes, compareOutboundNATRules(old.OutboundRules, newCfg.OutboundRules)...)
	changes = append(changes, compareInboundNATRules(old.InboundRules, newCfg.InboundRules)...)

	// Compare NAT boolean settings
	if old.ReflectionDisabled != newCfg.ReflectionDisabled {
		changes = append(changes, Change{
			Type:        ChangeModified,
			Section:     SectionNAT,
			Path:        "nat.reflectionDisabled",
			Description: "NAT reflection setting changed",
			OldValue:    strconv.FormatBool(old.ReflectionDisabled),
			NewValue:    strconv.FormatBool(newCfg.ReflectionDisabled),
		})
	}
	if old.PfShareForward != newCfg.PfShareForward {
		changes = append(changes, Change{
			Type:        ChangeModified,
			Section:     SectionNAT,
			Path:        "nat.pfShareForward",
			Description: "pf share-forward setting changed",
			OldValue:    strconv.FormatBool(old.PfShareForward),
			NewValue:    strconv.FormatBool(newCfg.PfShareForward),
		})
	}
	if old.BiNATEnabled != newCfg.BiNATEnabled {
		changes = append(changes, Change{
			Type:        ChangeModified,
			Section:     SectionNAT,
			Path:        "nat.biNatEnabled",
			Description: "BiNAT setting changed",
			OldValue:    strconv.FormatBool(old.BiNATEnabled),
			NewValue:    strconv.FormatBool(newCfg.BiNATEnabled),
		})
	}

	return changes
}

// NAT rule similarity weights, mirroring the firewall ones: the operator's own
// description outranks any single field, and the interface list is the next
// strongest signal.
const (
	natSimWeightDescription = 4
	natSimWeightInterfaces  = 2
	natSimWeightField       = 1

	// natSimMinScore is the floor for calling two NAT rules the same rule
	// edited: a matching description alone, or a matching interface list plus
	// two other fields.
	natSimMinScore = 4

	// natSimMaxPairs bounds the similarity scoring; see itemPairer.maxPairs.
	natSimMaxPairs = 512
)

// natRuleIdentity returns an outbound NAT rule's stable id. No vendor observed
// so far populates it -- neither pfSense nor the OPNsense MVC configs carry a
// UUID on NAT rules -- so pairing normally falls through to content and
// similarity. It is honoured when present rather than assumed absent.
func natRuleIdentity(rule common.NATRule) (string, bool) {
	if rule.UUID == "" {
		return "", false
	}

	return "uuid=" + rule.UUID, true
}

// inboundNATRuleIdentity is natRuleIdentity for port forwards.
func inboundNATRuleIdentity(rule common.InboundNATRule) (string, bool) {
	if rule.UUID == "" {
		return "", false
	}

	return "uuid=" + rule.UUID, true
}

// natRulesEqual reports whether two outbound NAT rules are semantically
// identical. Every field that changes what the rule matches or how it
// translates is compared; a field omitted here produces no diff entry at all.
//
// UUID is excluded because it is the identity the pairing keys on.
//
// When a field is added to common.NATRule it belongs here.
// TestNATRulesEqual_ComparesEveryField fails until it is.
func natRulesEqual(a, b common.NATRule) bool {
	return slices.Equal(a.Interfaces, b.Interfaces) &&
		a.IPProtocol == b.IPProtocol &&
		a.Protocol == b.Protocol &&
		endpointsEqual(a.Source, b.Source) &&
		endpointsEqual(a.Destination, b.Destination) &&
		a.Target == b.Target &&
		objectRefsEqual(a.TargetRef, b.TargetRef) &&
		a.SourcePort == b.SourcePort &&
		objectRefsEqual(a.SourcePortRef, b.SourcePortRef) &&
		a.NatPort == b.NatPort &&
		objectRefsEqual(a.NatPortRef, b.NatPortRef) &&
		a.PoolOpts == b.PoolOpts &&
		a.StaticNatPort == b.StaticNatPort &&
		a.NoNat == b.NoNat &&
		a.Disabled == b.Disabled &&
		a.Log == b.Log &&
		a.Description == b.Description &&
		a.Category == b.Category &&
		a.Tag == b.Tag &&
		a.Tagged == b.Tagged
}

// inboundNATRulesEqual is natRulesEqual for port forwards. InternalIP and
// InternalPort are the translation target: a change there redirects inbound
// traffic to a different host, which is the change this comparison exists to
// surface.
//
// When a field is added to common.InboundNATRule it belongs here.
// TestInboundNATRulesEqual_ComparesEveryField fails until it is.
func inboundNATRulesEqual(a, b common.InboundNATRule) bool {
	return slices.Equal(a.Interfaces, b.Interfaces) &&
		a.IPProtocol == b.IPProtocol &&
		a.Protocol == b.Protocol &&
		endpointsEqual(a.Source, b.Source) &&
		endpointsEqual(a.Destination, b.Destination) &&
		a.ExternalPort == b.ExternalPort &&
		objectRefsEqual(a.ExternalPortRef, b.ExternalPortRef) &&
		a.InternalIP == b.InternalIP &&
		objectRefsEqual(a.InternalIPRef, b.InternalIPRef) &&
		a.InternalPort == b.InternalPort &&
		objectRefsEqual(a.InternalPortRef, b.InternalPortRef) &&
		a.LocalPort == b.LocalPort &&
		objectRefsEqual(a.LocalPortRef, b.LocalPortRef) &&
		a.Reflection == b.Reflection &&
		a.NATReflection == b.NATReflection &&
		a.AssociatedRuleID == b.AssociatedRuleID &&
		a.Priority == b.Priority &&
		a.NoRDR == b.NoRDR &&
		a.NoSync == b.NoSync &&
		a.Disabled == b.Disabled &&
		a.Log == b.Log &&
		a.Description == b.Description
}

// natRuleSimilarity scores how likely two outbound NAT rules are the same rule
// after an edit.
func natRuleSimilarity(a, b common.NATRule) int {
	score := 0

	if a.Description != "" && a.Description == b.Description {
		score += natSimWeightDescription
	}

	if slices.Equal(a.Interfaces, b.Interfaces) {
		score += natSimWeightInterfaces
	}

	for _, same := range []bool{
		a.Protocol == b.Protocol,
		a.Source.Address == b.Source.Address,
		a.Destination.Address == b.Destination.Address,
		a.Target == b.Target,
	} {
		if same {
			score += natSimWeightField
		}
	}

	return score
}

// inboundNATRuleSimilarity is natRuleSimilarity for port forwards.
func inboundNATRuleSimilarity(a, b common.InboundNATRule) int {
	score := 0

	if a.Description != "" && a.Description == b.Description {
		score += natSimWeightDescription
	}

	if slices.Equal(a.Interfaces, b.Interfaces) {
		score += natSimWeightInterfaces
	}

	for _, same := range []bool{
		a.Protocol == b.Protocol,
		a.ExternalPort == b.ExternalPort,
		a.InternalIP == b.InternalIP,
		a.InternalPort == b.InternalPort,
	} {
		if same {
			score += natSimWeightField
		}
	}

	return score
}

// natRuleDescription names a NAT rule for diff output, falling back to a
// synthesized summary when the operator left the description blank.
func natRuleDescription(rule common.NATRule) string {
	if rule.Description != "" {
		return rule.Description
	}

	return cmp.Or(rule.Source.Address, addressUnknown) + " -> " + cmp.Or(rule.Target, addressUnknown)
}

// inboundNATRuleDescription is natRuleDescription for port forwards.
func inboundNATRuleDescription(rule common.InboundNATRule) string {
	if rule.Description != "" {
		return rule.Description
	}

	return joinHostPort(formatEndpoint(rule.Destination), rule.ExternalPort) +
		" -> " + joinHostPort(cmp.Or(rule.InternalIP, addressUnknown), rule.InternalPort)
}

// formatNATRule renders an outbound NAT rule compactly for diff output.
func formatNATRule(rule common.NATRule) string {
	var parts []string
	if len(rule.Interfaces) > 0 {
		parts = append(parts, "if="+strings.Join(rule.Interfaces, ","))
	}

	if rule.Protocol != "" {
		parts = append(parts, "proto="+rule.Protocol)
	}

	parts = append(parts,
		"src="+formatEndpoint(rule.Source),
		"dst="+formatEndpoint(rule.Destination),
		"target="+cmp.Or(rule.Target, addressUnknown))

	if rule.Disabled {
		parts = append(parts, "disabled")
	}

	return strings.Join(parts, ", ")
}

// formatInboundNATRule renders a port forward compactly for diff output.
//
// Each component is omitted when empty rather than printed as "unknown": a port
// forward's external port lives in Destination.Port on some vendors and in
// ExternalPort on others, so blindly printing both yields "wanip:80:unknown".
func formatInboundNATRule(rule common.InboundNATRule) string {
	var parts []string
	if len(rule.Interfaces) > 0 {
		parts = append(parts, "if="+strings.Join(rule.Interfaces, ","))
	}

	if rule.Protocol != "" {
		parts = append(parts, "proto="+rule.Protocol)
	}

	parts = append(parts,
		"ext="+joinHostPort(formatEndpoint(rule.Destination), rule.ExternalPort),
		"int="+joinHostPort(cmp.Or(rule.InternalIP, addressUnknown), rule.InternalPort))

	if rule.Disabled {
		parts = append(parts, "disabled")
	}

	return strings.Join(parts, ", ")
}

// joinHostPort appends ":port" to host only when port is set and host does not
// already carry one (formatEndpoint adds the endpoint's own port).
func joinHostPort(host, port string) string {
	if port == "" || strings.Contains(host, ":") {
		return host
	}

	return host + ":" + port
}

// compareOutboundNATRules reports per-rule outbound NAT changes.
//
// This previously compared only len(old) != len(new), so every content change
// that left the count intact was invisible: retargeting a rule, moving it to
// another interface, or disabling it all reported nothing.
func compareOutboundNATRules(old, newCfg []common.NATRule) []Change {
	var changes []Change

	pairer := itemPairer[common.NATRule]{
		identity:   natRuleIdentity,
		equal:      natRulesEqual,
		similarity: natRuleSimilarity,
		minScore:   natSimMinScore,
		maxPairs:   natSimMaxPairs,
	}

	res := pairer.pair(old, newCfg, func(oi, ni int) {
		if natRulesEqual(old[oi], newCfg[ni]) {
			return
		}

		changes = append(changes, Change{
			Type:        ChangeModified,
			Section:     SectionNAT,
			Path:        fmt.Sprintf("nat.outbound.rules[%d]", ni),
			Description: "Modified outbound NAT rule: " + natRuleDescription(newCfg[ni]),
			OldValue:    formatNATRule(old[oi]),
			NewValue:    formatNATRule(newCfg[ni]),
		})
	})

	for i, paired := range res.oldPaired {
		if !paired {
			changes = append(changes, Change{
				Type:        ChangeRemoved,
				Section:     SectionNAT,
				Path:        fmt.Sprintf("nat.outbound.rules[%d]", i),
				Description: "Removed outbound NAT rule: " + natRuleDescription(old[i]),
				OldValue:    formatNATRule(old[i]),
			})
		}
	}

	for i, paired := range res.newPaired {
		if !paired {
			changes = append(changes, Change{
				Type:        ChangeAdded,
				Section:     SectionNAT,
				Path:        fmt.Sprintf("nat.outbound.rules[%d]", i),
				Description: "Added outbound NAT rule: " + natRuleDescription(newCfg[i]),
				NewValue:    formatNATRule(newCfg[i]),
			})
		}
	}

	return changes
}

// compareInboundNATRules reports per-rule port-forward changes.
//
// Like the outbound rules this compared only the count, so a port forward
// retargeted to a different internal host -- the most consequential NAT change
// there is -- produced no diff entry. The nat.inbound path makes the security
// scorer's port-forward-change pattern apply to every entry.
func compareInboundNATRules(old, newCfg []common.InboundNATRule) []Change {
	var changes []Change

	pairer := itemPairer[common.InboundNATRule]{
		identity:   inboundNATRuleIdentity,
		equal:      inboundNATRulesEqual,
		similarity: inboundNATRuleSimilarity,
		minScore:   natSimMinScore,
		maxPairs:   natSimMaxPairs,
	}

	res := pairer.pair(old, newCfg, func(oi, ni int) {
		if inboundNATRulesEqual(old[oi], newCfg[ni]) {
			return
		}

		changes = append(changes, Change{
			Type:        ChangeModified,
			Section:     SectionNAT,
			Path:        fmt.Sprintf("nat.inbound.rules[%d]", ni),
			Description: "Modified port forward: " + inboundNATRuleDescription(newCfg[ni]),
			OldValue:    formatInboundNATRule(old[oi]),
			NewValue:    formatInboundNATRule(newCfg[ni]),
		})
	})

	for i, paired := range res.oldPaired {
		if !paired {
			changes = append(changes, Change{
				Type:        ChangeRemoved,
				Section:     SectionNAT,
				Path:        fmt.Sprintf("nat.inbound.rules[%d]", i),
				Description: "Removed port forward: " + inboundNATRuleDescription(old[i]),
				OldValue:    formatInboundNATRule(old[i]),
			})
		}
	}

	for i, paired := range res.newPaired {
		if !paired {
			changes = append(changes, Change{
				Type:           ChangeAdded,
				Section:        SectionNAT,
				Path:           fmt.Sprintf("nat.inbound.rules[%d]", i),
				Description:    "Added port forward: " + inboundNATRuleDescription(newCfg[i]),
				NewValue:       formatInboundNATRule(newCfg[i]),
				SecurityImpact: "high",
			})
		}
	}

	return changes
}
