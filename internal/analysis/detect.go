package analysis

import (
	"fmt"
	"maps"
	"net"
	"slices"
	"strings"

	"github.com/EvilBit-Labs/opnDossier/internal/constants"
	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
)

// ComputeAnalysis performs lightweight analysis of the device configuration and returns
// an Analysis suitable for serialization in JSON/YAML exports. The returned Analysis is
// derived purely from cfg with no side effects. A nil cfg returns an empty Analysis.
func ComputeAnalysis(cfg *common.CommonDevice) *common.Analysis {
	if cfg == nil {
		return &common.Analysis{}
	}

	return &common.Analysis{
		DeadRules:         DetectDeadRules(cfg),
		UnusedInterfaces:  DetectUnusedInterfaces(cfg),
		SecurityIssues:    DetectSecurityIssues(cfg),
		PerformanceIssues: DetectPerformanceIssues(cfg),
		ConsistencyIssues: DetectConsistency(cfg),
		ShadowedRules:     DetectShadowedRules(cfg),
	}
}

// deadRuleOwnerKey identifies one (interface, owner rule index) pair in the
// legacy per-interface, raw-position bucketing DetectDeadRules re-projects
// onto (see normalizeForDeadRuleView and DetectDeadRules doc comment). The
// owner is the winner rule for both kinds: the block-all rule for an
// unreachable finding, the earlier rule for a duplicate finding.
type deadRuleOwnerKey struct {
	iface string
	owner int
}

// DetectDeadRules detects unreachable and duplicate firewall rules. It is a
// compatibility view *derived* from the shared shadow-detection core
// (ADR-0004, R16): the unreachable-plus-duplicate subset of
// DetectShadowedRules, re-projected into the legacy DeadRuleFinding shape
// and legacy per-interface, raw-list-position ordering. Each finding carries
// a Kind field ("unreachable" or "duplicate") for structured classification.
// Returns nil when no dead rules are found.
//
// The shadow core groups rules by (interface, direction) with floating-first
// reordering (internal/analysis/precedence.go), but the pre-existing
// DetectDeadRules output — pinned byte-for-byte by this file's test suite —
// buckets by interface name only and orders by raw per-interface list
// position, with no notion of direction, quick, or floating rules.
// normalizeForDeadRuleView collapses the shadow core's grouping back down to
// that legacy shape before calling DetectShadowedRules; the flatten loop
// below then re-projects the filtered result using the *original* rules'
// interface bindings and positions so output ordering is unchanged.
func DetectDeadRules(cfg *common.CommonDevice) []common.DeadRuleFinding {
	if cfg == nil || len(cfg.FirewallRules) == 0 {
		return nil
	}

	shadows := DetectShadowedRules(normalizeForDeadRuleView(cfg))

	// A pair can independently satisfy both conditions (e.g. two identical
	// block-all rules in a row are both an unreachable pair and a duplicate
	// pair), so both maps are populated from the same scan rather than
	// partitioning pairs into one bucket or the other. unreachableOwners is
	// a set: unlike duplicates, the legacy view emits exactly one
	// unreachable finding per block-all owner regardless of how many later
	// rules it shadows.
	unreachableOwners := make(map[deadRuleOwnerKey]bool)
	duplicatesByOwner := make(map[deadRuleOwnerKey][]common.ShadowedRuleFinding)

	for _, f := range shadows {
		if f.Kind != common.ShadowKindFull {
			continue
		}

		winner := cfg.FirewallRules[f.ShadowedByIndex]
		loser := cfg.FirewallRules[f.RuleIndex]
		key := deadRuleOwnerKey{iface: f.Interface, owner: f.ShadowedByIndex}

		if isBlockAllRule(winner) {
			unreachableOwners[key] = true
		}

		if RulesEquivalent(winner, loser) {
			duplicatesByOwner[key] = append(duplicatesByOwner[key], f)
		}
	}

	// Group rules by interface — unchanged from the pre-derivation
	// implementation, and the source of the legacy ordering the flatten
	// loop below reproduces.
	interfaceRules := make(map[string][]IndexedRule)
	for i, rule := range cfg.FirewallRules {
		for _, iface := range rule.Interfaces {
			interfaceRules[iface] = append(interfaceRules[iface], IndexedRule{Index: i, Rule: rule})
		}
	}

	var findings []common.DeadRuleFinding

	for _, iface := range slices.Sorted(maps.Keys(interfaceRules)) {
		for _, ir := range interfaceRules[iface] {
			key := deadRuleOwnerKey{iface: iface, owner: ir.Index}

			if unreachableOwners[key] {
				findings = append(findings, common.DeadRuleFinding{
					Kind:      common.DeadRuleKindUnreachable,
					RuleIndex: ir.Index,
					Interface: iface,
					Description: fmt.Sprintf(
						"Rules after position %d on interface %s are unreachable due to preceding block-all rule",
						ir.Index+1, iface,
					),
					Recommendation: "Remove unreachable rules or reorder them before the block-all rule",
				})
			}

			// duplicatesByOwner[key] preserves ascending loser-index order:
			// DetectShadowedRules sorts its output by (interface, direction,
			// RuleIndex, ShadowedByIndex), and filtering a sorted slice down
			// to one owner preserves the relative RuleIndex ordering — the
			// same order the pre-derivation nested loop produced.
			for _, dup := range duplicatesByOwner[key] {
				findings = append(findings, common.DeadRuleFinding{
					Kind:      common.DeadRuleKindDuplicate,
					RuleIndex: dup.RuleIndex,
					Interface: iface,
					Description: fmt.Sprintf(
						"Rule at position %d is duplicate of rule at position %d on interface %s",
						dup.RuleIndex+1, ir.Index+1, iface,
					),
					Recommendation: "Remove duplicate rule to simplify configuration",
				})
			}
		}
	}

	return findings
}

// isBlockAllRule reports whether rule is the terminal-default-deny shape
// DetectDeadRules classifies as an "unreachable" owner: a block-all matching
// any source and any destination. This mirrors the shape the pre-derivation
// implementation checked directly (RuleTypeBlock only; the legacy view never
// considered RuleTypeReject) — DetectDeadRules' byte-for-byte legacy output
// contract depends on this staying Block-only. Use isTerminalDenyRule
// instead for any new check that should also recognize RuleTypeReject (e.g.
// the R9 shadow-detection guard in shadow.go).
func isBlockAllRule(rule common.FirewallRule) bool {
	return rule.Type == common.RuleTypeBlock &&
		rule.Source.Address == constants.NetworkAny &&
		rule.Destination.Address == constants.NetworkAny
}

// isTerminalDenyRule reports whether rule is a block-all OR reject-all
// matching any source and any destination — the terminal default-deny shape
// R9 exempts from shadow reporting regardless of whether the operator wrote
// "block" or "reject". Unlike isBlockAllRule (kept Block-only to preserve
// DetectDeadRules' legacy byte-for-byte output), this is used by the R9
// shadow-detection guard, where a terminal `reject any->any` below specific
// passes is exactly as legitimate a default-deny pattern as a terminal
// `block any->any` and must not produce a false-positive Security shadow.
func isTerminalDenyRule(rule common.FirewallRule) bool {
	return (rule.Type == common.RuleTypeBlock || rule.Type == common.RuleTypeReject) &&
		rule.Source.Address == constants.NetworkAny &&
		rule.Destination.Address == constants.NetworkAny
}

// normalizeForDeadRuleView builds a shallow clone of cfg whose firewall
// rules are given a uniform Direction (DirectionIn), Quick=true, and
// Floating=false. The legacy DetectDeadRules algorithm never modeled
// direction, quick-vs-non-quick precedence, or floating rules — it grouped
// purely by interface name and treated the earlier rule in each per-interface
// list as always taking precedence. Forcing every rule into the "in" bucket
// with quick (first-match, earlier-wins) semantics and no floating
// device-wide join collapses the shadow core's (interface, direction)
// grouping (internal/analysis/precedence.go) back down to exactly that
// legacy per-interface, raw-list-order shape:
//   - Direction=in uniformly means every rule joins only the "in" bucket for
//     its own interfaces, so each interface has exactly one populated group
//     (no double-counting across "in"/"out" buckets).
//   - Quick=true uniformly means the earlier-positioned rule in a group
//     always wins an overlap it covers, matching the legacy assumption that
//     an earlier block-all or duplicate rule is the "owner".
//   - Floating=false uniformly means an unscoped floating rule (Floating=
//     true, no Interfaces) never joins any group — exactly reproducing the
//     legacy blind spot, where such a rule has no entry in `rule.Interfaces`
//     and so never appears in any per-interface bucket either.
//
// The clone is a new slice — cfg's own FirewallRules backing array is never
// mutated (immutability invariant; GOTCHAS §21.2).
func normalizeForDeadRuleView(cfg *common.CommonDevice) *common.CommonDevice {
	normalized := make([]common.FirewallRule, len(cfg.FirewallRules))

	for i, rule := range cfg.FirewallRules {
		rule.Direction = common.DirectionIn
		rule.Quick = true
		rule.Floating = false
		normalized[i] = rule
	}

	return &common.CommonDevice{
		FirewallRules: normalized,
		NamedObjects:  cfg.NamedObjects,
		Interfaces:    cfg.Interfaces,
	}
}

// DetectUnusedInterfaces detects enabled interfaces not referenced by firewall rules,
// DHCP scopes, DNS resolvers (Unbound/DNSMasq), OpenVPN instances, WireGuard, or the
// load balancer. DNS, WireGuard, and load balancer currently assume "lan" binding when
// enabled — this is a known limitation when these services are bound to non-LAN interfaces.
// Returns nil when no unused interfaces are found.
func DetectUnusedInterfaces(cfg *common.CommonDevice) []common.UnusedInterfaceFinding {
	if cfg == nil {
		return nil
	}

	used := make(map[string]bool)

	for _, rule := range cfg.FirewallRules {
		for _, iface := range rule.Interfaces {
			used[iface] = true
		}
	}
	for _, scope := range cfg.DHCP {
		if scope.Enabled {
			used[scope.Interface] = true
		}
	}
	if cfg.DNS.Unbound.Enabled || cfg.DNS.DNSMasq.Enabled {
		used["lan"] = true
	}
	for _, srv := range cfg.VPN.OpenVPN.Servers {
		if srv.Interface != "" {
			used[srv.Interface] = true
		}
	}
	for _, cli := range cfg.VPN.OpenVPN.Clients {
		if cli.Interface != "" {
			used[cli.Interface] = true
		}
	}
	if cfg.VPN.WireGuard.Enabled {
		used["lan"] = true
	}
	if len(cfg.LoadBalancer.MonitorTypes) > 0 {
		used["lan"] = true
	}

	var findings []common.UnusedInterfaceFinding
	for _, iface := range cfg.Interfaces {
		if iface.Enabled && !used[iface.Name] {
			findings = append(findings, common.UnusedInterfaceFinding{
				InterfaceName: iface.Name,
				Description: fmt.Sprintf(
					"Interface %s is enabled but not used in any rules or services",
					strings.ToUpper(iface.Name),
				),
				Recommendation: "Consider disabling unused interface or add appropriate rules",
			})
		}
	}

	return findings
}

// DetectSecurityIssues detects security configuration issues.
// Returns nil when no security issues are found.
func DetectSecurityIssues(cfg *common.CommonDevice) []common.SecurityFinding {
	if cfg == nil {
		return nil
	}

	var findings []common.SecurityFinding

	if cfg.System.WebGUI.Protocol != "" && cfg.System.WebGUI.Protocol != constants.ProtocolHTTPS {
		findings = append(findings, common.SecurityFinding{
			Component:      "system.webgui.protocol",
			Issue:          "Insecure Web GUI Protocol",
			Severity:       common.SeverityCritical,
			Description:    "Web GUI is configured to use HTTP instead of HTTPS",
			Recommendation: "Change web GUI protocol to HTTPS for secure administration",
		})
	}

	if cfg.SNMP.ROCommunity == "public" {
		findings = append(findings, common.SecurityFinding{
			Component:      "snmpd.rocommunity",
			Issue:          "Default SNMP Community String",
			Severity:       common.SeverityHigh,
			Description:    "SNMP is using the default 'public' community string",
			Recommendation: "Change SNMP community string to a secure, non-default value",
		})
	}

	for i, rule := range cfg.FirewallRules {
		if !rule.Disabled && rule.Type == common.RuleTypePass && rule.Source.Address == constants.NetworkAny &&
			RuleReachability(rule, cfg.Interfaces) == WANReachable {
			findings = append(findings, common.SecurityFinding{
				Component:      fmt.Sprintf("filter.rule[%d]", i),
				Issue:          "Overly Permissive WAN Rule",
				Severity:       common.SeverityHigh,
				Description:    fmt.Sprintf("Rule %d allows any source to pass traffic on WAN interface", i+1),
				Recommendation: "Restrict source networks or add specific destination restrictions",
			})
		}
	}

	return findings
}

// DetectPerformanceIssues detects performance configuration issues.
// Returns nil when no performance issues are found.
func DetectPerformanceIssues(cfg *common.CommonDevice) []common.PerformanceFinding {
	if cfg == nil {
		return nil
	}

	var findings []common.PerformanceFinding

	if cfg.System.DisableChecksumOffloading {
		findings = append(findings, common.PerformanceFinding{
			Component:      "system.disablechecksumoffloading",
			Issue:          "Checksum Offloading Disabled",
			Severity:       common.SeverityLow,
			Description:    "Hardware checksum offloading is disabled, which may impact performance",
			Recommendation: "Enable checksum offloading unless experiencing specific hardware issues",
		})
	}

	if cfg.System.DisableSegmentationOffloading {
		findings = append(findings, common.PerformanceFinding{
			Component:      "system.disablesegmentationoffloading",
			Issue:          "Segmentation Offloading Disabled",
			Severity:       common.SeverityLow,
			Description:    "Hardware segmentation offloading is disabled, which may impact performance",
			Recommendation: "Enable segmentation offloading unless experiencing specific hardware issues",
		})
	}

	if len(cfg.FirewallRules) > constants.LargeRuleCountThreshold {
		findings = append(findings, common.PerformanceFinding{
			Component: "filter.rule",
			Issue:     "High Number of Firewall Rules",
			Severity:  common.SeverityMedium,
			Description: fmt.Sprintf(
				"Configuration contains %d firewall rules, which may impact performance",
				len(cfg.FirewallRules),
			),
			Recommendation: "Consider consolidating rules or using aliases to reduce rule count",
		})
	}

	return findings
}

// DetectConsistency detects configuration consistency issues.
// Returns nil when no consistency issues are found.
func DetectConsistency(cfg *common.CommonDevice) []common.ConsistencyFinding {
	if cfg == nil {
		return nil
	}

	var findings []common.ConsistencyFinding

	// Gateway format consistency.
	for _, iface := range cfg.Interfaces {
		if iface.Gateway != "" && iface.IPAddress != "" && iface.Subnet != "" {
			if net.ParseIP(iface.Gateway) == nil {
				findings = append(findings, common.ConsistencyFinding{
					Component: fmt.Sprintf("interfaces.%s.gateway", iface.Name),
					Issue:     "Invalid Gateway Format",
					Severity:  common.SeverityMedium,
					Description: fmt.Sprintf(
						"Gateway %s for interface %s appears to be invalid",
						iface.Gateway, iface.Name,
					),
					Recommendation: "Verify gateway IP address format and reachability",
				})
			}
		}
	}

	// DHCP without interface IP.
	lanDHCP := FindDHCPScope(cfg.DHCP, "lan")
	if lanDHCP != nil && lanDHCP.Enabled && lanDHCP.Range.From != "" && lanDHCP.Range.To != "" {
		lanIface := FindInterface(cfg.Interfaces, "lan")
		if lanIface != nil && lanIface.IPAddress == "" {
			findings = append(findings, common.ConsistencyFinding{
				Component:      "dhcpd.lan",
				Issue:          "DHCP Enabled Without Interface IP",
				Severity:       common.SeverityHigh,
				Description:    "DHCP is enabled on LAN interface but the interface has no IP address configured",
				Recommendation: "Configure LAN interface IP address or disable DHCP service",
			})
		}
	}

	// User-group consistency.
	existingGroups := make(map[string]bool)
	for _, group := range cfg.Groups {
		existingGroups[group.Name] = true
	}
	for i, user := range cfg.Users {
		if user.GroupName != "" && !existingGroups[user.GroupName] {
			findings = append(findings, common.ConsistencyFinding{
				Component: fmt.Sprintf("system.user[%d].groupname", i),
				Issue:     "User References Non-existent Group",
				Severity:  common.SeverityMedium,
				Description: fmt.Sprintf(
					"User %s references group %s which does not exist",
					user.Name, user.GroupName,
				),
				Recommendation: "Create the referenced group or update user's group assignment",
			})
		}
	}

	return findings
}
