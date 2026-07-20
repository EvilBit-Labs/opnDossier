package analysis

import (
	"strings"
	"testing"

	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// baseShadowRule returns a firewall rule with every dimension wildcarded and
// Quick=true (interface rules default to quick under pf semantics — see
// GOTCHAS and ADR-0005). Test cases narrow only the dimensions under test.
func baseShadowRule(iface string, dir common.FirewallDirection, ruleType common.FirewallRuleType) common.FirewallRule {
	return common.FirewallRule{
		Type:        ruleType,
		Interfaces:  []string{iface},
		Direction:   dir,
		Quick:       true,
		Source:      common.RuleEndpoint{Address: "any"},
		Destination: common.RuleEndpoint{Address: "any"},
	}
}

func TestDetectShadowedRules_NilOrTooFewRules(t *testing.T) {
	assert.Nil(t, DetectShadowedRules(nil))
	assert.Nil(t, DetectShadowedRules(&common.CommonDevice{}))
	assert.Nil(t, DetectShadowedRules(&common.CommonDevice{
		FirewallRules: []common.FirewallRule{baseShadowRule("wan", common.DirectionIn, common.RuleTypePass)},
	}))
}

// Regression: real OPNsense/pfSense interface rules commonly omit the
// <direction> element, so the converter yields Direction=="". Such rules must
// still be grouped (pf evaluates them as inbound) and produce shadow findings —
// before the empty-direction fix they joined no precedence bucket and the
// detector silently found nothing on typical real configs.
func TestDetectShadowedRules_EmptyDirection_TreatedAsInbound(t *testing.T) {
	earlier := baseShadowRule("wan", "", common.RuleTypePass)
	earlier.Destination.Port = "22"

	later := baseShadowRule("wan", "", common.RuleTypeBlock)
	later.Source.Address = "10.0.0.0/8"
	later.Destination.Port = "22"

	cfg := &common.CommonDevice{FirewallRules: []common.FirewallRule{earlier, later}}

	findings := DetectShadowedRules(cfg)
	require.Len(t, findings, 1, "empty-direction interface rules must still be analyzed")
	assert.Equal(t, common.ShadowKindFull, findings[0].Kind)
	assert.Equal(t, common.ImpactClassSecurity, findings[0].ImpactClass)
	assert.Equal(t, 1, findings[0].RuleIndex)
}

// AE1: quick pass any->any:22 then quick block 10/8->any:22 on WAN in ⇒ full
// shadow of the block, Security, critical (WAN escalation, R6/R12/R14).
func TestDetectShadowedRules_AE1_FullShadow_Security_Critical_WAN(t *testing.T) {
	earlier := baseShadowRule("wan", common.DirectionIn, common.RuleTypePass)
	earlier.Destination.Port = "22"

	later := baseShadowRule("wan", common.DirectionIn, common.RuleTypeBlock)
	later.Source.Address = "10.0.0.0/8"
	later.Destination.Port = "22"

	cfg := &common.CommonDevice{FirewallRules: []common.FirewallRule{earlier, later}}

	findings := DetectShadowedRules(cfg)
	require.Len(t, findings, 1)

	f := findings[0]
	assert.Equal(t, common.ShadowKindFull, f.Kind)
	assert.Equal(t, common.ImpactClassSecurity, f.ImpactClass)
	assert.Equal(t, common.SeverityCritical, f.Severity)
	assert.Equal(t, common.ConfidenceHigh, f.Confidence)
	assert.Equal(t, 1, f.RuleIndex)
	assert.Equal(t, 0, f.ShadowedByIndex)
	assert.Equal(t, "wan", f.Interface)
	assert.Equal(t, string(common.DirectionIn), f.Direction)
	assert.Empty(t, f.Port, "full shadow should not populate the eclipsed-port field")
}

// AE2 (adjusted): the plan's literal AE2 port numbers (1-1024 covering a
// bare 443) compute to CoverFull under U4's already-committed coverage()
// logic (see internal/analysis/overlap_test.go "port range covers single
// port" -> CoverFull), not CoverPartial as the plan's prose states. Using a
// genuinely overlapping-but-not-containing range (500-2000 vs 1-1024, the
// same pairing overlap_test.go itself uses for "port range partially
// overlaps another range" -> CoverPartial) preserves R7's intent: a partial
// shadow, Security, LAN out, severity high (not WAN).
func TestDetectShadowedRules_AE2_PartialShadow_Security_High_LANEgress(t *testing.T) {
	earlier := baseShadowRule("lan", common.DirectionOut, common.RuleTypePass)
	earlier.Source.Address = "10.0.0.0/8"
	earlier.Destination.Port = "1-1024"

	later := baseShadowRule("lan", common.DirectionOut, common.RuleTypeBlock)
	later.Source.Address = "10.0.0.0/8"
	later.Destination.Port = "500-2000"

	cfg := &common.CommonDevice{FirewallRules: []common.FirewallRule{earlier, later}}

	findings := DetectShadowedRules(cfg)
	require.Len(t, findings, 1)

	f := findings[0]
	assert.Equal(t, common.ShadowKindPartial, f.Kind)
	assert.Equal(t, common.ImpactClassSecurity, f.ImpactClass)
	assert.Equal(t, common.SeverityHigh, f.Severity)
	assert.Equal(t, common.ConfidenceHigh, f.Confidence)
	assert.Equal(t, "500-2000", f.Port, "eclipsed port should be a best-effort read of the loser's destination port")
}

// AE3: quick pass any->any:443 then quick pass 10/8->any:443 ⇒ the later
// rule is redundant, Hygiene, low (R6/R12).
func TestDetectShadowedRules_AE3_Hygiene_Redundant(t *testing.T) {
	earlier := baseShadowRule("lan", common.DirectionIn, common.RuleTypePass)
	earlier.Destination.Port = "443"

	later := baseShadowRule("lan", common.DirectionIn, common.RuleTypePass)
	later.Source.Address = "10.0.0.0/8"
	later.Destination.Port = "443"

	cfg := &common.CommonDevice{FirewallRules: []common.FirewallRule{earlier, later}}

	findings := DetectShadowedRules(cfg)
	require.Len(t, findings, 1)

	f := findings[0]
	assert.Equal(t, common.ShadowKindFull, f.Kind)
	assert.Equal(t, common.ImpactClassHygiene, f.ImpactClass)
	assert.Equal(t, common.SeverityLow, f.Severity)
	assert.Equal(t, 1, f.RuleIndex)
	assert.Equal(t, 0, f.ShadowedByIndex)
}

// AE4: quick block any->any:80 then quick pass 10/8->any:80 ⇒ the pass is
// shadowed, Troubleshooting (R6/R12).
func TestDetectShadowedRules_AE4_Troubleshooting(t *testing.T) {
	earlier := baseShadowRule("lan", common.DirectionIn, common.RuleTypeBlock)
	earlier.Destination.Port = "80"

	later := baseShadowRule("lan", common.DirectionIn, common.RuleTypePass)
	later.Source.Address = "10.0.0.0/8"
	later.Destination.Port = "80"

	cfg := &common.CommonDevice{FirewallRules: []common.FirewallRule{earlier, later}}

	findings := DetectShadowedRules(cfg)
	require.Len(t, findings, 1)

	f := findings[0]
	assert.Equal(t, common.ImpactClassTroubleshooting, f.ImpactClass)
	assert.Equal(t, 1, f.RuleIndex, "the later pass rule is the loser under quick semantics")
	assert.Equal(t, 0, f.ShadowedByIndex)
}

// AE5: two specific quick allows above a terminal quick block any->any on
// the same interface/direction ⇒ no shadow finding at all (R9). Without the
// R9 guard, each pass rule would partially "cover" the block-all on the
// wildcarded port dimension (their narrow port is a subset of "any"),
// producing a false-positive Security shadow against the intended
// default-deny.
func TestDetectShadowedRules_AE5_DefaultDeny_NonFinding(t *testing.T) {
	allow443 := baseShadowRule("lan", common.DirectionIn, common.RuleTypePass)
	allow443.Destination.Port = "443"

	allow80 := baseShadowRule("lan", common.DirectionIn, common.RuleTypePass)
	allow80.Destination.Port = "80"

	blockAll := baseShadowRule("lan", common.DirectionIn, common.RuleTypeBlock)

	cfg := &common.CommonDevice{FirewallRules: []common.FirewallRule{allow443, allow80, blockAll}}

	findings := DetectShadowedRules(cfg)
	assert.Empty(t, findings, "a terminal default-deny below specific allows must never be reported as a shadow")
}

// TestDetectShadowedRules_AllFloating_ProducesShadow is the P2 regression
// paired with precedence_test.go's
// TestResolvePrecedence_AllFloating_SeedsFromDeviceInterfaces: a device with
// a single interface and ONLY unscoped floating rules (no interface-bound
// rules at all) must still be evaluated for shadows. This mirrors AE1's
// exact shape (quick pass any->any:22, then quick block 10/8->any:22 — the
// earlier pass fully covers the later block on every dimension) using
// floating rules instead of interface-bound ones.
func TestDetectShadowedRules_AllFloating_ProducesShadow(t *testing.T) {
	earlier := floatingRule()
	earlier.Type = common.RuleTypePass
	earlier.Quick = true
	earlier.Destination.Port = "22"

	later := floatingRule()
	later.Type = common.RuleTypeBlock
	later.Quick = true
	later.Source.Address = "10.0.0.0/8"
	later.Destination.Port = "22"

	cfg := &common.CommonDevice{
		FirewallRules: []common.FirewallRule{earlier, later},
		Interfaces:    []common.Interface{{Name: "lan"}},
	}

	findings := DetectShadowedRules(cfg)
	require.Len(t, findings, 1, "an all-floating ruleset must still be evaluated against the device's own interfaces")

	f := findings[0]
	assert.Equal(t, "lan", f.Interface)
	assert.Equal(t, common.ImpactClassSecurity, f.ImpactClass)
	assert.Equal(t, common.ShadowKindFull, f.Kind)
	assert.Equal(t, 1, f.RuleIndex, "the later block rule is shadowed by the earlier quick pass")
	assert.Equal(t, 0, f.ShadowedByIndex)
}

// R10 false-positive regression: a negated source whose literal exactly
// matches the other rule's literal must not produce a confirmed shadow, even
// though the pre-negation coverage computation resolves to CoverFull (see
// overlap_test.go's "negated source with identical literal is indeterminate,
// not full"). Before the coverage() negation guard covered CoverFull (and
// not just CoverPartial), "NOT 10.0.0.0/8" (which actually matches every
// address OUTSIDE that range) vs a plain "10.0.0.0/8" pass rule would
// silently produce a critical Security false positive.
func TestDetectShadowedRules_R10_NegatedIdenticalLiteral_NoFinding(t *testing.T) {
	earlier := baseShadowRule("wan", common.DirectionIn, common.RuleTypePass)
	earlier.Source.Address = "10.0.0.0/8"
	earlier.Source.Negated = true

	later := baseShadowRule("wan", common.DirectionIn, common.RuleTypeBlock)
	later.Source.Address = "10.0.0.0/8"

	cfg := &common.CommonDevice{FirewallRules: []common.FirewallRule{earlier, later}}

	findings := DetectShadowedRules(cfg)
	assert.Empty(
		t,
		findings,
		"a negated source must never produce a confirmed shadow from an identical-literal false containment",
	)
}

// R9/reject regression: AE5's scenario but with a terminal `reject any->any`
// instead of `block any->any`. Before isTerminalDefaultDeny recognized
// RuleTypeReject, the identical ruleset with `reject` (a mainstream
// default-deny pattern) produced a false-positive Security shadow, even
// though the byte-identical `block` version correctly produced zero
// findings.
func TestDetectShadowedRules_AE5_DefaultDeny_Reject_NonFinding(t *testing.T) {
	allow443 := baseShadowRule("lan", common.DirectionIn, common.RuleTypePass)
	allow443.Destination.Port = "443"

	allow80 := baseShadowRule("lan", common.DirectionIn, common.RuleTypePass)
	allow80.Destination.Port = "80"

	rejectAll := baseShadowRule("lan", common.DirectionIn, common.RuleTypeReject)

	cfg := &common.CommonDevice{FirewallRules: []common.FirewallRule{allow443, allow80, rejectAll}}

	findings := DetectShadowedRules(cfg)
	assert.Empty(
		t,
		findings,
		"a terminal reject-based default-deny below specific allows must never be reported as a shadow",
	)
}

// AE6 (adjusted): the plan's literal AE6 (an unqualified pass any->any:WEB
// followed by a block any->any:443, alias WEB={80,443}) computes to
// CoverFull under U4's already-committed coverage() logic — the later
// rule's entire match set (port 443 alone) is fully contained by the
// alias's resolved member set. overlap_test.go's own "alias member
// containment resolves cleanly" case establishes the fix: narrow the
// covering rule's destination address relative to the shadowed rule's so
// the address dimension is genuinely Partial, which then dominates the
// combined result even though the port dimension alone is Full. This
// preserves R4/R8/R12's intent: a Security partial shadow via alias
// resolution.
func TestDetectShadowedRules_AE6_AliasAware_PartialShadow(t *testing.T) {
	no := common.NamedObjects{
		"WEB": common.NamedObject{
			Name:    "WEB",
			Type:    common.NamedObjectTypePort,
			Members: []string{"80", "443"},
		},
	}

	earlier := baseShadowRule("wan", common.DirectionIn, common.RuleTypePass)
	earlier.Destination.Address = "10.0.1.0/24"
	earlier.Destination.Port = "WEB"
	earlier.Destination.PortRef = &common.ObjectRef{Name: "WEB"}

	later := baseShadowRule("wan", common.DirectionIn, common.RuleTypeBlock)
	later.Destination.Address = "10.0.0.0/16"
	later.Destination.Port = "443"

	cfg := &common.CommonDevice{
		FirewallRules: []common.FirewallRule{earlier, later},
		NamedObjects:  no,
	}

	findings := DetectShadowedRules(cfg)
	require.Len(t, findings, 1)

	f := findings[0]
	assert.Equal(t, common.ShadowKindPartial, f.Kind)
	assert.Equal(t, common.ImpactClassSecurity, f.ImpactClass)
	assert.NotEqual(
		t,
		common.ConfidenceLow,
		f.Confidence,
		"a cleanly resolved alias is a confirmed finding, not an advisory",
	)
}

// Non-quick counterpart to AE1-AE4: an earlier broad non-quick block fully
// covered by a later non-quick pass. Under last-match (non-quick) pf
// semantics the LATER rule wins, so the EARLIER block is the loser — the
// mirror image of the quick cases. Classification must key off the
// winner/loser action relationship (winner=pass, loser=block), not
// earlier/later: that is Security by the same rule AE1 exercises (a block
// that never fires because a pass overrides it is the "blocked traffic
// silently flows" case), NOT Troubleshooting. This is deliberately
// asserted: flipping Quick must flip winner/loser (proven by RuleIndex/
// ShadowedByIndex swapping relative to AE4's quick block-then-pass), while
// the impact class must NOT flip along with it, proving classification
// keys off winner/loser action and not rule position.
func TestDetectShadowedRules_NonQuick_WinnerLoserFlip_StillSecurity(t *testing.T) {
	earlier := baseShadowRule("lan", common.DirectionIn, common.RuleTypeBlock)
	earlier.Quick = false
	earlier.Source.Address = "10.0.0.0/8"

	later := baseShadowRule("lan", common.DirectionIn, common.RuleTypePass)
	later.Quick = false

	cfg := &common.CommonDevice{FirewallRules: []common.FirewallRule{earlier, later}}

	findings := DetectShadowedRules(cfg)
	require.Len(t, findings, 1)

	f := findings[0]
	assert.Equal(t, common.ShadowKindFull, f.Kind)
	assert.Equal(t, common.ImpactClassSecurity, f.ImpactClass,
		"winner(pass)->loser(block) is Security regardless of quick/non-quick")
	assert.Equal(t, 0, f.RuleIndex, "under non-quick, the EARLIER block rule is the loser")
	assert.Equal(t, 1, f.ShadowedByIndex, "under non-quick, the LATER pass rule is the winner")
	assert.Equal(t, common.SeverityHigh, f.Severity, "LAN-reachable Security shadow")
}

// R13: a LAN-reachable shadow is emitted — reachability feeds severity but
// never gates whether a finding is emitted at all.
func TestDetectShadowedRules_R13_LANReachableShadowEmitted(t *testing.T) {
	earlier := baseShadowRule("lan", common.DirectionIn, common.RuleTypeBlock)
	earlier.Destination.Port = "80"

	later := baseShadowRule("lan", common.DirectionIn, common.RuleTypePass)
	later.Source.Address = "10.0.0.0/8"
	later.Destination.Port = "80"

	cfg := &common.CommonDevice{FirewallRules: []common.FirewallRule{earlier, later}}

	findings := DetectShadowedRules(cfg)
	require.Len(t, findings, 1)
	assert.Equal(t, "lan", findings[0].Interface)
}

// R14 matrix: the same Security shadow flips high -> critical when the
// loser rule's interface is WAN instead of LAN.
func TestDetectShadowedRules_R14_SeverityEscalatesOnWAN(t *testing.T) {
	buildPair := func(iface string) *common.CommonDevice {
		earlier := baseShadowRule(iface, common.DirectionIn, common.RuleTypePass)
		earlier.Destination.Port = "22"

		later := baseShadowRule(iface, common.DirectionIn, common.RuleTypeBlock)
		later.Source.Address = "10.0.0.0/8"
		later.Destination.Port = "22"

		return &common.CommonDevice{FirewallRules: []common.FirewallRule{earlier, later}}
	}

	lanFindings := DetectShadowedRules(buildPair("lan"))
	require.Len(t, lanFindings, 1)
	assert.Equal(t, common.SeverityHigh, lanFindings[0].Severity)

	wanFindings := DetectShadowedRules(buildPair("wan"))
	require.Len(t, wanFindings, 1)
	assert.Equal(t, common.SeverityCritical, wanFindings[0].Severity)

	assert.Equal(t, lanFindings[0].ImpactClass, wanFindings[0].ImpactClass)
	assert.Equal(t, lanFindings[0].Kind, wanFindings[0].Kind)
}

// R8 advisory: a pass winner over a block loser where the port dimension
// resolves via an unresolvable alias reference (aliasBlocked=true) produces
// exactly one low-confidence advisory finding, carrying the explicit
// "(unconfirmed -- unresolved alias)" marker.
func TestDetectShadowedRules_R8_AdvisoryOnUnresolvableAlias_Security(t *testing.T) {
	earlier := baseShadowRule("wan", common.DirectionIn, common.RuleTypePass)
	earlier.Destination.Port = "UNRESOLVABLE"
	earlier.Destination.PortRef = &common.ObjectRef{Name: "UNRESOLVABLE"}

	later := baseShadowRule("wan", common.DirectionIn, common.RuleTypeBlock)
	// Source must not be exactly "any" or this would collide with the R9
	// terminal-default-deny guard (Type block + Source any + Dest any).
	later.Source.Address = "10.0.0.0/8"
	later.Destination.Port = "443"

	cfg := &common.CommonDevice{
		FirewallRules: []common.FirewallRule{earlier, later},
		NamedObjects:  common.NamedObjects{}, // "UNRESOLVABLE" is not registered
	}

	findings := DetectShadowedRules(cfg)
	require.Len(
		t,
		findings,
		1,
		"exactly one advisory finding, not a duplicate from both the precedence resolver and the advisory scan",
	)

	f := findings[0]
	assert.Equal(t, common.ImpactClassSecurity, f.ImpactClass)
	assert.Equal(t, common.ConfidenceLow, f.Confidence)
	assert.Equal(t, common.SeverityHigh, f.Severity, "WAN advisory row")
	assert.Contains(t, f.Description, "(unconfirmed — unresolved alias)")
}

// R8 silence: the same aliasBlocked shape (unresolvable port alias) in a
// Hygiene or Troubleshooting overlap produces no finding at all.
func TestDetectShadowedRules_R8_SilentOnNonSecurityAliasBlocked(t *testing.T) {
	t.Run("hygiene (pass over pass)", func(t *testing.T) {
		earlier := baseShadowRule("wan", common.DirectionIn, common.RuleTypePass)
		earlier.Destination.Port = "UNRESOLVABLE"
		earlier.Destination.PortRef = &common.ObjectRef{Name: "UNRESOLVABLE"}

		later := baseShadowRule("wan", common.DirectionIn, common.RuleTypePass)
		later.Destination.Port = "443"

		cfg := &common.CommonDevice{FirewallRules: []common.FirewallRule{earlier, later}}

		assert.Empty(t, DetectShadowedRules(cfg))
	})

	t.Run("troubleshooting (block over pass)", func(t *testing.T) {
		earlier := baseShadowRule("wan", common.DirectionIn, common.RuleTypeBlock)
		earlier.Destination.Port = "UNRESOLVABLE"
		earlier.Destination.PortRef = &common.ObjectRef{Name: "UNRESOLVABLE"}

		later := baseShadowRule("wan", common.DirectionIn, common.RuleTypePass)
		later.Destination.Port = "443"

		cfg := &common.CommonDevice{FirewallRules: []common.FirewallRule{earlier, later}}

		assert.Empty(t, DetectShadowedRules(cfg))
	})
}

// Same-action partial overlap classifies as Hygiene (partial redundancy),
// not Troubleshooting.
func TestDetectShadowedRules_SameActionPartialOverlap_Hygiene(t *testing.T) {
	earlier := baseShadowRule("lan", common.DirectionIn, common.RuleTypePass)
	earlier.Destination.Port = "1-1024"

	later := baseShadowRule("lan", common.DirectionIn, common.RuleTypePass)
	later.Destination.Port = "500-2000"

	cfg := &common.CommonDevice{FirewallRules: []common.FirewallRule{earlier, later}}

	findings := DetectShadowedRules(cfg)
	require.Len(t, findings, 1)

	f := findings[0]
	assert.Equal(t, common.ShadowKindPartial, f.Kind)
	assert.Equal(t, common.ImpactClassHygiene, f.ImpactClass)
	assert.Equal(t, common.SeverityLow, f.Severity)
}

// Deterministic ordering: findings across multiple interfaces are sorted by
// interface name.
func TestDetectShadowedRules_DeterministicOrdering(t *testing.T) {
	buildAt := func(iface string) (common.FirewallRule, common.FirewallRule) {
		earlier := baseShadowRule(iface, common.DirectionIn, common.RuleTypePass)
		earlier.Destination.Port = "22"

		later := baseShadowRule(iface, common.DirectionIn, common.RuleTypeBlock)
		later.Source.Address = "10.0.0.0/8"
		later.Destination.Port = "22"

		return earlier, later
	}

	wanEarlier, wanLater := buildAt("wan")
	lanEarlier, lanLater := buildAt("lan")

	cfg := &common.CommonDevice{
		FirewallRules: []common.FirewallRule{wanEarlier, wanLater, lanEarlier, lanLater},
	}

	findings := DetectShadowedRules(cfg)
	require.Len(t, findings, 2)
	assert.Equal(t, "lan", findings[0].Interface, "lan sorts before wan")
	assert.Equal(t, "wan", findings[1].Interface)
}

// ComputeAnalysis wiring: Analysis.ShadowedRules is populated from
// DetectShadowedRules.
func TestComputeAnalysis_PopulatesShadowedRules(t *testing.T) {
	earlier := baseShadowRule("wan", common.DirectionIn, common.RuleTypePass)
	earlier.Destination.Port = "22"

	later := baseShadowRule("wan", common.DirectionIn, common.RuleTypeBlock)
	later.Source.Address = "10.0.0.0/8"
	later.Destination.Port = "22"

	cfg := &common.CommonDevice{FirewallRules: []common.FirewallRule{earlier, later}}

	got := ComputeAnalysis(cfg)
	require.Len(t, got.ShadowedRules, 1)
	assert.Equal(t, common.ImpactClassSecurity, got.ShadowedRules[0].ImpactClass)
}

// Guard against a false-negative test bug: the advisory description marker
// must appear verbatim (em-dash, exact wording) since that string is what
// downstream sorted output uses to distinguish advisory findings.
func TestDetectShadowedRules_AdvisoryMarkerExactText(t *testing.T) {
	earlier := baseShadowRule("wan", common.DirectionIn, common.RuleTypePass)
	earlier.Destination.Port = "UNRESOLVABLE"
	earlier.Destination.PortRef = &common.ObjectRef{Name: "UNRESOLVABLE"}

	later := baseShadowRule("wan", common.DirectionIn, common.RuleTypeBlock)
	later.Source.Address = "10.0.0.0/8"
	later.Destination.Port = "443"

	cfg := &common.CommonDevice{FirewallRules: []common.FirewallRule{earlier, later}}

	findings := DetectShadowedRules(cfg)
	require.Len(t, findings, 1)
	assert.True(t, strings.HasPrefix(findings[0].Description, "(unconfirmed — unresolved alias)"))
}
