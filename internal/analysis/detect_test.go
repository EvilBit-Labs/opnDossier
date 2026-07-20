package analysis_test

import (
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/analysis"
	"github.com/EvilBit-Labs/opnDossier/internal/constants"
	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestComputeAnalysis(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name                  string
		cfg                   *common.CommonDevice
		wantDeadRules         int
		wantUnusedInterfaces  int
		wantSecurityIssues    int
		wantPerformanceIssues int
		wantConsistencyIssues int
	}{
		{
			name: "minimal device produces no findings",
			cfg:  &common.CommonDevice{},
		},
		{
			name: "nil device produces no findings",
			cfg:  nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result := analysis.ComputeAnalysis(tt.cfg)

			require.NotNil(t, result)
			assert.Len(t, result.DeadRules, tt.wantDeadRules)
			assert.Len(t, result.UnusedInterfaces, tt.wantUnusedInterfaces)
			assert.Len(t, result.SecurityIssues, tt.wantSecurityIssues)
			assert.Len(t, result.PerformanceIssues, tt.wantPerformanceIssues)
			assert.Len(t, result.ConsistencyIssues, tt.wantConsistencyIssues)
		})
	}
}

//nolint:funlen // test table or data declaration; length is in data not logic
func TestDetectDeadRules(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		cfg          *common.CommonDevice
		wantCount    int
		wantIndex    int
		wantIface    string
		wantContains string
		wantKind     string
	}{
		{
			name:      "nil device",
			cfg:       nil,
			wantCount: 0,
		},
		{
			name:      "empty rules",
			cfg:       &common.CommonDevice{},
			wantCount: 0,
		},
		{
			name: "block-all with subsequent rules",
			cfg: &common.CommonDevice{
				FirewallRules: []common.FirewallRule{
					{
						Type:        common.RuleTypeBlock,
						Interfaces:  []string{"wan"},
						Source:      common.RuleEndpoint{Address: "any"},
						Destination: common.RuleEndpoint{Address: "any"},
					},
					{
						Type:        common.RuleTypePass,
						Interfaces:  []string{"wan"},
						Source:      common.RuleEndpoint{Address: "192.168.1.0/24"},
						Destination: common.RuleEndpoint{Address: "10.0.0.0/8"},
					},
				},
			},
			wantCount:    1,
			wantIndex:    0,
			wantIface:    "wan",
			wantContains: "unreachable",
			wantKind:     common.DeadRuleKindUnreachable,
		},
		{
			name: "block-all as last rule produces no finding",
			cfg: &common.CommonDevice{
				FirewallRules: []common.FirewallRule{
					{
						Type:        common.RuleTypePass,
						Interfaces:  []string{"wan"},
						Source:      common.RuleEndpoint{Address: "192.168.1.0/24"},
						Destination: common.RuleEndpoint{Address: "any"},
					},
					{
						Type:        common.RuleTypeBlock,
						Interfaces:  []string{"wan"},
						Source:      common.RuleEndpoint{Address: "any"},
						Destination: common.RuleEndpoint{Address: "any"},
					},
				},
			},
			wantCount: 0,
		},
		{
			name: "duplicate rules detected",
			cfg: &common.CommonDevice{
				FirewallRules: []common.FirewallRule{
					{
						Type:        common.RuleTypePass,
						IPProtocol:  common.IPProtocolInet,
						Interfaces:  []string{"lan"},
						Source:      common.RuleEndpoint{Address: "192.168.1.0/24"},
						Destination: common.RuleEndpoint{Address: "any"},
					},
					{
						Type:        common.RuleTypePass,
						IPProtocol:  common.IPProtocolInet,
						Interfaces:  []string{"lan"},
						Source:      common.RuleEndpoint{Address: "192.168.1.0/24"},
						Destination: common.RuleEndpoint{Address: "any"},
					},
				},
			},
			wantCount:    1,
			wantIndex:    1,
			wantIface:    "lan",
			wantContains: "duplicate",
			wantKind:     common.DeadRuleKindDuplicate,
		},
		{
			name: "three equivalent rules produce findings for each pair",
			cfg: &common.CommonDevice{
				FirewallRules: []common.FirewallRule{
					{
						Type:        common.RuleTypePass,
						IPProtocol:  common.IPProtocolInet,
						Interfaces:  []string{"lan"},
						Source:      common.RuleEndpoint{Address: "192.168.1.0/24"},
						Destination: common.RuleEndpoint{Address: "any"},
					},
					{
						Type:        common.RuleTypePass,
						IPProtocol:  common.IPProtocolInet,
						Interfaces:  []string{"lan"},
						Source:      common.RuleEndpoint{Address: "192.168.1.0/24"},
						Destination: common.RuleEndpoint{Address: "any"},
					},
					{
						Type:        common.RuleTypePass,
						IPProtocol:  common.IPProtocolInet,
						Interfaces:  []string{"lan"},
						Source:      common.RuleEndpoint{Address: "192.168.1.0/24"},
						Destination: common.RuleEndpoint{Address: "any"},
					},
				},
			},
			wantCount:    3,
			wantIndex:    1,
			wantIface:    "lan",
			wantContains: "duplicate",
			wantKind:     common.DeadRuleKindDuplicate,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			findings := analysis.DetectDeadRules(tt.cfg)

			require.Len(t, findings, tt.wantCount)
			if tt.wantCount > 0 {
				assert.Equal(t, tt.wantIndex, findings[0].RuleIndex)
				assert.Equal(t, tt.wantIface, findings[0].Interface)
				assert.Contains(t, findings[0].Description, tt.wantContains)
				assert.Equal(t, tt.wantKind, findings[0].Kind)
			}
		})
	}
}

// TestDetectDeadRules_DisabledNotEquivalent ensures a disabled rule is not
// reported as a duplicate of an otherwise-identical enabled rule. Both
// RulesEquivalent and hashRule must agree on this — if either drops the
// Disabled check, integration output changes silently.
func TestDetectDeadRules_DisabledNotEquivalent(t *testing.T) {
	t.Parallel()

	rule := common.FirewallRule{
		Type:        common.RuleTypePass,
		IPProtocol:  common.IPProtocolInet,
		Interfaces:  []string{"lan"},
		Source:      common.RuleEndpoint{Address: "192.168.1.0/24"},
		Destination: common.RuleEndpoint{Address: "any"},
	}
	disabled := rule
	disabled.Disabled = true

	cfg := &common.CommonDevice{FirewallRules: []common.FirewallRule{rule, disabled}}
	findings := analysis.DetectDeadRules(cfg)
	assert.Empty(t, findings, "disabled rule must not duplicate enabled rule")
}

// TestDetectDeadRules_CrossInterfaceDuplicates ensures that two identical
// multi-interface rules produce one duplicate finding per shared interface.
// Guards the per-interface bucket reset — if buckets ever leak across
// interfaces, counts change.
func TestDetectDeadRules_CrossInterfaceDuplicates(t *testing.T) {
	t.Parallel()

	rule := common.FirewallRule{
		Type:        common.RuleTypePass,
		IPProtocol:  common.IPProtocolInet,
		Interfaces:  []string{"wan", "lan"},
		Source:      common.RuleEndpoint{Address: "192.168.1.0/24"},
		Destination: common.RuleEndpoint{Address: "any"},
	}
	cfg := &common.CommonDevice{FirewallRules: []common.FirewallRule{rule, rule}}

	findings := analysis.DetectDeadRules(cfg)
	require.Len(t, findings, 2)

	seenIfaces := map[string]bool{}
	for _, f := range findings {
		assert.Equal(t, common.DeadRuleKindDuplicate, f.Kind)
		assert.Equal(t, 1, f.RuleIndex)
		seenIfaces[f.Interface] = true
	}
	assert.True(t, seenIfaces["lan"], "expected duplicate finding on lan")
	assert.True(t, seenIfaces["wan"], "expected duplicate finding on wan")
}

// TestDetectDeadRules_BlockAllPlusDuplicate exercises the mixed case: a
// block-all rule followed by two identical pass rules on one interface.
// Expected: one unreachable finding (block-all at index 0) plus one duplicate
// finding (index 2 duplicates index 1).
func TestDetectDeadRules_BlockAllPlusDuplicate(t *testing.T) {
	t.Parallel()

	blockAll := common.FirewallRule{
		Type:        common.RuleTypeBlock,
		Interfaces:  []string{"wan"},
		Source:      common.RuleEndpoint{Address: "any"},
		Destination: common.RuleEndpoint{Address: "any"},
	}
	pass := common.FirewallRule{
		Type:        common.RuleTypePass,
		IPProtocol:  common.IPProtocolInet,
		Interfaces:  []string{"wan"},
		Source:      common.RuleEndpoint{Address: "192.168.1.0/24"},
		Destination: common.RuleEndpoint{Address: "any"},
	}
	cfg := &common.CommonDevice{FirewallRules: []common.FirewallRule{blockAll, pass, pass}}

	findings := analysis.DetectDeadRules(cfg)
	require.Len(t, findings, 2)

	assert.Equal(t, common.DeadRuleKindUnreachable, findings[0].Kind)
	assert.Equal(t, 0, findings[0].RuleIndex)

	assert.Equal(t, common.DeadRuleKindDuplicate, findings[1].Kind)
	assert.Equal(t, 2, findings[1].RuleIndex)
	assert.Contains(t, findings[1].Description, "position 3 is duplicate of rule at position 2")
}

// TestDetectDeadRules_TriplicatePairwise verifies the exact pairwise emission
// contract for three equivalent rules. This is tighter than the existing
// table-based "wantCount: 3" assertion and would catch a regression to a
// first-seen-only scheme (which would drop the rule-3-dup-of-rule-2 finding).
func TestDetectDeadRules_TriplicatePairwise(t *testing.T) {
	t.Parallel()

	rule := common.FirewallRule{
		Type:        common.RuleTypePass,
		IPProtocol:  common.IPProtocolInet,
		Interfaces:  []string{"lan"},
		Source:      common.RuleEndpoint{Address: "192.168.1.0/24"},
		Destination: common.RuleEndpoint{Address: "any"},
	}
	cfg := &common.CommonDevice{FirewallRules: []common.FirewallRule{rule, rule, rule}}

	findings := analysis.DetectDeadRules(cfg)
	require.Len(t, findings, 3)

	type pair struct {
		dupIndex    int
		description string
	}
	want := []pair{
		{dupIndex: 1, description: "position 2 is duplicate of rule at position 1"},
		{dupIndex: 2, description: "position 3 is duplicate of rule at position 1"},
		{dupIndex: 2, description: "position 3 is duplicate of rule at position 2"},
	}
	for i, w := range want {
		assert.Equal(t, common.DeadRuleKindDuplicate, findings[i].Kind, "finding %d kind", i)
		assert.Equal(t, w.dupIndex, findings[i].RuleIndex, "finding %d rule index", i)
		assert.Contains(t, findings[i].Description, w.description, "finding %d description", i)
	}
}

// TestDetectDeadRules_QuadruplicatePairwise locks in the nested-loop ordering
// for equivalence classes of size 4. The old algorithm emits findings grouped
// by the earlier rule's position (i=0 first, then i=1, i=2); a naive hash
// approach that emits when the later rule is visited would interleave
// differently. Reported by Copilot on PR #554.
func TestDetectDeadRules_QuadruplicatePairwise(t *testing.T) {
	t.Parallel()

	rule := common.FirewallRule{
		Type:        common.RuleTypePass,
		IPProtocol:  common.IPProtocolInet,
		Interfaces:  []string{"lan"},
		Source:      common.RuleEndpoint{Address: "192.168.1.0/24"},
		Destination: common.RuleEndpoint{Address: "any"},
	}
	cfg := &common.CommonDevice{FirewallRules: []common.FirewallRule{rule, rule, rule, rule}}

	findings := analysis.DetectDeadRules(cfg)
	require.Len(t, findings, 6)

	type pair struct {
		dupIndex    int
		description string
	}
	want := []pair{
		{dupIndex: 1, description: "position 2 is duplicate of rule at position 1"},
		{dupIndex: 2, description: "position 3 is duplicate of rule at position 1"},
		{dupIndex: 3, description: "position 4 is duplicate of rule at position 1"},
		{dupIndex: 2, description: "position 3 is duplicate of rule at position 2"},
		{dupIndex: 3, description: "position 4 is duplicate of rule at position 2"},
		{dupIndex: 3, description: "position 4 is duplicate of rule at position 3"},
	}
	for i, w := range want {
		assert.Equal(t, common.DeadRuleKindDuplicate, findings[i].Kind, "finding %d kind", i)
		assert.Equal(t, w.dupIndex, findings[i].RuleIndex, "finding %d rule index", i)
		assert.Contains(t, findings[i].Description, w.description, "finding %d description", i)
	}
}

// TestDetectDeadRules_DuplicateBeforeBlockAll ensures that when a block-all
// rule is sandwiched between identical pass rules, the duplicate finding from
// the earlier pass rule precedes the unreachable finding from the block-all
// rule — preserving the per-position ordering of the original nested loop.
func TestDetectDeadRules_DuplicateBeforeBlockAll(t *testing.T) {
	t.Parallel()

	pass := common.FirewallRule{
		Type:        common.RuleTypePass,
		IPProtocol:  common.IPProtocolInet,
		Interfaces:  []string{"wan"},
		Source:      common.RuleEndpoint{Address: "192.168.1.0/24"},
		Destination: common.RuleEndpoint{Address: "any"},
	}
	blockAll := common.FirewallRule{
		Type:        common.RuleTypeBlock,
		Interfaces:  []string{"wan"},
		Source:      common.RuleEndpoint{Address: "any"},
		Destination: common.RuleEndpoint{Address: "any"},
	}
	cfg := &common.CommonDevice{FirewallRules: []common.FirewallRule{pass, blockAll, pass}}

	findings := analysis.DetectDeadRules(cfg)
	require.Len(t, findings, 2)

	assert.Equal(t, common.DeadRuleKindDuplicate, findings[0].Kind)
	assert.Equal(t, 2, findings[0].RuleIndex)
	assert.Contains(t, findings[0].Description, "position 3 is duplicate of rule at position 1")

	assert.Equal(t, common.DeadRuleKindUnreachable, findings[1].Kind)
	assert.Equal(t, 1, findings[1].RuleIndex)
}

// TestDetectDeadRules_EquivalentToShadowSubset pins the ADR-0004 drift
// mitigation: DetectDeadRules(cfg) must equal the unreachable+duplicate
// projection of DetectShadowedRules(cfg) — full shadows whose winner is a
// block-all (unreachable) or whose winner/loser pair is RulesEquivalent
// (duplicate). The fixture gives every rule Direction=in, Quick=true
// explicitly so DetectShadowedRules(cfg) is called on literally the same
// effective shape DetectDeadRules derives internally (see
// normalizeForDeadRuleView) — this isolates the equivalence check from the
// internal normalization and lets the two detectors be compared directly
// over one un-normalized fixture spanning two interfaces.
func TestDetectDeadRules_EquivalentToShadowSubset(t *testing.T) {
	t.Parallel()

	blockAllWAN := common.FirewallRule{
		Type:        common.RuleTypeBlock,
		Interfaces:  []string{"wan"},
		Direction:   common.DirectionIn,
		Quick:       true,
		Source:      common.RuleEndpoint{Address: constants.NetworkAny},
		Destination: common.RuleEndpoint{Address: constants.NetworkAny},
	}
	passWAN := common.FirewallRule{
		Type:        common.RuleTypePass,
		IPProtocol:  common.IPProtocolInet,
		Interfaces:  []string{"wan"},
		Direction:   common.DirectionIn,
		Quick:       true,
		Source:      common.RuleEndpoint{Address: "192.168.1.0/24"},
		Destination: common.RuleEndpoint{Address: constants.NetworkAny},
	}
	dupLAN := common.FirewallRule{
		Type:        common.RuleTypePass,
		IPProtocol:  common.IPProtocolInet,
		Interfaces:  []string{"lan"},
		Direction:   common.DirectionIn,
		Quick:       true,
		Source:      common.RuleEndpoint{Address: "10.0.0.0/24"},
		Destination: common.RuleEndpoint{Address: constants.NetworkAny},
	}

	cfg := &common.CommonDevice{
		FirewallRules: []common.FirewallRule{blockAllWAN, passWAN, dupLAN, dupLAN},
	}

	deadRules := analysis.DetectDeadRules(cfg)
	shadows := analysis.DetectShadowedRules(cfg)

	require.NotEmpty(t, deadRules)
	require.NotEmpty(t, shadows)

	type key struct {
		kind  string
		iface string
		idx   int
	}

	wantUnreachable := make(map[key]bool)
	wantDuplicateCount := make(map[key]int)

	for _, f := range shadows {
		if f.Kind != common.ShadowKindFull {
			continue
		}

		winner := cfg.FirewallRules[f.ShadowedByIndex]
		loser := cfg.FirewallRules[f.RuleIndex]

		if winner.Type == common.RuleTypeBlock &&
			winner.Source.Address == constants.NetworkAny &&
			winner.Destination.Address == constants.NetworkAny {
			wantUnreachable[key{common.DeadRuleKindUnreachable, f.Interface, f.ShadowedByIndex}] = true
		}

		if analysis.RulesEquivalent(winner, loser) {
			wantDuplicateCount[key{common.DeadRuleKindDuplicate, f.Interface, f.RuleIndex}]++
		}
	}

	gotUnreachable := make(map[key]bool)
	gotDuplicateCount := make(map[key]int)

	for _, d := range deadRules {
		k := key{d.Kind, d.Interface, d.RuleIndex}
		switch d.Kind {
		case common.DeadRuleKindUnreachable:
			gotUnreachable[k] = true
		case common.DeadRuleKindDuplicate:
			gotDuplicateCount[k]++
		}
	}

	assert.Equal(t, wantUnreachable, gotUnreachable, "unreachable subset must match shadow projection")
	assert.Equal(t, wantDuplicateCount, gotDuplicateCount, "duplicate subset must match shadow projection")
}

// TestDetectDeadRules_FloatingRuleByteIdentity pins the ADR-0004 legacy
// ordering re-projection for the one case where it matters most: an
// unscoped floating rule (Floating=true, no Interfaces) sitting between a
// block-all and a later duplicate pair. The pre-refactor DetectDeadRules
// grouped rules solely by `rule.Interfaces`, so an unscoped floating rule
// (which binds to no interface) never appeared in any per-interface bucket
// and was invisible to unreachable/duplicate detection — regardless of the
// shadow core's own floating-first, device-wide-join semantics
// (internal/analysis/precedence.go). The expected findings below were
// hand-derived from the pre-refactor algorithm (block-all-not-last emits
// one unreachable finding keyed to its own position; the later identical
// pass pair emits one duplicate finding keyed to the earlier pass's
// position) and confirmed to pass against the original nested-loop
// implementation before the derive-from-shadow rewrite landed.
func TestDetectDeadRules_FloatingRuleByteIdentity(t *testing.T) {
	t.Parallel()

	blockAll := common.FirewallRule{
		Type:        common.RuleTypeBlock,
		Interfaces:  []string{"wan"},
		Source:      common.RuleEndpoint{Address: constants.NetworkAny},
		Destination: common.RuleEndpoint{Address: constants.NetworkAny},
	}
	floating := common.FirewallRule{
		Type:        common.RuleTypePass,
		Floating:    true,
		Source:      common.RuleEndpoint{Address: constants.NetworkAny},
		Destination: common.RuleEndpoint{Address: constants.NetworkAny},
	}
	pass := common.FirewallRule{
		Type:        common.RuleTypePass,
		IPProtocol:  common.IPProtocolInet,
		Interfaces:  []string{"wan"},
		Source:      common.RuleEndpoint{Address: "192.168.1.0/24"},
		Destination: common.RuleEndpoint{Address: constants.NetworkAny},
	}

	cfg := &common.CommonDevice{
		FirewallRules: []common.FirewallRule{blockAll, floating, pass, pass},
	}

	findings := analysis.DetectDeadRules(cfg)
	require.Len(t, findings, 2)

	assert.Equal(t, common.DeadRuleKindUnreachable, findings[0].Kind)
	assert.Equal(t, 0, findings[0].RuleIndex)
	assert.Equal(t, "wan", findings[0].Interface)

	assert.Equal(t, common.DeadRuleKindDuplicate, findings[1].Kind)
	assert.Equal(t, 3, findings[1].RuleIndex)
	assert.Equal(t, "wan", findings[1].Interface)
	assert.Contains(t, findings[1].Description, "position 4 is duplicate of rule at position 3")
}

//nolint:funlen // test table or data declaration; length is in data not logic
func TestDetectUnusedInterfaces(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		cfg       *common.CommonDevice
		wantCount int
		wantNames []string
	}{
		{
			name:      "nil device",
			cfg:       nil,
			wantCount: 0,
		},
		{
			name: "enabled unused interface flagged",
			cfg: &common.CommonDevice{
				Interfaces: []common.Interface{
					{Name: "wan", Enabled: true},
					{Name: "lan", Enabled: true},
					{Name: "opt1", Enabled: true},
					{Name: "opt2", Enabled: false},
				},
				FirewallRules: []common.FirewallRule{
					{Interfaces: []string{"wan"}},
					{Interfaces: []string{"lan"}},
				},
			},
			wantCount: 1,
			wantNames: []string{"opt1"},
		},
		{
			name: "used by DHCP not flagged",
			cfg: &common.CommonDevice{
				Interfaces: []common.Interface{
					{Name: "opt1", Enabled: true},
				},
				DHCP: []common.DHCPScope{
					{Interface: "opt1", Enabled: true},
				},
			},
			wantCount: 0,
		},
		{
			name: "used by OpenVPN server not flagged",
			cfg: &common.CommonDevice{
				Interfaces: []common.Interface{
					{Name: "opt1", Enabled: true},
				},
				VPN: common.VPN{
					OpenVPN: common.OpenVPNConfig{
						Servers: []common.OpenVPNServer{
							{Interface: "opt1"},
						},
					},
				},
			},
			wantCount: 0,
		},
		{
			name: "used by WireGuard not flagged",
			cfg: &common.CommonDevice{
				Interfaces: []common.Interface{
					{Name: "lan", Enabled: true},
				},
				VPN: common.VPN{
					WireGuard: common.WireGuardConfig{Enabled: true},
				},
			},
			wantCount: 0,
		},
		{
			name: "used by DNS not flagged",
			cfg: &common.CommonDevice{
				Interfaces: []common.Interface{
					{Name: "lan", Enabled: true},
				},
				DNS: common.DNSConfig{
					Unbound: common.UnboundConfig{Enabled: true},
				},
			},
			wantCount: 0,
		},
		{
			name: "used by DNSMasq not flagged",
			cfg: &common.CommonDevice{
				Interfaces: []common.Interface{
					{Name: "lan", Enabled: true},
				},
				DNS: common.DNSConfig{
					DNSMasq: common.DNSMasqConfig{Enabled: true},
				},
			},
			wantCount: 0,
		},
		{
			name: "used by OpenVPN client not flagged",
			cfg: &common.CommonDevice{
				Interfaces: []common.Interface{
					{Name: "opt1", Enabled: true},
				},
				VPN: common.VPN{
					OpenVPN: common.OpenVPNConfig{
						Clients: []common.OpenVPNClient{
							{Interface: "opt1"},
						},
					},
				},
			},
			wantCount: 0,
		},
		{
			name: "used by load balancer not flagged",
			cfg: &common.CommonDevice{
				Interfaces: []common.Interface{
					{Name: "lan", Enabled: true},
				},
				LoadBalancer: common.LoadBalancerConfig{
					MonitorTypes: []common.MonitorType{{Name: "http"}},
				},
			},
			wantCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			findings := analysis.DetectUnusedInterfaces(tt.cfg)

			require.Len(t, findings, tt.wantCount)
			for i, name := range tt.wantNames {
				assert.Equal(t, name, findings[i].InterfaceName)
			}
		})
	}
}

func TestDetectSecurityIssues(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		cfg            *common.CommonDevice
		wantCount      int
		wantIssues     []string
		wantSeverities []common.Severity
	}{
		{
			name:      "nil device",
			cfg:       nil,
			wantCount: 0,
		},
		{
			name: "all three issue types",
			cfg: &common.CommonDevice{
				System: common.System{
					WebGUI: common.WebGUI{Protocol: "http"},
				},
				SNMP: common.SNMPConfig{ROCommunity: "public"},
				FirewallRules: []common.FirewallRule{
					{
						Type:       common.RuleTypePass,
						Interfaces: []string{"wan"},
						Source:     common.RuleEndpoint{Address: "any"},
					},
				},
			},
			wantCount: 3,
			wantIssues: []string{
				"Insecure Web GUI Protocol",
				"Default SNMP Community String",
				"Overly Permissive WAN Rule",
			},
			wantSeverities: []common.Severity{common.SeverityCritical, common.SeverityHigh, common.SeverityHigh},
		},
		{
			name: "secure config produces no findings",
			cfg: &common.CommonDevice{
				System: common.System{
					WebGUI: common.WebGUI{Protocol: "https"},
				},
				SNMP: common.SNMPConfig{ROCommunity: "s3cr3t"},
			},
			wantCount: 0,
		},
		{
			name: "empty protocol not flagged",
			cfg: &common.CommonDevice{
				System: common.System{
					WebGUI: common.WebGUI{Protocol: ""},
				},
			},
			wantCount: 0,
		},
		{
			// Covers AE5 / U1 consolidation: the pre-consolidation exact-match
			// WAN check (`slices.Contains(rule.Interfaces, "wan")`) misses
			// multi-WAN interfaces like "wan2". This is the regression test
			// pinning the fix to route through the canonical
			// analysis.RuleReachability helper instead.
			name: "wan2 permissive rule is detected (multi-WAN)",
			cfg: &common.CommonDevice{
				FirewallRules: []common.FirewallRule{
					{
						Type:       common.RuleTypePass,
						Interfaces: []string{"wan2"},
						Source:     common.RuleEndpoint{Address: "any"},
					},
				},
			},
			wantCount:      1,
			wantIssues:     []string{"Overly Permissive WAN Rule"},
			wantSeverities: []common.Severity{common.SeverityHigh},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			findings := analysis.DetectSecurityIssues(tt.cfg)

			require.Len(t, findings, tt.wantCount)
			for i := range tt.wantIssues {
				assert.Equal(t, tt.wantIssues[i], findings[i].Issue)
				assert.Equal(t, tt.wantSeverities[i], findings[i].Severity)
			}
		})
	}
}

func TestDetectPerformanceIssues(t *testing.T) {
	t.Parallel()

	highRuleCount := make([]common.FirewallRule, 101)
	for i := range highRuleCount {
		highRuleCount[i] = common.FirewallRule{Type: common.RuleTypePass, Interfaces: []string{"lan"}}
	}

	tests := []struct {
		name           string
		cfg            *common.CommonDevice
		wantCount      int
		wantIssues     []string
		wantSeverities []common.Severity
	}{
		{
			name:      "nil device",
			cfg:       nil,
			wantCount: 0,
		},
		{
			name:      "no issues on empty device",
			cfg:       &common.CommonDevice{},
			wantCount: 0,
		},
		{
			name: "both offloading disabled",
			cfg: &common.CommonDevice{
				System: common.System{
					DisableChecksumOffloading:     true,
					DisableSegmentationOffloading: true,
				},
			},
			wantCount:      2,
			wantIssues:     []string{"Checksum Offloading Disabled", "Segmentation Offloading Disabled"},
			wantSeverities: []common.Severity{common.SeverityLow, common.SeverityLow},
		},
		{
			name:           "high rule count",
			cfg:            &common.CommonDevice{FirewallRules: highRuleCount},
			wantCount:      1,
			wantIssues:     []string{"High Number of Firewall Rules"},
			wantSeverities: []common.Severity{common.SeverityMedium},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			findings := analysis.DetectPerformanceIssues(tt.cfg)

			require.Len(t, findings, tt.wantCount)
			for i := range tt.wantIssues {
				assert.Equal(t, tt.wantIssues[i], findings[i].Issue)
				assert.Equal(t, tt.wantSeverities[i], findings[i].Severity)
			}
		})
	}
}

func TestDetectConsistency(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		cfg        *common.CommonDevice
		wantCount  int
		wantIssues []string
	}{
		{
			name:      "nil device",
			cfg:       nil,
			wantCount: 0,
		},
		{
			name: "no issues with valid config",
			cfg: &common.CommonDevice{
				Interfaces: []common.Interface{
					{Name: "lan", Enabled: true, IPAddress: "192.168.1.1"},
				},
				DHCP: []common.DHCPScope{
					{
						Interface: "lan",
						Enabled:   true,
						Range:     common.DHCPRange{From: "192.168.1.100", To: "192.168.1.200"},
					},
				},
				Users:  []common.User{{Name: "admin", GroupName: "wheel"}},
				Groups: []common.Group{{Name: "wheel"}},
			},
			wantCount: 0,
		},
		{
			name: "invalid gateway format",
			cfg: &common.CommonDevice{
				Interfaces: []common.Interface{
					{Name: "wan", IPAddress: "1.2.3.4", Subnet: "24", Gateway: "invalid-gw"},
				},
			},
			wantCount:  1,
			wantIssues: []string{"Invalid Gateway Format"},
		},
		{
			name: "valid gateway not flagged",
			cfg: &common.CommonDevice{
				Interfaces: []common.Interface{
					{Name: "wan", IPAddress: "1.2.3.4", Subnet: "24", Gateway: "1.2.3.1"},
				},
			},
			wantCount: 0,
		},
		{
			name: "valid IPv6 gateway not flagged",
			cfg: &common.CommonDevice{
				Interfaces: []common.Interface{
					{Name: "wan", IPAddress: "2001:db8::1", Subnet: "64", Gateway: "fe80::1"},
				},
			},
			wantCount: 0,
		},
		{
			name: "DHCP without interface IP and nonexistent group",
			cfg: &common.CommonDevice{
				Interfaces: []common.Interface{
					{Name: "lan", Enabled: true},
				},
				DHCP: []common.DHCPScope{
					{
						Interface: "lan",
						Enabled:   true,
						Range:     common.DHCPRange{From: "192.168.1.100", To: "192.168.1.200"},
					},
				},
				Users:  []common.User{{Name: "admin", GroupName: "nonexistent"}},
				Groups: []common.Group{{Name: "wheel"}},
			},
			wantCount:  2,
			wantIssues: []string{"DHCP Enabled Without Interface IP", "User References Non-existent Group"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			findings := analysis.DetectConsistency(tt.cfg)

			require.Len(t, findings, tt.wantCount)
			for i, wantIssue := range tt.wantIssues {
				assert.Equal(t, wantIssue, findings[i].Issue)
			}
		})
	}
}
