package analysis

import (
	"testing"

	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// precedenceRule returns a firewall rule bound to iface/dir with sensible
// wildcard defaults (pass, any protocol, any/any endpoints) so each test
// case only needs to override the field(s) under test.
func precedenceRule(iface string, dir common.FirewallDirection) common.FirewallRule {
	return common.FirewallRule{
		Type:        common.RuleTypePass,
		Interfaces:  []string{iface},
		Direction:   dir,
		Protocol:    "any",
		Source:      common.RuleEndpoint{Address: "any"},
		Destination: common.RuleEndpoint{Address: "any"},
	}
}

// floatingRule returns an unscoped floating rule (Floating && no Interfaces)
// with sensible wildcard defaults, scoped to DirectionIn — every existing
// caller uses DirectionIn (see the unparam finding this comment replaced).
func floatingRule() common.FirewallRule {
	return common.FirewallRule{
		Type:        common.RuleTypePass,
		Floating:    true,
		Direction:   common.DirectionIn,
		Protocol:    "any",
		Source:      common.RuleEndpoint{Address: "any"},
		Destination: common.RuleEndpoint{Address: "any"},
	}
}

func TestResolvePrecedence_QuickEarlierCoversLater(t *testing.T) {
	t.Parallel()

	earlier := precedenceRule("wan", common.DirectionIn)
	earlier.Quick = true
	earlier.Destination.Address = "10.0.0.0/8"

	later := precedenceRule("wan", common.DirectionIn)
	later.Destination.Address = "10.1.0.0/16"

	cfg := &common.CommonDevice{FirewallRules: []common.FirewallRule{earlier, later}}

	pairs := ResolvePrecedence(cfg)

	require.Len(t, pairs, 1)
	assert.Equal(t, 0, pairs[0].Winner.Index, "quick earlier rule wins the overlap")
	assert.Equal(t, 1, pairs[0].Loser.Index, "later rule is shadowed")
	assert.Equal(t, CoverFull, pairs[0].Extent)
}

func TestResolvePrecedence_NonQuickEarlierFullyCoveredByLater(t *testing.T) {
	t.Parallel()

	// Earlier is non-quick (default) and narrower; later is broader and
	// fully covers it. Last-match semantics: later wins, earlier is fully
	// shadowed.
	earlier := precedenceRule("wan", common.DirectionIn)
	earlier.Destination.Address = "10.1.0.0/16"

	later := precedenceRule("wan", common.DirectionIn)
	later.Destination.Address = "10.0.0.0/8"

	cfg := &common.CommonDevice{FirewallRules: []common.FirewallRule{earlier, later}}

	pairs := ResolvePrecedence(cfg)

	require.Len(t, pairs, 1)
	assert.Equal(t, 1, pairs[0].Winner.Index, "later rule wins under last-match")
	assert.Equal(t, 0, pairs[0].Loser.Index, "earlier non-quick rule is shadowed")
	assert.Equal(t, CoverFull, pairs[0].Extent)
}

// TestResolvePrecedence_NonQuickBroadEarlierNarrowerLater_FalsePositiveGuard
// is the ADR-0005 false-positive guard: an earlier broad non-quick rule with
// a later narrower rule below it must not report the later rule as dead.
// Under last-match semantics the later (narrower) rule is still the last
// match for its own traffic, so it stays live; the earlier (broad) rule is
// the one partially shadowed on the overlap subset.
func TestResolvePrecedence_NonQuickBroadEarlierNarrowerLater_FalsePositiveGuard(t *testing.T) {
	t.Parallel()

	earlier := precedenceRule("wan", common.DirectionIn)
	earlier.Destination.Address = "10.0.0.0/8" // broad

	later := precedenceRule("wan", common.DirectionIn)
	later.Destination.Address = "10.1.0.0/16" // narrower, below

	cfg := &common.CommonDevice{FirewallRules: []common.FirewallRule{earlier, later}}

	pairs := ResolvePrecedence(cfg)

	require.Len(t, pairs, 1)
	assert.Equal(t, 1, pairs[0].Winner.Index, "later (narrower) rule wins its own traffic")
	assert.Equal(t, 0, pairs[0].Loser.Index, "earlier (broad) rule is the loser, not the later rule")
	assert.Equal(t, CoverPartial, pairs[0].Extent, "only the overlap subset is shadowed")

	for _, p := range pairs {
		assert.NotEqual(t, 1, p.Loser.Index,
			"later rule must never be reported as shadowed (false-positive guard)")
	}
}

func TestResolvePrecedence_FloatingRulesJoinInterfaceGroupsAheadOfInterfaceBound(t *testing.T) {
	t.Parallel()

	t.Run("non-quick floating loses to later interface rule under last-match", func(t *testing.T) {
		t.Parallel()

		// Floating rule placed AFTER the interface rule in the raw list
		// (index 1), to prove grouping reorders it ahead rather than
		// mirroring raw list order.
		interfaceRule := precedenceRule("wan", common.DirectionIn)
		interfaceRule.Destination.Address = "10.0.0.0/8" // broad, covers floating fully

		floating := floatingRule()
		floating.Destination.Address = "10.1.0.0/16" // narrow, fully covered

		cfg := &common.CommonDevice{FirewallRules: []common.FirewallRule{interfaceRule, floating}}

		pairs := ResolvePrecedence(cfg)

		require.Len(t, pairs, 1)
		assert.Equal(t, 0, pairs[0].Winner.Index, "later interface rule wins under last-match")
		assert.Equal(t, 1, pairs[0].Loser.Index, "floating rule (grouped ahead) is shadowed")
		assert.Equal(t, CoverFull, pairs[0].Extent)
	})

	t.Run("quick floating wins over later interface rule", func(t *testing.T) {
		t.Parallel()

		interfaceRule := precedenceRule("wan", common.DirectionIn)
		interfaceRule.Destination.Address = "10.1.0.0/16" // narrow

		floating := floatingRule()
		floating.Quick = true
		floating.Destination.Address = "10.0.0.0/8" // broad, covers interfaceRule fully

		cfg := &common.CommonDevice{FirewallRules: []common.FirewallRule{interfaceRule, floating}}

		pairs := ResolvePrecedence(cfg)

		require.Len(t, pairs, 1)
		assert.Equal(t, 1, pairs[0].Winner.Index, "quick floating rule (grouped ahead) wins outright")
		assert.Equal(t, 0, pairs[0].Loser.Index, "interface rule is shadowed")
		assert.Equal(t, CoverFull, pairs[0].Extent)
	})

	t.Run("quick floating bound to the interface wins over an earlier quick interface rule", func(t *testing.T) {
		t.Parallel()

		// pfSense compiles every floating rule ahead of interface rules, scoped
		// or not, and its converter keeps document order, so list order between
		// the two does not count.
		interfaceRule := precedenceRule("wan", common.DirectionIn)
		interfaceRule.Quick = true
		interfaceRule.Destination.Address = "10.1.0.0/16" // narrow

		floating := floatingRule()
		floating.Interfaces = []string{"wan"}
		floating.Quick = true
		floating.Destination.Address = "10.0.0.0/8" // broad, covers interfaceRule fully

		cfg := &common.CommonDevice{
			DeviceType:    common.DeviceTypePfSense,
			FirewallRules: []common.FirewallRule{interfaceRule, floating},
		}

		pairs := ResolvePrecedence(cfg)

		require.Len(t, pairs, 1)
		assert.Equal(t, 1, pairs[0].Winner.Index, "scoped quick floating rule (grouped ahead) wins")
		assert.Equal(t, 0, pairs[0].Loser.Index, "interface rule is shadowed")
		assert.Equal(t, CoverFull, pairs[0].Extent)
	})

	t.Run("quick floating bound to several interfaces joins each of their groups", func(t *testing.T) {
		t.Parallel()

		interfaceRule := precedenceRule("lan", common.DirectionIn)
		interfaceRule.Quick = true
		interfaceRule.Destination.Address = "10.1.0.0/16" // narrow

		floating := floatingRule()
		floating.Interfaces = []string{"wan", "lan"}
		floating.Quick = true
		floating.Destination.Address = "10.0.0.0/8" // broad, covers interfaceRule fully

		cfg := &common.CommonDevice{FirewallRules: []common.FirewallRule{interfaceRule, floating}}

		pairs := ResolvePrecedence(cfg)

		require.Len(t, pairs, 1)
		assert.Equal(t, "lan", pairs[0].Interface)
		assert.Equal(t, 1, pairs[0].Winner.Index, "floating rule wins on its second interface too")
		assert.Equal(t, 0, pairs[0].Loser.Index, "interface rule is shadowed")
		assert.Equal(t, CoverFull, pairs[0].Extent)
	})

	t.Run("floating rule bound to another interface stays out of the group", func(t *testing.T) {
		t.Parallel()

		interfaceRule := precedenceRule("wan", common.DirectionIn)
		interfaceRule.Quick = true
		interfaceRule.Destination.Address = "10.1.0.0/16"

		floating := floatingRule()
		floating.Interfaces = []string{"lan"}
		floating.Quick = true
		floating.Destination.Address = "10.0.0.0/8"

		cfg := &common.CommonDevice{FirewallRules: []common.FirewallRule{interfaceRule, floating}}

		assert.Empty(t, ResolvePrecedence(cfg))
	})
}

// TestResolvePrecedence_FloatingRulesKeepListOrder pins floating rules against
// each other: both vendors evaluate them in the order they are listed, with or
// without an interface, so an unscoped one must not jump a scoped one (#921).
func TestResolvePrecedence_FloatingRulesKeepListOrder(t *testing.T) {
	t.Parallel()

	deviceTypes := []struct {
		name       string
		deviceType common.DeviceType
	}{
		{"OPNsense", common.DeviceTypeOPNsense},
		{"pfSense", common.DeviceTypePfSense},
		{"no device type", common.DeviceTypeUnknown},
	}

	for _, tt := range deviceTypes {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			scoped := floatingRule()
			scoped.Type = common.RuleTypeBlock
			scoped.Interfaces = []string{"lan"}
			scoped.Quick = true

			unscoped := floatingRule()
			unscoped.Quick = true

			cfg := func(scopedDestination, unscopedDestination string) *common.CommonDevice {
				first, second := scoped, unscoped
				first.Destination.Address = scopedDestination
				second.Destination.Address = unscopedDestination

				return &common.CommonDevice{
					DeviceType:    tt.deviceType,
					FirewallRules: []common.FirewallRule{first, second},
				}
			}

			// The first rule covers the second, so it wins and the pair is reported.
			pairs := ResolvePrecedence(cfg("10.0.0.0/8", "10.1.0.0/16"))

			require.Len(t, pairs, 1)
			assert.Equal(t, "lan", pairs[0].Interface)
			assert.Equal(t, 0, pairs[0].Winner.Index, "scoped floating block listed first wins")
			assert.Equal(t, 1, pairs[0].Loser.Index, "unscoped floating pass listed second is shadowed")
			assert.Equal(t, CoverFull, pairs[0].Extent)

			// The first rule is narrower, so it only takes part of the second's
			// traffic. Taken in the other order, the block would read as bypassed.
			pairs = ResolvePrecedence(cfg("10.1.0.0/16", "10.0.0.0/8"))

			require.Len(t, pairs, 1)
			assert.Equal(t, 0, pairs[0].Winner.Index, "scoped floating block listed first wins")
			assert.Equal(t, 1, pairs[0].Loser.Index, "unscoped floating pass listed second loses the overlap")
			assert.Equal(t, CoverPartial, pairs[0].Extent)
		})
	}
}

// TestResolvePrecedence_OPNsenseKeepsListOrder covers the list the OPNsense
// converter has put in evaluation order. A rule on one interface can precede a
// floating rule there: the os-firewall plugin ran the filter model's rules ahead
// of every legacy rule (GOTCHAS 3.8). The same list from pfSense, whose converter
// keeps document order, has its floating rule moved first.
func TestResolvePrecedence_OPNsenseKeepsListOrder(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		interfaces []string
	}{
		{"floating rule bound to the interface", []string{"wan"}},
		{"unscoped floating rule", nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			interfaceRule := precedenceRule("wan", common.DirectionIn)
			interfaceRule.Quick = true
			interfaceRule.Destination.Address = "10.0.0.0/8" // broad, covers floating fully

			floating := floatingRule()
			floating.Type = common.RuleTypeBlock
			floating.Interfaces = tt.interfaces
			floating.Quick = true
			floating.Destination.Address = "10.1.0.0/16" // narrow

			rules := []common.FirewallRule{interfaceRule, floating}

			pairs := ResolvePrecedence(&common.CommonDevice{
				DeviceType:    common.DeviceTypeOPNsense,
				FirewallRules: rules,
			})

			require.Len(t, pairs, 1)
			assert.Equal(t, 0, pairs[0].Winner.Index, "the rule listed first wins")
			assert.Equal(t, 1, pairs[0].Loser.Index, "the floating rule listed second is shadowed")
			assert.Equal(t, CoverFull, pairs[0].Extent)

			pairs = ResolvePrecedence(&common.CommonDevice{
				DeviceType:    common.DeviceTypePfSense,
				FirewallRules: rules,
			})

			require.Len(t, pairs, 1)
			assert.Equal(t, 1, pairs[0].Winner.Index, "the floating rule, moved first, wins")
			assert.Equal(t, 0, pairs[0].Loser.Index, "the interface rule loses the overlap")
			assert.Equal(t, CoverPartial, pairs[0].Extent)
		})
	}
}

// TestResolvePrecedence_DisabledRuleCannotWin covers a disabled rule on each side
// of a pair. Both firewalls skip it, so it takes nothing from the other rule, but
// it can still lose: it would lose the same pair if it were enabled.
func TestResolvePrecedence_DisabledRuleCannotWin(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name            string
		earlierQuick    bool
		earlierDisabled bool
		laterDisabled   bool
		wantPair        bool
		wantWinner      int
	}{
		{name: "quick disabled rule above an enabled rule", earlierQuick: true, earlierDisabled: true},
		{name: "disabled rule below a non-quick enabled rule", laterDisabled: true},
		{name: "two disabled rules", earlierQuick: true, earlierDisabled: true, laterDisabled: true},
		{
			name:          "disabled rule below a quick enabled rule still loses",
			earlierQuick:  true,
			laterDisabled: true,
			wantPair:      true,
			wantWinner:    0,
		},
		{
			name:            "non-quick disabled rule above an enabled rule still loses",
			earlierDisabled: true,
			wantPair:        true,
			wantWinner:      1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			earlier := precedenceRule("wan", common.DirectionIn)
			earlier.Quick = tt.earlierQuick
			earlier.Disabled = tt.earlierDisabled

			later := precedenceRule("wan", common.DirectionIn)
			later.Type = common.RuleTypeBlock
			later.Disabled = tt.laterDisabled

			pairs := ResolvePrecedence(&common.CommonDevice{FirewallRules: []common.FirewallRule{earlier, later}})

			if !tt.wantPair {
				assert.Empty(t, pairs)
				return
			}

			require.Len(t, pairs, 1)
			assert.Equal(t, tt.wantWinner, pairs[0].Winner.Index)
			assert.Equal(t, 1-tt.wantWinner, pairs[0].Loser.Index)
		})
	}
}

func TestResolvePrecedence_DirectionScoping(t *testing.T) {
	t.Parallel()

	t.Run("in and out rules never interact", func(t *testing.T) {
		t.Parallel()

		ruleIn := precedenceRule("wan", common.DirectionIn)
		ruleIn.Quick = true
		ruleIn.Destination.Address = "10.0.0.0/8"

		ruleOut := precedenceRule("wan", common.DirectionOut)
		ruleOut.Destination.Address = "10.1.0.0/16"

		cfg := &common.CommonDevice{FirewallRules: []common.FirewallRule{ruleIn, ruleOut}}

		pairs := ResolvePrecedence(cfg)

		assert.Empty(t, pairs, "in and out rules must not be grouped together")
	})

	t.Run("any rule interacts with both in and out rules", func(t *testing.T) {
		t.Parallel()

		ruleAny := precedenceRule("wan", common.DirectionAny)
		ruleAny.Quick = true
		ruleAny.Destination.Address = "10.0.0.0/8"

		ruleIn := precedenceRule("wan", common.DirectionIn)
		ruleIn.Destination.Address = "10.1.0.0/16"

		ruleOut := precedenceRule("wan", common.DirectionOut)
		ruleOut.Destination.Address = "10.2.0.0/16"

		cfg := &common.CommonDevice{FirewallRules: []common.FirewallRule{ruleAny, ruleIn, ruleOut}}

		pairs := ResolvePrecedence(cfg)

		require.Len(t, pairs, 2, "the any-direction rule pairs with both the in and out rule")

		var gotDirections []common.FirewallDirection
		for _, p := range pairs {
			assert.Equal(t, 0, p.Winner.Index, "the any-direction quick rule wins both overlaps")
			gotDirections = append(gotDirections, p.Direction)
		}

		assert.ElementsMatch(t, []common.FirewallDirection{common.DirectionIn, common.DirectionOut}, gotDirections)
	})
}

func TestResolvePrecedence_MultiInterfaceBucketedIndependently(t *testing.T) {
	t.Parallel()

	shared := precedenceRule("wan", common.DirectionIn)
	shared.Interfaces = []string{"wan", "lan"}
	shared.Quick = true
	shared.Destination.Address = "10.0.0.0/8"

	wanRule := precedenceRule("wan", common.DirectionIn)
	wanRule.Destination.Address = "10.1.0.0/16"

	lanRule := precedenceRule("lan", common.DirectionIn)
	lanRule.Destination.Address = "10.2.0.0/16"

	cfg := &common.CommonDevice{FirewallRules: []common.FirewallRule{shared, wanRule, lanRule}}

	pairs := ResolvePrecedence(cfg)

	require.Len(t, pairs, 2)

	byInterface := make(map[string]PrecedencePair, len(pairs))
	for _, p := range pairs {
		byInterface[p.Interface] = p
	}

	wanPair, ok := byInterface["wan"]
	require.True(t, ok, "expected a pair attributed to wan")
	assert.Equal(t, 0, wanPair.Winner.Index)
	assert.Equal(t, 1, wanPair.Loser.Index)

	lanPair, ok := byInterface["lan"]
	require.True(t, ok, "expected a pair attributed to lan")
	assert.Equal(t, 0, lanPair.Winner.Index)
	assert.Equal(t, 2, lanPair.Loser.Index)
}

func TestResolvePrecedence_DeterministicGroupOrdering(t *testing.T) {
	t.Parallel()

	zebraEarlier := precedenceRule("zebra", common.DirectionIn)
	zebraEarlier.Quick = true
	zebraEarlier.Destination.Address = "10.0.0.0/8"
	zebraLater := precedenceRule("zebra", common.DirectionIn)
	zebraLater.Destination.Address = "10.1.0.0/16"

	alphaEarlier := precedenceRule("alpha", common.DirectionIn)
	alphaEarlier.Quick = true
	alphaEarlier.Destination.Address = "10.0.0.0/8"
	alphaLater := precedenceRule("alpha", common.DirectionIn)
	alphaLater.Destination.Address = "10.1.0.0/16"

	cfg := &common.CommonDevice{
		FirewallRules: []common.FirewallRule{zebraEarlier, zebraLater, alphaEarlier, alphaLater},
	}

	var previous []PrecedencePair

	for i := range 5 {
		pairs := ResolvePrecedence(cfg)

		require.Len(t, pairs, 2)
		assert.Equal(t, "alpha", pairs[0].Interface, "alpha sorts before zebra")
		assert.Equal(t, "zebra", pairs[1].Interface)

		if i > 0 {
			assert.Equal(t, previous, pairs, "output must be deterministic across repeated calls")
		}

		previous = pairs
	}
}

// TestResolvePrecedence_AllFloating_SeedsFromDeviceInterfaces is the P2
// regression for buildPrecedenceGroups: a ruleset of ONLY unscoped floating
// rules (no interface-bound rules at all) previously yielded zero candidate
// interface names — since an unscoped floating rule never appears in any
// rule's own r.Interfaces — and so zero groups, meaning a floating-vs-
// floating shadow was never detected at all. Seeding candidate names from
// cfg.Interfaces (scoped to only fire when an unscoped floating rule is
// present) fixes this without touching the interface-bound-only case any
// other test in this file exercises.
func TestResolvePrecedence_AllFloating_SeedsFromDeviceInterfaces(t *testing.T) {
	t.Parallel()

	earlier := floatingRule()
	earlier.Quick = true
	earlier.Destination.Address = "10.0.0.0/8"

	later := floatingRule()
	later.Destination.Address = "10.1.0.0/16"

	cfg := &common.CommonDevice{
		FirewallRules: []common.FirewallRule{earlier, later},
		Interfaces:    []common.Interface{{Name: "lan"}},
	}

	pairs := ResolvePrecedence(cfg)

	require.Len(t, pairs, 1, "an all-floating ruleset must still be evaluated against the device's own interfaces")
	assert.Equal(t, "lan", pairs[0].Interface)
	assert.Equal(t, 0, pairs[0].Winner.Index, "quick earlier floating rule wins the overlap")
	assert.Equal(t, 1, pairs[0].Loser.Index, "later floating rule is shadowed")
	assert.Equal(t, CoverFull, pairs[0].Extent)
}

// TestResolvePrecedence_NoFloating_DeviceInterfacesNotConsulted proves the
// seeding fix above is scoped: when there is no unscoped floating rule,
// cfg.Interfaces is never consulted for candidate names — a device
// interface with no bound rules at all (here, "dmz") must not spuriously
// gain a group or otherwise change output for the ordinary
// interface-bound-only case.
func TestResolvePrecedence_NoFloating_DeviceInterfacesNotConsulted(t *testing.T) {
	t.Parallel()

	earlier := precedenceRule("wan", common.DirectionIn)
	earlier.Quick = true
	earlier.Destination.Address = "10.0.0.0/8"

	later := precedenceRule("wan", common.DirectionIn)
	later.Destination.Address = "10.1.0.0/16"

	cfg := &common.CommonDevice{
		FirewallRules: []common.FirewallRule{earlier, later},
		Interfaces:    []common.Interface{{Name: "wan"}, {Name: "dmz"}},
	}

	pairs := ResolvePrecedence(cfg)

	require.Len(t, pairs, 1)
	assert.Equal(t, "wan", pairs[0].Interface)
}

func TestResolvePrecedence_NilOrInsufficientRules(t *testing.T) {
	t.Parallel()

	assert.Nil(t, ResolvePrecedence(nil))
	assert.Nil(t, ResolvePrecedence(&common.CommonDevice{}))

	single := &common.CommonDevice{
		FirewallRules: []common.FirewallRule{precedenceRule("wan", common.DirectionIn)},
	}
	assert.Nil(t, ResolvePrecedence(single))
}

func TestResolvePrecedence_NoOverlapProducesNoPairs(t *testing.T) {
	t.Parallel()

	earlier := precedenceRule("wan", common.DirectionIn)
	earlier.Quick = true
	earlier.Destination.Address = "10.0.0.5"

	later := precedenceRule("wan", common.DirectionIn)
	later.Destination.Address = "10.1.0.5"

	cfg := &common.CommonDevice{FirewallRules: []common.FirewallRule{earlier, later}}

	assert.Empty(t, ResolvePrecedence(cfg))
}
