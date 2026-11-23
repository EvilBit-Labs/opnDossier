package analysis

import (
	"net/netip"
	"slices"
	"strconv"
	"testing"
	"time"

	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
	"github.com/stretchr/testify/assert"
)

// networkAlias builds an enabled network alias for the literal walk tests.
func networkAlias(name string, members ...string) common.NamedObject {
	return common.NamedObject{Name: name, Type: common.NamedObjectTypeNetwork, Members: members}
}

// addressRef is an endpoint whose address names the alias.
func addressRef(name string) common.RuleEndpoint {
	return common.RuleEndpoint{Address: name, AddressRef: &common.ObjectRef{Name: name}}
}

// literalWithin reads ep's literal networks and fails the test if the walk
// does not finish in time, which is how an exponential walk shows up.
func literalWithin(t *testing.T, ep common.RuleEndpoint, objects common.NamedObjects) ([]netip.Prefix, bool) {
	t.Helper()

	type result struct {
		prefixes []netip.Prefix
		proven   bool
	}

	done := make(chan result, 1)

	go func() {
		prefixes, proven := literalPrefixes(ep, objects)
		done <- result{prefixes: prefixes, proven: proven}
	}()

	select {
	case r := <-done:
		return r.prefixes, r.proven
	case <-time.After(30 * time.Second):
		t.Fatal("the literal alias walk did not finish")

		return nil, false
	}
}

// doubledNetworkChain builds network aliases N0 to N<levels> where each names
// the next twice and the deepest holds 10.0.0.0/8. Read path by path that is
// 2^levels expansions, far over the visit budget at sixteen levels.
func doubledNetworkChain(levels int) common.NamedObjects {
	objects := make(common.NamedObjects, levels+1)

	for level := range levels + 1 {
		name := "N" + strconv.Itoa(level)
		if level == levels {
			objects[name] = networkAlias(name, "10.0.0.0/8")

			continue
		}

		next := "N" + strconv.Itoa(level+1)
		objects[name] = networkAlias(name, next, next)
	}

	return objects
}

// TestLiteralPrefixes_RepeatedAndSharedAliases pins that an alias named many
// times, by one alias or through several, is expanded once, and that a
// network listed many times is kept once, as a table holds each entry once.
// Each graph is within the depth cap and holds a handful of distinct networks,
// so the set is proven. Without the cache, or with duplicates counted, each
// runs out of the visit budget or the member cap and is unproven.
func TestLiteralPrefixes_RepeatedAndSharedAliases(t *testing.T) {
	t.Parallel()

	// Each level names five distinct aliases that all name the next level,
	// so nothing repeats inside one alias but every path is shared.
	shared := make(common.NamedObjects)

	for level := range maxPortAliasDepth/2 + 1 {
		name := "S" + strconv.Itoa(level)
		if level == maxPortAliasDepth/2 {
			shared[name] = networkAlias(name, "10.0.0.0/8")

			continue
		}

		var fan []string

		for branch := range 5 {
			hop := name + "x" + strconv.Itoa(branch)
			shared[hop] = networkAlias(hop, "S"+strconv.Itoa(level+1))
			fan = append(fan, hop)
		}

		shared[name] = networkAlias(name, fan...)
	}

	tests := []struct {
		name    string
		objects common.NamedObjects
		root    string
		want    []string
	}{
		{
			name:    "each level names the next twice",
			objects: doubledNetworkChain(maxPortAliasDepth),
			root:    "N0",
			want:    []string{"10.0.0.0/8"},
		},
		{
			name:    "each level fans out to aliases sharing the next",
			objects: shared,
			root:    "S0",
			want:    []string{"10.0.0.0/8"},
		},
		{
			name: "one network listed five thousand times",
			objects: common.NamedObjects{
				"Flat": networkAlias("Flat", slices.Repeat([]string{"10.0.0.0/8"}, 5000)...),
			},
			root: "Flat",
			want: []string{"10.0.0.0/8"},
		},
		{
			name: "one network in two aliases, once with host bits",
			objects: common.NamedObjects{
				"Both": networkAlias("Both", "A", "B"),
				"A":    networkAlias("A", "10.0.0.0/8", "192.168.0.0/16"),
				"B":    networkAlias("B", "10.1.2.3/8"),
			},
			root: "Both",
			want: []string{"10.0.0.0/8", "192.168.0.0/16"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			prefixes, proven := literalWithin(t, addressRef(tt.root), tt.objects)

			assert.True(t, proven, "proven")

			want := make([]netip.Prefix, 0, len(tt.want))
			for _, s := range tt.want {
				want = append(want, netip.MustParsePrefix(s))
			}

			assert.ElementsMatch(t, want, prefixes)
		})
	}
}

// TestLiteralPrefixes_MemberCapCountsDistinctNetworks pins that the member cap
// counts distinct networks: five thousand of them leave the set unproven,
// while one network listed five thousand times is proven.
func TestLiteralPrefixes_MemberCapCountsDistinctNetworks(t *testing.T) {
	t.Parallel()

	hosts := make([]string, 0, 5000)
	for i := range 5000 {
		hosts = append(hosts, netip.AddrFrom4([4]byte{10, 0, byte(i >> 8), byte(i)}).String())
	}

	objects := common.NamedObjects{
		"Hosts":  {Name: "Hosts", Type: common.NamedObjectTypeHost, Members: hosts},
		"Repeat": {Name: "Repeat", Type: common.NamedObjectTypeHost, Members: slices.Repeat(hosts[:1], 5000)},
	}

	_, proven := literalPrefixes(addressRef("Hosts"), objects)
	assert.False(t, proven, "more distinct networks than the cap")

	prefixes, proven := literalPrefixes(addressRef("Repeat"), objects)
	assert.True(t, proven, "one network listed many times")
	assert.Len(t, prefixes, 1)
}

// TestLiteralPrefixes_VisitBudgetCountsDistinctAliases pins the visit budget
// on a graph the cache does not shrink: one alias names 4100 distinct aliases
// that each hold a network, more expansions than the budget allows, so the set
// is unproven though every member is a literal. An alias naming 4000 of them
// is within the budget and proven.
func TestLiteralPrefixes_VisitBudgetCountsDistinctAliases(t *testing.T) {
	t.Parallel()

	objects := make(common.NamedObjects)
	leaves := make([]string, 0, maxPortAliasVisits+4)

	for i := range maxPortAliasVisits + 4 {
		name := "Leaf" + strconv.Itoa(i)
		objects[name] = networkAlias(name, "10.0.0.0/8")
		leaves = append(leaves, name)
	}

	objects["Wide"] = networkAlias("Wide", leaves...)
	objects["Within"] = networkAlias("Within", leaves[:4000]...)

	_, proven := literalWithin(t, addressRef("Wide"), objects)
	assert.False(t, proven, "over the budget")

	_, proven = literalWithin(t, addressRef("Within"), objects)
	assert.True(t, proven, "within the budget")
}

// TestLiteralPrefixes_CycleIsUnproven pins that an alias graph with a cycle is
// never proven, even when the cycle is reached after a shared alias has been
// remembered, so only an alias walked in full is remembered.
func TestLiteralPrefixes_CycleIsUnproven(t *testing.T) {
	t.Parallel()

	objects := common.NamedObjects{
		"Shared": networkAlias("Shared", "10.0.0.0/8"),
		"Loop1":  networkAlias("Loop1", "Shared", "Loop2"),
		"Loop2":  networkAlias("Loop2", "10.1.0.0/16", "Loop1"),
		"Root":   networkAlias("Root", "Shared", "Loop1"),
	}

	for _, root := range []string{"Loop1", "Loop2", "Root"} {
		_, proven := literalWithin(t, addressRef(root), objects)
		assert.False(t, proven, root)
	}
}

// TestLiteralPrefixes_CachedAliasPastTheDepthCap pins that the cache does not
// make the depth cap depend on walk order. Inner is a chain ten levels deep.
// Reached through a five-level chain it ends exactly at the cap, and the set
// is proven in either order. Reached through a seven-level chain it reaches
// past the cap, and the set is unproven in either order, as it is when the
// walk follows every path.
func TestLiteralPrefixes_CachedAliasPastTheDepthCap(t *testing.T) {
	t.Parallel()

	objects := make(common.NamedObjects)

	const innerDepth = 10

	for level := range innerDepth + 1 {
		name := "Inner" + strconv.Itoa(level)
		members := []string{"10." + strconv.Itoa(level) + ".0.0/16"}

		if level < innerDepth {
			members = append(members, "Inner"+strconv.Itoa(level+1))
		}

		objects[name] = networkAlias(name, members...)
	}

	chain := func(prefix string, length int) {
		for level := range length {
			next := prefix + strconv.Itoa(level+1)
			if level == length-1 {
				next = "Inner0"
			}

			name := prefix + strconv.Itoa(level)
			objects[name] = networkAlias(name, next)
		}
	}

	chain("Mid", 5)
	chain("Long", 7)

	objects["MidShortFirst"] = networkAlias("MidShortFirst", "Inner0", "Mid0")
	objects["MidLongFirst"] = networkAlias("MidLongFirst", "Mid0", "Inner0")
	objects["ShortFirst"] = networkAlias("ShortFirst", "Inner0", "Long0")
	objects["LongFirst"] = networkAlias("LongFirst", "Long0", "Inner0")

	for _, root := range []string{"MidShortFirst", "MidLongFirst"} {
		prefixes, proven := literalPrefixes(addressRef(root), objects)
		assert.True(t, proven, "%s: within the depth cap", root)
		assert.Len(t, prefixes, innerDepth+1, root)
	}

	for _, root := range []string{"ShortFirst", "LongFirst"} {
		_, proven := literalPrefixes(addressRef(root), objects)
		assert.False(t, proven, "%s: past the depth cap", root)
	}
}

// TestDetectShadowedRules_ComplementThroughRepeatedAliases drives the
// complement proof through a network alias graph whose levels each name the
// next twice. A pass to every port from outside the alias never meets a block
// from a network inside it, whatever the block's unreadable port alias holds,
// so the pair is silent; a block from a network outside the alias is the
// low-confidence advisory. Without the cache the walk runs out of its visit
// budget, the proof fails, and the silent pair is reported too.
func TestDetectShadowedRules_ComplementThroughRepeatedAliases(t *testing.T) {
	t.Parallel()

	objects := doubledNetworkChain(maxPortAliasDepth)
	objects["Feed"] = portAlias("Feed", "no-such-service")

	tests := []struct {
		name        string
		blockSource string
		want        bool
	}{
		{name: "block from inside the negated alias", blockSource: "10.1.0.0/24"},
		{name: "block from outside the negated alias", blockSource: "11.0.0.0/24", want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			pass := baseShadowRule("wan", common.DirectionIn, common.RuleTypePass)
			pass.Protocol = "tcp"
			pass.Source = addressRef("N0")
			pass.Source.Negated = true

			block := baseShadowRule("wan", common.DirectionIn, common.RuleTypeBlock)
			block.Protocol = "tcp"
			block.Source = common.RuleEndpoint{Address: tt.blockSource}
			block.Destination = portRef("Feed")
			block.Destination.Address = "any"

			findings := DetectShadowedRules(&common.CommonDevice{
				FirewallRules: []common.FirewallRule{pass, block},
				NamedObjects:  objects,
			})

			if !tt.want {
				assert.Empty(t, findings)

				return
			}

			if assert.Len(t, findings, 1) {
				assert.Equal(t, common.ConfidenceLow, findings[0].Confidence)
			}
		})
	}
}
