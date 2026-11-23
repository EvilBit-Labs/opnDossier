package analysis

import (
	"slices"
	"strconv"
	"testing"
	"time"

	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
	"github.com/stretchr/testify/assert"
)

// portAlias builds an enabled port alias for the walk tests.
func portAlias(name string, members ...string) common.NamedObject {
	return common.NamedObject{Name: name, Type: common.NamedObjectTypePort, Members: members}
}

// portRef is an endpoint whose port names the alias.
func portRef(name string) common.RuleEndpoint {
	return common.RuleEndpoint{Port: name, PortRef: &common.ObjectRef{Name: name}}
}

// walkWithin reads ep's ports and fails the test if the walk does not finish
// in time, which is how an exponential walk shows up.
func walkWithin(t *testing.T, ep common.RuleEndpoint, objects common.NamedObjects) PortSet {
	t.Helper()

	done := make(chan PortSet, 1)

	go func() { done <- EndpointPorts(ep, objects) }()

	select {
	case set := <-done:
		return set
	case <-time.After(30 * time.Second):
		t.Fatal("the port alias walk did not finish")

		return PortSet{}
	}
}

// TestEndpointPorts_RepeatedAndSharedAliases pins that an alias named many
// times, by one alias or through several, is read once, as the loader reads
// it: filter_core_get_port_alias expands a nested alias the same way each time
// and keeps each port once, with no cap on depth or visits. Each graph here is
// within the depth cap and holds a handful of distinct ports, so the set is
// complete. Without a cache, or with duplicates counted, each graph runs out
// of the visit budget or the member cap and reads as incomplete.
func TestEndpointPorts_RepeatedAndSharedAliases(t *testing.T) {
	t.Parallel()

	// Each level names the next twice, and the deepest holds 23.
	doubled := make(common.NamedObjects)
	for level := range maxPortAliasDepth + 1 {
		name := "D" + strconv.Itoa(level)
		if level == maxPortAliasDepth {
			doubled[name] = portAlias(name, "23")

			continue
		}

		next := "D" + strconv.Itoa(level+1)
		doubled[name] = portAlias(name, next, next)
	}

	// Each level names five distinct aliases that all name the next level,
	// so nothing repeats inside one alias but every path is shared.
	shared := make(common.NamedObjects)
	for level := range maxPortAliasDepth/2 + 1 {
		name := "S" + strconv.Itoa(level)
		if level == maxPortAliasDepth/2 {
			shared[name] = portAlias(name, "23")

			continue
		}

		var fan []string

		for branch := range 5 {
			hop := name + "x" + strconv.Itoa(branch)
			shared[hop] = portAlias(hop, "S"+strconv.Itoa(level+1))
			fan = append(fan, hop)
		}

		shared[name] = portAlias(name, fan...)
	}

	// Twelve levels that each name the next twice and add three ports of
	// their own: 34 distinct ports in all.
	leafy := make(common.NamedObjects)
	wantLeafy := []int{23}

	for level := range 12 {
		name := "L" + strconv.Itoa(level)
		next := "L" + strconv.Itoa(level+1)
		members := []string{next, next}

		for k := range 3 {
			port := 1000 + level*10 + k
			members = append(members, strconv.Itoa(port))
			wantLeafy = append(wantLeafy, port)
		}

		leafy[name] = portAlias(name, members...)
	}

	leafy["L12"] = portAlias("L12", "23")

	tests := []struct {
		name    string
		objects common.NamedObjects
		root    string
		want    []int
	}{
		{name: "each level names the next twice", objects: doubled, root: "D0", want: []int{23}},
		{name: "each level fans out to aliases sharing the next", objects: shared, root: "S0", want: []int{23}},
		{name: "doubled levels with ports of their own", objects: leafy, root: "L0", want: wantLeafy},
		{
			name:    "one port listed five thousand times",
			objects: common.NamedObjects{"Flat": portAlias("Flat", slices.Repeat([]string{"80"}, 5000)...)},
			root:    "Flat",
			want:    []int{80},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			set := walkWithin(t, portRef(tt.root), tt.objects)

			assert.True(t, set.Complete(), "complete")

			for _, port := range tt.want {
				assert.True(t, set.ContainsAny(port), "holds %d", port)
			}

			assert.Len(t, set.values.ranges, len(mergeIntervals(portList(tt.want))), "distinct ranges")
		})
	}
}

// portList turns ports into single-port ranges.
func portList(ports []int) []portRange {
	ranges := make([]portRange, 0, len(ports))
	for _, port := range ports {
		ranges = append(ranges, portRange{lo: port, hi: port})
	}

	return ranges
}

// TestEndpointPorts_MemberCapCountsDistinctPorts pins that the member cap
// counts the merged set: five thousand ports that run together are one range
// and read in full, and five thousand that do not exceed the cap and leave
// the set incomplete, as NamedObjects.Resolve leaves an alias that large.
func TestEndpointPorts_MemberCapCountsDistinctPorts(t *testing.T) {
	t.Parallel()

	var consecutive, spaced []string

	for i := range 5000 {
		consecutive = append(consecutive, strconv.Itoa(1000+i))
		spaced = append(spaced, strconv.Itoa(1000+2*i))
	}

	objects := common.NamedObjects{
		"Consecutive": portAlias("Consecutive", consecutive...),
		"Spaced":      portAlias("Spaced", spaced...),
	}

	run := EndpointPorts(portRef("Consecutive"), objects)
	assert.True(t, run.Complete())
	assert.True(t, run.ContainsAny(5999))

	gaps := EndpointPorts(portRef("Spaced"), objects)
	assert.False(t, gaps.Complete())
	assert.False(t, gaps.ContainsAny(1000), "a set over the cap is not read")
}

// TestEndpointPorts_WorkBudget pins the bound on the ranges one walk gathers:
// hundreds of aliases that each name one alias of four thousand ports merge to
// a set under the member cap, but each of them copies those ports, so gathering
// the set takes more than the budget, the walk stops there and the set reads as
// incomplete. An alias that
// lists that alias hundreds of times takes its ports once and stays under it.
func TestEndpointPorts_WorkBudget(t *testing.T) {
	t.Parallel()

	big := make([]string, 0, 4000)
	for i := range 4000 {
		big = append(big, strconv.Itoa(1000+2*i))
	}

	objects := common.NamedObjects{"Big": portAlias("Big", big...)}

	var hops []string

	for i := range 300 {
		name := "Hop" + strconv.Itoa(i)
		objects[name] = portAlias(name, "Big")
		hops = append(hops, name)
	}

	objects["Root"] = portAlias("Root", hops...)
	objects["Few"] = portAlias("Few", hops[:2]...)
	objects["Repeat"] = portAlias("Repeat", slices.Repeat([]string{"Big"}, 300)...)

	assert.False(t, walkWithin(t, portRef("Root"), objects).Complete(), "over the budget")
	assert.True(t, walkWithin(t, portRef("Few"), objects).Complete(), "under the budget")
	assert.True(t, walkWithin(t, portRef("Repeat"), objects).Complete(), "a repeated member is taken once")
}

// TestEndpointPorts_SharedLeafAlias pins that a disabled alias and a non-port
// alias are cached like any other. Root names 2100 aliases that each hold a
// port of their own and name the same leaf: 2102 aliases, within the visit
// budget when each is read once, and over it when the leaf costs a visit each
// time it is named. A disabled leaf adds no port, so the set is complete; a
// non-port leaf leaves it incomplete. Either way every port is read.
func TestEndpointPorts_SharedLeafAlias(t *testing.T) {
	t.Parallel()

	const parents = 2100

	leaves := map[string]common.NamedObject{
		"disabled": {Name: "Leaf", Type: common.NamedObjectTypePort, Members: []string{"23"}, Disabled: true},
		"non-port": {Name: "Leaf", Type: common.NamedObjectTypeNetwork, Members: []string{"10.0.0.0/8"}},
	}

	for kind, leaf := range leaves {
		t.Run(kind, func(t *testing.T) {
			t.Parallel()

			objects := common.NamedObjects{"Leaf": leaf}
			names := make([]string, 0, parents)

			for i := range parents {
				name := "P" + strconv.Itoa(i)
				objects[name] = portAlias(name, "Leaf", strconv.Itoa(1000+2*i))
				names = append(names, name)
			}

			objects["Root"] = portAlias("Root", names...)

			set := walkWithin(t, portRef("Root"), objects)

			assert.Equal(t, kind == "disabled", set.Complete(), "complete")
			assert.False(t, set.ContainsAny(23), "a disabled leaf adds no port")

			for i := range parents {
				if !set.ContainsAny(1000 + 2*i) {
					t.Errorf("port %d of P%d was not read", 1000+2*i, i)

					break
				}
			}
		})
	}
}

// TestEndpointPorts_CachedAliasPastTheDepthCap pins that the cache does not
// make the depth cap depend on walk order. Inner is a chain ten levels deep.
// Reached directly it is within the cap; reached through a seven-level chain
// it reaches past it. Either order reads every port of Inner and leaves the
// set incomplete, as an uncached walk does.
func TestEndpointPorts_CachedAliasPastTheDepthCap(t *testing.T) {
	t.Parallel()

	objects := make(common.NamedObjects)

	const innerDepth, longChain = 10, 7

	var wantPorts []int

	for level := range innerDepth + 1 {
		name := "Inner" + strconv.Itoa(level)
		port := 2000 + level
		wantPorts = append(wantPorts, port)

		members := []string{strconv.Itoa(port)}
		if level < innerDepth {
			members = append(members, "Inner"+strconv.Itoa(level+1))
		}

		objects[name] = portAlias(name, members...)
	}

	for level := range longChain {
		name := "Long" + strconv.Itoa(level)
		next := "Long" + strconv.Itoa(level+1)

		if level == longChain-1 {
			next = "Inner0"
		}

		objects[name] = portAlias(name, next)
	}

	objects["ShortFirst"] = portAlias("ShortFirst", "Inner0", "Long0")
	objects["LongFirst"] = portAlias("LongFirst", "Long0", "Inner0")

	for _, root := range []string{"ShortFirst", "LongFirst"} {
		set := EndpointPorts(portRef(root), objects)

		assert.False(t, set.Complete(), "%s: past the depth cap", root)

		for _, port := range wantPorts {
			assert.True(t, set.ContainsAny(port), "%s: holds %d", root, port)
		}
	}
}

// TestEndpointPorts_VisitBudgetStopsCyclicFanOut pins the visit budget. When
// every alias sits above a cycle none of them can be cached, and the budget is
// what keeps the walk small: the depth cap still lets the paths multiply at
// each level. A0 to A6 each name five aliases that all name the next level,
// and A7 names A0 and port 23. Walked in full that is 195,311 expansions
// within the depth cap; the budget stops it soon after 4096. Each member
// still pending on the stack when the budget runs out costs one visit more,
// hence the loose upper bound. The set is incomplete and keeps port 23, which
// the first path down reads.
func TestEndpointPorts_VisitBudgetStopsCyclicFanOut(t *testing.T) {
	t.Parallel()

	const levels, fan = 7, 5

	objects := make(common.NamedObjects)

	for level := range levels {
		name := "A" + strconv.Itoa(level)
		hops := make([]string, 0, fan)

		for branch := range fan {
			hop := name + "h" + strconv.Itoa(branch)
			objects[hop] = portAlias(hop, "A"+strconv.Itoa(level+1))
			hops = append(hops, hop)
		}

		objects[name] = portAlias(name, hops...)
	}

	last := "A" + strconv.Itoa(levels)
	objects[last] = portAlias(last, "A0", "23")

	w := portAliasWalker{no: objects, visiting: make(map[string]struct{}), memo: make(map[string]portSubtree)}
	sub, _ := w.walk("A0", 0)

	assert.Greater(t, w.visits, maxPortAliasVisits, "the graph reaches the budget")
	assert.Less(t, w.visits, 2*maxPortAliasVisits, "the budget stops the walk")
	assert.NotZero(t, sub.cause&causeAlias, "the set is incomplete")

	set := walkWithin(t, portRef("A0"), objects)
	assert.False(t, set.Complete())
	assert.True(t, set.ContainsAny(23), "a port read before the budget ran out is kept")
}
