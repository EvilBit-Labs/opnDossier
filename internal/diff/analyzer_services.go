package diff

import (
	"fmt"
	"maps"
	"reflect"
	"slices"
	"strconv"
	"strings"

	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
)

// CompareDHCP compares DHCP configuration between two configs.
// Focuses on persistent configuration (static reservations) not ephemeral state (leases).
func (a *Analyzer) CompareDHCP(old, newCfg []common.DHCPScope) []Change {
	if len(old) == 0 && len(newCfg) == 0 {
		return nil
	}
	if len(old) == 0 {
		return []Change{{
			Type:        ChangeAdded,
			Section:     SectionDHCP,
			Path:        "dhcpd",
			Description: "DHCP configuration section added",
		}}
	}
	if len(newCfg) == 0 {
		return []Change{{
			Type:        ChangeRemoved,
			Section:     SectionDHCP,
			Path:        "dhcpd",
			Description: "DHCP configuration section removed",
		}}
	}

	oldNames, newNames := dhcpScopeNames(old), dhcpScopeNames(newCfg)
	pairs, res := pairDHCPScopes(old, newCfg, oldNames)

	var changes []Change

	// Find removed DHCP configs
	for _, oi := range sortedScopeIndexes(oldNames, res.oldPaired) {
		name := oldNames[oi]
		changes = append(changes, Change{
			Type:        ChangeRemoved,
			Section:     SectionDHCP,
			Path:        "dhcpd." + name,
			Description: "Removed DHCP server for " + name,
		})
	}

	// Find added DHCP configs
	for _, ni := range sortedScopeIndexes(newNames, res.newPaired) {
		name := newNames[ni]
		changes = append(changes, Change{
			Type:        ChangeAdded,
			Section:     SectionDHCP,
			Path:        "dhcpd." + name,
			Description: "Added DHCP server for " + name,
		})
	}

	// Compare existing DHCP configs - focus on static reservations
	for _, p := range pairs {
		changes = append(changes, a.compareDHCPScope(oldNames[p.oldIdx], old[p.oldIdx], newCfg[p.newIdx])...)
	}

	return changes
}

// compareDHCPScope reports the changes between two paired scopes.
func (a *Analyzer) compareDHCPScope(name string, oldDHCP, newDHCP common.DHCPScope) []Change {
	// Compare static reservations specifically
	changes := a.compareStaticMappings(name, oldDHCP.StaticLeases, newDHCP.StaticLeases)

	// Compare DHCP range changes
	if oldDHCP.Range.From != newDHCP.Range.From || oldDHCP.Range.To != newDHCP.Range.To {
		changes = append(changes, Change{
			Type:        ChangeModified,
			Section:     SectionDHCP,
			Path:        fmt.Sprintf("dhcpd.%s.range", name),
			Description: "DHCP range changed for " + name,
			OldValue:    fmt.Sprintf("%s - %s", oldDHCP.Range.From, oldDHCP.Range.To),
			NewValue:    fmt.Sprintf("%s - %s", newDHCP.Range.From, newDHCP.Range.To),
		})
	}

	// A dnsmasq scope also carries a DHCPv6 range.
	if oldV6, newV6 := formatOptionalRange(oldDHCP.RangeV6), formatOptionalRange(newDHCP.RangeV6); oldV6 != newV6 {
		changes = append(changes, Change{
			Type:        ChangeModified,
			Section:     SectionDHCP,
			Path:        fmt.Sprintf("dhcpd.%s.rangeV6", name),
			Description: "DHCPv6 range changed for " + name,
			OldValue:    oldV6,
			NewValue:    newV6,
		})
	}

	// Compare enable state
	if oldDHCP.Enabled != newDHCP.Enabled {
		changes = append(changes, Change{
			Type:        ChangeModified,
			Section:     SectionDHCP,
			Path:        fmt.Sprintf("dhcpd.%s.enabled", name),
			Description: fmt.Sprintf("DHCP server %s state changed", name),
			OldValue:    strconv.FormatBool(oldDHCP.Enabled),
			NewValue:    strconv.FormatBool(newDHCP.Enabled),
		})
	}

	return changes
}

// dhcpScopePair is one old scope matched to one new scope.
type dhcpScopePair struct {
	oldIdx, newIdx int
}

// dhcpSimMinScore is the floor for calling two scopes without a unique
// identity the same scope edited: a range, a description or a reservation in
// common. dhcpScopeSimilarity scores no field a server copies into every
// scope, such as a gateway or DNS server set globally, so the floor cannot be
// met on such a value alone.
const dhcpSimMinScore = 1

// dhcpSimDescription and dhcpSimRange weight a matching description, the
// operator's own label for the scope, and a matching address pool above a
// DHCPv6 range or a single reservation.
const (
	dhcpSimDescription = 2
	dhcpSimRange       = 2
)

// pairDHCPScopes matches the scopes of two configs.
//
// A scope with a unique identity (dhcpScopeKey), one no other scope on either
// side has, pairs only with the scope of the same identity; without one it is
// removed or added. Moving an ISC scope from opt1 to opt2 is therefore a
// removal and an addition, however alike the two scopes are.
//
// Only scopes with no identity, or with one more than one scope has, are
// paired by what they hold: identical content first, then similarity, as
// firewall and NAT rules are (itemPairer). Such a scope pairs only within its
// group, the scopes sharing its identity or the scopes with none.
//
// The pairs come back ordered by the old scope's name.
func pairDHCPScopes(old, newCfg []common.DHCPScope, oldNames []string) ([]dhcpScopePair, pairResult) {
	shared := sharedScopeKeys(old)
	maps.Copy(shared, sharedScopeKeys(newCfg))
	group := func(scope common.DHCPScope) (string, bool) {
		key, ok := dhcpScopeKey(scope)
		if !ok {
			return "", false
		}
		_, dup := shared[key]
		return key, !dup
	}

	res := pairResult{oldPaired: make([]bool, len(old)), newPaired: make([]bool, len(newCfg))}
	var pairs []dhcpScopePair
	bind := func(oi, ni int) {
		res.oldPaired[oi], res.newPaired[ni] = true, true
		pairs = append(pairs, dhcpScopePair{oldIdx: oi, newIdx: ni})
	}

	newByKey := make(map[string]int, len(newCfg))
	var newRest []int
	for ni, scope := range newCfg {
		if key, unique := group(scope); unique {
			newByKey[key] = ni
		} else {
			newRest = append(newRest, ni)
		}
	}
	var oldRest []int
	for oi, scope := range old {
		key, unique := group(scope)
		if !unique {
			oldRest = append(oldRest, oi)
			continue
		}
		if ni, ok := newByKey[key]; ok {
			bind(oi, ni)
		}
	}

	pairer := itemPairer[common.DHCPScope]{
		equal: func(x, y common.DHCPScope) bool { return reflect.DeepEqual(x, y) },
		similarity: func(x, y common.DHCPScope) int {
			kx, _ := group(x)
			ky, _ := group(y)
			if kx != ky {
				return 0
			}
			if kx != "" {
				// Scopes sharing a key are ranges in one network, and the
				// converter puts every reservation in that network on the
				// first of them, so reservations follow config order rather
				// than the range and say nothing about which range is which.
				x.StaticLeases, y.StaticLeases = nil, nil
			}
			return dhcpScopeSimilarity(x, y)
		},
		minScore: dhcpSimMinScore,
		maxPairs: simMaxPairs,
	}
	pairer.pair(pick(old, oldRest), pick(newCfg, newRest), func(i, j int) {
		bind(oldRest[i], newRest[j])
	})

	slices.SortStableFunc(pairs, func(x, y dhcpScopePair) int {
		return strings.Compare(oldNames[x.oldIdx], oldNames[y.oldIdx])
	})

	return pairs, res
}

// pick returns the scopes at the given positions.
func pick(scopes []common.DHCPScope, idx []int) []common.DHCPScope {
	out := make([]common.DHCPScope, 0, len(idx))
	for _, i := range idx {
		out = append(out, scopes[i])
	}

	return out
}

// sharedScopeKeys returns the identities more than one scope of a config has.
func sharedScopeKeys(scopes []common.DHCPScope) map[string]struct{} {
	seen := make(map[string]int, len(scopes))
	for _, scope := range scopes {
		if key, ok := dhcpScopeKey(scope); ok {
			seen[key]++
		}
	}
	shared := make(map[string]struct{})
	for key, n := range seen {
		if n > 1 {
			shared[key] = struct{}{}
		}
	}

	return shared
}

// sortedScopeIndexes returns the unpaired positions, ordered by scope name.
func sortedScopeIndexes(names []string, paired []bool) []int {
	idx := unpairedIndexes(paired)
	slices.SortStableFunc(idx, func(x, y int) int { return strings.Compare(names[x], names[y]) })

	return idx
}

// dhcpScopeSimilarity scores how likely two scopes without a unique identity
// are one scope edited: a matching description or address pool scores 2, a
// matching DHCPv6 range and each reservation both hold score 1. Scopes of
// different servers never match. Fields a server can copy into every scope,
// the gateway and the DNS, NTP and WINS servers, are not scored.
func dhcpScopeSimilarity(x, y common.DHCPScope) int {
	if dhcpServer(x) != dhcpServer(y) {
		return 0
	}
	score := 0
	if x.Description != "" && x.Description == y.Description {
		score += dhcpSimDescription
	}
	if x.Range != (common.DHCPRange{}) && x.Range == y.Range {
		score += dhcpSimRange
	}
	if x.RangeV6 != nil && y.RangeV6 != nil && *x.RangeV6 == *y.RangeV6 {
		score++
	}
	leases := make(map[string]struct{}, len(x.StaticLeases))
	for _, lease := range x.StaticLeases {
		leases[staticLeaseKey(lease)] = struct{}{}
	}
	for _, lease := range y.StaticLeases {
		if _, ok := leases[staticLeaseKey(lease)]; ok {
			score++
		}
	}

	return score
}

// dhcpServer returns the server of a scope, reading an empty Source as ISC.
func dhcpServer(scope common.DHCPScope) string {
	if scope.Source == "" {
		return string(common.DHCPSourceISC)
	}

	return string(scope.Source)
}

// dhcpScopeKey returns the identity of a scope, and false when it has none.
// An ISC scope is its bare interface name; a scope of another server is
// prefixed with the server, such as dnsmasq.lan. A scope with no interface,
// which every Kea subnet is and a dnsmasq range no interface's network holds
// can be, is named by its server and its Subnet, such as kea[10.0.1.0/24]:
// Kea requires the subnet and keeps it unique, and it does not move when the
// pool or a reservation is edited.
func dhcpScopeKey(scope common.DHCPScope) (string, bool) {
	server := dhcpServer(scope)
	switch {
	case scope.Interface != "" && server == string(common.DHCPSourceISC):
		return scope.Interface, true
	case scope.Interface != "":
		return server + "." + scope.Interface, true
	case scope.Subnet != "":
		return server + "[" + scope.Subnet + "]", true
	default:
		return "", false
	}
}

// dhcpScopeNames names each scope of a config in diff paths and descriptions.
// A scope is named by its identity, or with none by its server and the start
// of its range, such as dnsmasq[172.16.0.100]. A name more than one scope of
// the config would get is told apart by the range start, as
// dnsmasq[10.0.0.0/8,10.1.0.100] for two relayed ranges in one class
// network, and a name still repeated after that gets #2, #3 in order. A name
// labels the changes; it does not pair the scope.
func dhcpScopeNames(scopes []common.DHCPScope) []string {
	base := make([]string, len(scopes))
	count := make(map[string]int, len(scopes))
	for i, scope := range scopes {
		base[i] = dhcpScopeName(scope)
		count[base[i]]++
	}

	names := make([]string, len(scopes))
	seen := make(map[string]int, len(scopes))
	for i, scope := range scopes {
		name := base[i]
		if _, keyed := dhcpScopeKey(scope); keyed && count[name] > 1 {
			if start := dhcpScopeStart(scope); start != "" {
				name = strings.TrimSuffix(name, "]") + "," + start + "]"
			}
		}
		seen[name]++
		if n := seen[name]; n > 1 {
			name += "#" + strconv.Itoa(n)
		}
		names[i] = name
	}

	return names
}

// dhcpScopeName names one scope: its identity, or its server and range start.
func dhcpScopeName(scope common.DHCPScope) string {
	if key, ok := dhcpScopeKey(scope); ok {
		return key
	}

	return dhcpServer(scope) + "[" + dhcpScopeStart(scope) + "]"
}

// dhcpScopeStart returns the start of a scope's IPv4 range, or of its DHCPv6
// range when it has no IPv4 one.
func dhcpScopeStart(scope common.DHCPScope) string {
	if scope.Range.From != "" || scope.RangeV6 == nil {
		return scope.Range.From
	}

	return scope.RangeV6.From
}

// staticLeaseKey identifies a reservation: its MAC address, or its client id
// when it has none, as a dnsmasq reservation can.
func staticLeaseKey(lease common.DHCPStaticLease) string {
	if lease.MAC == "" && lease.CID != "" {
		return "id:" + lease.CID
	}

	return lease.MAC
}

// compareStaticMappings compares DHCP static reservations between two configs.
func (a *Analyzer) compareStaticMappings(ifaceName string, old, newCfg []common.DHCPStaticLease) []Change {
	var changes []Change

	// Build maps by MAC address, or client id (unique identifier for reservations)
	oldByMAC := make(map[string]common.DHCPStaticLease, len(old))
	newByMAC := make(map[string]common.DHCPStaticLease, len(newCfg))

	for _, lease := range old {
		oldByMAC[staticLeaseKey(lease)] = lease
	}
	for _, lease := range newCfg {
		newByMAC[staticLeaseKey(lease)] = lease
	}

	// Sort keys for deterministic output
	oldMACs := slices.Sorted(maps.Keys(oldByMAC))
	newMACs := slices.Sorted(maps.Keys(newByMAC))

	// Find removed static reservations
	for _, mac := range oldMACs {
		if _, exists := newByMAC[mac]; !exists {
			oldLease := oldByMAC[mac]
			changes = append(changes, Change{
				Type:    ChangeRemoved,
				Section: SectionDHCP,
				Path:    fmt.Sprintf("dhcpd.%s.staticmap[%s]", ifaceName, mac),
				Description: fmt.Sprintf(
					"Removed static reservation: %s (%s)",
					oldLease.IPAddress,
					staticLeaseLabel(oldLease),
				),
				OldValue: formatStaticLease(oldLease),
			})
		}
	}

	// Find added static reservations
	for _, mac := range newMACs {
		if _, exists := oldByMAC[mac]; !exists {
			newLease := newByMAC[mac]
			changes = append(changes, Change{
				Type:    ChangeAdded,
				Section: SectionDHCP,
				Path:    fmt.Sprintf("dhcpd.%s.staticmap[%s]", ifaceName, mac),
				Description: fmt.Sprintf(
					"Added static reservation: %s (%s)",
					newLease.IPAddress,
					staticLeaseLabel(newLease),
				),
				NewValue: formatStaticLease(newLease),
			})
		}
	}

	// Find modified static reservations
	for _, mac := range oldMACs {
		newLease, exists := newByMAC[mac]
		if !exists {
			continue
		}
		oldLease := oldByMAC[mac]
		if oldLease.IPAddress != newLease.IPAddress {
			changes = append(changes, Change{
				Type:        ChangeModified,
				Section:     SectionDHCP,
				Path:        fmt.Sprintf("dhcpd.%s.staticmap[%s].ipaddr", ifaceName, mac),
				Description: "Static reservation IP changed for " + staticLeaseLabel(newLease),
				OldValue:    oldLease.IPAddress,
				NewValue:    newLease.IPAddress,
			})
		}
		if oldLease.Hostname != newLease.Hostname {
			changes = append(changes, Change{
				Type:        ChangeModified,
				Section:     SectionDHCP,
				Path:        fmt.Sprintf("dhcpd.%s.staticmap[%s].hostname", ifaceName, mac),
				Description: "Static reservation hostname changed for " + mac,
				OldValue:    oldLease.Hostname,
				NewValue:    newLease.Hostname,
			})
		}
		// A reservation keyed by its MAC address can still change the client
		// id it matches; one keyed by its client id has the same one on both
		// sides.
		if oldLease.CID != newLease.CID {
			changes = append(changes, Change{
				Type:        ChangeModified,
				Section:     SectionDHCP,
				Path:        fmt.Sprintf("dhcpd.%s.staticmap[%s].cid", ifaceName, mac),
				Description: "Static reservation client ID changed for " + staticLeaseLabel(newLease),
				OldValue:    oldLease.CID,
				NewValue:    newLease.CID,
			})
		}
	}

	return changes
}

// staticLeaseLabel returns a human-readable label for a static lease.
func staticLeaseLabel(lease common.DHCPStaticLease) string {
	if lease.Hostname != "" {
		return lease.Hostname
	}
	if lease.Description != "" {
		return lease.Description
	}
	return staticLeaseKey(lease)
}

// formatStaticLease returns a formatted string for a static lease.
func formatStaticLease(lease common.DHCPStaticLease) string {
	parts := []string{"ip=" + lease.IPAddress, "mac=" + lease.MAC}
	if lease.CID != "" {
		parts = append(parts, "cid="+lease.CID)
	}
	if lease.Hostname != "" {
		parts = append(parts, "hostname="+lease.Hostname)
	}
	if lease.Description != "" {
		parts = append(parts, "descr="+lease.Description)
	}
	return strings.Join(parts, ", ")
}

// formatOptionalRange renders a range that may be absent; an absent range is
// the empty string.
func formatOptionalRange(r *common.DHCPRange) string {
	if r == nil {
		return ""
	}

	return fmt.Sprintf("%s - %s", r.From, r.To)
}
