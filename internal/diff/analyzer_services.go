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

	pairs, res := pairDHCPScopes(old, newCfg)

	var changes []Change

	// Find removed DHCP configs
	for _, oi := range sortedScopeIndexes(old, res.oldPaired) {
		name := dhcpScopeName(old[oi])
		changes = append(changes, Change{
			Type:        ChangeRemoved,
			Section:     SectionDHCP,
			Path:        "dhcpd." + name,
			Description: "Removed DHCP server for " + name,
		})
	}

	// Find added DHCP configs
	for _, ni := range sortedScopeIndexes(newCfg, res.newPaired) {
		name := dhcpScopeName(newCfg[ni])
		changes = append(changes, Change{
			Type:        ChangeAdded,
			Section:     SectionDHCP,
			Path:        "dhcpd." + name,
			Description: "Added DHCP server for " + name,
		})
	}

	// Compare existing DHCP configs - focus on static reservations
	for _, p := range pairs {
		changes = append(changes, a.compareDHCPScope(p.name, old[p.oldIdx], newCfg[p.newIdx])...)
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

// dhcpScopePair is one old scope matched to one new scope, with the name the
// changes between them are reported under.
type dhcpScopePair struct {
	name           string
	oldIdx, newIdx int
}

// dhcpSimMinScore is the floor for calling two scopes without an identity the
// same scope edited: at least one setting or reservation in common. Scopes
// with nothing in common stay a removal and an addition.
const dhcpSimMinScore = 1

// dhcpSimDescription weights a matching description above any one other
// field, as the operator's own label for the scope.
const dhcpSimDescription = 2

// pairDHCPScopes matches the scopes of two configs. A scope pairs first by its
// identity (dhcpScopeKey), then by identical content, then by similarity, as
// firewall and NAT rules do (itemPairer). An identity two scopes of one config
// share identifies neither, so such scopes, and scopes with none, are paired
// by what they hold rather than by their position. The pairs come back sorted
// by name.
func pairDHCPScopes(old, newCfg []common.DHCPScope) ([]dhcpScopePair, pairResult) {
	shared := sharedScopeKeys(old)
	maps.Copy(shared, sharedScopeKeys(newCfg))

	pairer := itemPairer[common.DHCPScope]{
		identity: func(scope common.DHCPScope) (string, bool) {
			key, ok := dhcpScopeKey(scope)
			if !ok {
				return "", false
			}
			if _, dup := shared[key]; dup {
				return "", false
			}
			return key, true
		},
		equal:      func(x, y common.DHCPScope) bool { return reflect.DeepEqual(x, y) },
		similarity: dhcpScopeSimilarity,
		minScore:   dhcpSimMinScore,
		maxPairs:   simMaxPairs,
	}

	var pairs []dhcpScopePair
	res := pairer.pair(old, newCfg, func(oi, ni int) {
		pairs = append(pairs, dhcpScopePair{name: dhcpScopeName(old[oi]), oldIdx: oi, newIdx: ni})
	})
	slices.SortStableFunc(pairs, func(x, y dhcpScopePair) int { return strings.Compare(x.name, y.name) })

	return pairs, res
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
func sortedScopeIndexes(scopes []common.DHCPScope, paired []bool) []int {
	idx := unpairedIndexes(paired)
	slices.SortStableFunc(idx, func(x, y int) int {
		return strings.Compare(dhcpScopeName(scopes[x]), dhcpScopeName(scopes[y]))
	})

	return idx
}

// dhcpScopeSimilarity scores how likely two scopes without an identity are one
// scope edited. Scopes of different servers never match.
func dhcpScopeSimilarity(x, y common.DHCPScope) int {
	if dhcpServer(x) != dhcpServer(y) {
		return 0
	}
	score := 0
	if x.Description != "" && x.Description == y.Description {
		score += dhcpSimDescription
	}
	if x.Range != (common.DHCPRange{}) && x.Range == y.Range {
		score++
	}
	if x.RangeV6 != nil && y.RangeV6 != nil && *x.RangeV6 == *y.RangeV6 {
		score++
	}
	if x.Gateway != "" && x.Gateway == y.Gateway {
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

// dhcpScopeName names a scope in diff paths and descriptions: its identity,
// or for a scope with none its server and the start of its range, such as
// dnsmasq[172.16.0.100], or dnsmasq[] when it has no range. Such a name
// labels the change; it does not pair the scope.
func dhcpScopeName(scope common.DHCPScope) string {
	if key, ok := dhcpScopeKey(scope); ok {
		return key
	}
	start := scope.Range.From
	if start == "" && scope.RangeV6 != nil {
		start = scope.RangeV6.From
	}

	return dhcpServer(scope) + "[" + start + "]"
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
