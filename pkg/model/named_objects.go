package model

import (
	"maps"
	"slices"
)

// maxAliasDepth bounds how many nested named-object references Resolve will
// follow before giving up. It is deliberately generous — deeper than any
// real-world alias nest — while still bounding recursion against a
// misconfigured (or maliciously nested) device configuration.
const maxAliasDepth = 16

// NamedObjectType classifies a NamedObject's member semantics.
type NamedObjectType string

// Recognized named-object type constants.
const (
	// NamedObjectTypeHost is a single-host alias (one or more literal addresses).
	NamedObjectTypeHost NamedObjectType = "host"
	// NamedObjectTypeNetwork is a network/CIDR alias.
	NamedObjectTypeNetwork NamedObjectType = "network"
	// NamedObjectTypePort is a port or port-range alias.
	NamedObjectTypePort NamedObjectType = "port"
	// NamedObjectTypeURL is a dynamically-fetched URL table alias. Its
	// members are opaque and are never expanded by Resolve.
	NamedObjectTypeURL NamedObjectType = "url"
	// NamedObjectTypeGeoIP is a GeoIP country/region alias. Opaque, like URL.
	NamedObjectTypeGeoIP NamedObjectType = "geoip"
	// NamedObjectTypeExternal is an externally-managed table (e.g. a
	// vendor-maintained blocklist). Opaque, like URL.
	NamedObjectTypeExternal NamedObjectType = "external"
)

// IsValid reports whether t is a recognized named-object type.
func (t NamedObjectType) IsValid() bool {
	switch t {
	case NamedObjectTypeHost, NamedObjectTypeNetwork, NamedObjectTypePort,
		NamedObjectTypeURL, NamedObjectTypeGeoIP, NamedObjectTypeExternal:
		return true
	default:
		return false
	}
}

// staticNamedObjectTypes lists the ONLY NamedObjectType values whose members
// are genuinely a static, resolvable list. Converters store raw vendor type
// strings verbatim (e.g. OPNsense/pfSense "urltable", "urltable_ports",
// "networkgroup", "mac", plus any future or unrecognized vendor spelling),
// not just the three canonical dynamic constants. isDynamic used to be an
// allowlist of known-opaque types and treated everything else — including
// these vendor spellings — as statically resolvable, so a genuinely opaque,
// externally-fetched "urltable" alias was silently expanded, and R8's
// aliasBlocked/advisory path never fired for exactly the types it targets.
// Inverting to a denylist-of-one (only {host, network, port} resolve;
// everything else, known or not, is opaque) matches R4's intent: "Static
// host, network, and port objects resolve; dynamic objects remain opaque."
//
//nolint:gochecknoglobals,exhaustive // immutable, intentional allowlist-of-static-types; absence (url/geoip/external and any other value) means dynamic/opaque by design, not an omission.
var staticNamedObjectTypes = map[NamedObjectType]struct{}{
	NamedObjectTypeHost:    {},
	NamedObjectTypeNetwork: {},
	NamedObjectTypePort:    {},
}

// isStatic reports whether t is one of the known-static, resolvable
// NamedObjectType values (host, network, port). Every other type — the
// canonical dynamic constants (url, geoip, external), a vendor-specific
// dynamic spelling not modeled by a dedicated constant (e.g. "urltable",
// "urltable_ports"), or any other unrecognized string — is treated as
// opaque by isDynamic below.
func (t NamedObjectType) isStatic() bool {
	_, ok := staticNamedObjectTypes[t]
	return ok
}

// isDynamic reports whether t's members are opaque (fetched or evaluated at
// runtime by the firewall, or simply not one of the known-static types)
// rather than a static, resolvable member list. This is the complement of
// isStatic, not an independent allowlist — see staticNamedObjectTypes for
// why the check is inverted this way.
func (t NamedObjectType) isDynamic() bool {
	return !t.isStatic()
}

// NamedObject represents a single named object (alias) as it appears in a
// device's firewall configuration: a host, network, port, or dynamic
// (url/geoip/external) alias with zero or more members.
type NamedObject struct {
	// Name is the alias name, matching the registry key in NamedObjects.
	Name string `json:"name,omitempty" yaml:"name,omitempty"`
	// Type classifies the member semantics (host, network, port, url, geoip, external).
	Type NamedObjectType `json:"type,omitempty" yaml:"type,omitempty"`
	// Members lists the raw member values. For static types these are
	// literal addresses/ports or the names of other NamedObjects (nested
	// aliases); for dynamic types they are opaque and are not further resolved.
	Members []string `json:"members,omitempty" yaml:"members,omitempty"`
	// Description is the human-readable alias description, when present.
	Description string `json:"description,omitempty" yaml:"description,omitempty"`
}

// NamedObjects is a device's registry of named objects (aliases), keyed by
// object name. Alias names are unique per device, so a map gives O(1)
// lookup for the RuleEndpoint.AddressRef/PortRef resolution path.
//
// Iterate NamedObjects in sorted key order for any deterministic output
// (GOTCHAS §3.1) — Go map iteration order is non-deterministic.
type NamedObjects map[string]NamedObject

// ObjectRef identifies a RuleEndpoint field (address or port) that was
// originally expressed as a named-object reference rather than a literal
// value. It is nil on RuleEndpoint when the field was a literal.
type ObjectRef struct {
	// Name is the referenced object's name, keying into NamedObjects.
	Name string `json:"name,omitempty" yaml:"name,omitempty"`
}

// Ref returns a *ObjectRef when name matches a key in n, or nil when n is
// empty/nil, name is empty, or name does not resolve to a known named
// object (i.e. it is a literal address/port, not an alias reference).
func (n NamedObjects) Ref(name string) *ObjectRef {
	if name == "" || len(n) == 0 {
		return nil
	}
	if _, ok := n[name]; !ok {
		return nil
	}

	return &ObjectRef{Name: name}
}

// Resolve flattens name into its complete set of resolved static members.
//
// Nested references (an object whose members include another object's name)
// are followed and flattened into a single deduped, sorted member set.
// resolved is true only if every branch of the reference tree terminated in
// static, non-opaque members without hitting a cycle or the maxAliasDepth
// bound. On a cycle or depth-cap, Resolve returns whatever static members it
// reached before the failing branch (a partial result) with resolved=false.
// Dynamic object types (url, geoip, external) are never expanded — their
// members stay opaque — and Resolve reports resolved=false for them.
//
// Resolve is nil-safe: calling it on a nil NamedObjects, or looking up an
// unknown name, returns (nil, false).
func (n NamedObjects) Resolve(name string) ([]string, bool) {
	if n == nil {
		return nil, false
	}

	visited := make(map[string]struct{})
	// memo caches the fully-expanded members of names that resolved cleanly,
	// so a subtree shared by multiple references in a DAG is computed once
	// rather than re-expanded per reference. Without it, a non-cyclic alias
	// graph whose nodes each reference a shared child many times blows up
	// exponentially (bounded only by maxAliasDepth in depth, unbounded in
	// breadth) — a trivial DoS from a sub-1KB config, since coverage() calls
	// Resolve synchronously per rule pair. Only clean (resolved==true)
	// expansions are cached; cycle/depth failures are path-dependent and must
	// not poison a name reached cleanly on another branch.
	memo := make(map[string][]string)

	members, resolved := n.resolveNode(name, visited, memo, 0)
	if len(members) == 0 {
		return nil, resolved
	}

	return dedupeSorted(members), resolved
}

// resolveNode recursively expands name's members, tracking the current
// reference path in visited (to detect cycles) and depth (to enforce
// maxAliasDepth). It returns the literal members reached along every
// non-failing branch, and whether the whole subtree resolved cleanly.
func (n NamedObjects) resolveNode(
	name string,
	visited map[string]struct{},
	memo map[string][]string,
	depth int,
) ([]string, bool) {
	if depth > maxAliasDepth {
		return nil, false
	}
	if cached, ok := memo[name]; ok {
		return cached, true
	}
	if _, seen := visited[name]; seen {
		return nil, false
	}

	obj, exists := n[name]
	if !exists {
		return nil, false
	}
	if obj.Type.isDynamic() {
		return nil, false
	}

	visited[name] = struct{}{}
	defer delete(visited, name)

	var members []string

	resolved := true

	for _, member := range obj.Members {
		if _, isRef := n[member]; isRef {
			subMembers, subResolved := n.resolveNode(member, visited, memo, depth+1)
			members = append(members, subMembers...)

			if !subResolved {
				resolved = false
			}

			continue
		}

		members = append(members, member)
	}

	// Dedupe at every node, not just at the top-level Resolve. Members are a
	// set (a value reached via two paths counts once), so collapsing here is
	// semantically identical to deduping at the end — but it also bounds the
	// slice size at each level. Without it, a node that references a shared
	// child N times concatenates N copies of that child's (already large)
	// member set, so the slice grows multiplicatively with depth even though
	// the memo prevents recomputation: an exponential-size allocation, not
	// just exponential time. Deduping per node keeps each set at its distinct
	// member count.
	members = dedupeSorted(members)

	// Cache only clean expansions; a name that failed via a cycle or the
	// depth cap is path-dependent and may resolve cleanly elsewhere.
	if resolved {
		memo[name] = members
	}

	return members, resolved
}

// dedupeSorted returns a sorted copy of members with duplicates removed.
func dedupeSorted(members []string) []string {
	seen := make(map[string]struct{}, len(members))

	for _, m := range members {
		seen[m] = struct{}{}
	}

	return slices.Sorted(maps.Keys(seen))
}
