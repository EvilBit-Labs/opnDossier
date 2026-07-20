package model

import "sort"

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

// isDynamic reports whether t's members are opaque (fetched or evaluated at
// runtime by the firewall — a URL table, GeoIP feed, or external table)
// rather than a static, resolvable member list.
func (t NamedObjectType) isDynamic() bool {
	switch t {
	case NamedObjectTypeURL, NamedObjectTypeGeoIP, NamedObjectTypeExternal:
		return true
	default:
		return false
	}
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

	members, resolved := n.resolveNode(name, visited, 0)
	if len(members) == 0 {
		return nil, resolved
	}

	return dedupeSorted(members), resolved
}

// resolveNode recursively expands name's members, tracking the current
// reference path in visited (to detect cycles) and depth (to enforce
// maxAliasDepth). It returns the literal members reached along every
// non-failing branch, and whether the whole subtree resolved cleanly.
func (n NamedObjects) resolveNode(name string, visited map[string]struct{}, depth int) ([]string, bool) {
	if depth > maxAliasDepth {
		return nil, false
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
			subMembers, subResolved := n.resolveNode(member, visited, depth+1)
			members = append(members, subMembers...)

			if !subResolved {
				resolved = false
			}

			continue
		}

		members = append(members, member)
	}

	return members, resolved
}

// dedupeSorted returns a sorted copy of members with duplicates removed.
func dedupeSorted(members []string) []string {
	seen := make(map[string]struct{}, len(members))

	var out []string

	for _, m := range members {
		if _, ok := seen[m]; ok {
			continue
		}

		seen[m] = struct{}{}

		out = append(out, m)
	}

	sort.Strings(out)

	return out
}
