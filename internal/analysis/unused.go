package analysis

import (
	"slices"
	"strings"

	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
)

// unusedObjectRecommendation hedges rather than instructing deletion: the
// detector cannot see a config-invisible staging signal (an alias created
// before its referencing rule exists), so the copy asks the operator to
// confirm before removing (KTD-4).
const unusedObjectRecommendation = "Not currently referenced by any policy; confirm the object is unused before removing it."

// DetectUnusedObjects reports named objects (aliases) that are defined in cfg
// but not referenced by any policy (issue #203). It is framed as graph
// reachability from policy roots: nodes are cfg.NamedObjects entries, an edge
// runs from an object to each member that names another object, and roots are
// every live ObjectRef on a Tracked policy surface (the Surface Audit / KTD-3
// root sites). Any object not reachable from a root is unused.
//
// DetectUnusedObjects is a pure function of cfg: no shared state, mirroring
// every other Detect* in this package. Returns nil for a nil cfg or an empty
// NamedObjects registry. Output is sorted by object name for deterministic
// rendering (GOTCHAS §3.1).
func DetectUnusedObjects(cfg *common.CommonDevice) []common.UnusedObjectFinding {
	if cfg == nil || len(cfg.NamedObjects) == 0 {
		return nil
	}

	reachable := reachableObjects(cfg)

	findings := make([]common.UnusedObjectFinding, 0, len(cfg.NamedObjects))

	for name, obj := range cfg.NamedObjects {
		if reachable[name] {
			continue
		}

		findings = append(findings, common.UnusedObjectFinding{
			Name:           name,
			Type:           string(obj.Type),
			MemberCount:    len(obj.Members),
			Description:    obj.Description,
			Severity:       common.SeverityLow,
			Recommendation: unusedObjectRecommendation,
		})
	}

	if len(findings) == 0 {
		return nil
	}

	slices.SortFunc(findings, func(a, b common.UnusedObjectFinding) int {
		return strings.Compare(a.Name, b.Name)
	})

	return findings
}

// reachableObjects returns the set of NamedObjects names reachable from any
// policy root via member→object edges.
//
// The edge predicate is deliberately NOT resolveNode's member walk (KTD-2):
// resolveNode early-returns for isDynamic types (everything but host/network/
// port), so mirroring it would drop every edge out of a "networkgroup"-typed
// group and falsely flag its nested members as unused. Reachability only cares
// whether a member names another object, never whether the object's members
// expand into literal addresses — so this walk has no isDynamic gate. It is
// still correct for genuinely opaque types (url/geoip/external): their members
// are URLs and country codes, which do not key into the registry and so
// contribute no edges without needing a type check.
func reachableObjects(cfg *common.CommonDevice) map[string]bool {
	reachable := make(map[string]bool, len(cfg.NamedObjects))
	queue := collectRoots(cfg)

	for len(queue) > 0 {
		name := queue[len(queue)-1]
		queue = queue[:len(queue)-1]

		if reachable[name] {
			continue
		}

		obj, ok := cfg.NamedObjects[name]
		if !ok {
			// A root ref (or a member) may name an object not in the registry;
			// it contributes no edges. The visited guard above already bounds a
			// cyclic alias graph, so this terminates.
			continue
		}

		reachable[name] = true

		for _, member := range obj.Members {
			if _, isRef := cfg.NamedObjects[member]; isRef && !reachable[member] {
				queue = append(queue, member)
			}
		}
	}

	return reachable
}

// collectRoots returns the names of every object directly referenced by a
// policy surface — the Surface Audit's Tracked root sites (KTD-3). It walks
// only typed ObjectRef fields, never raw string values, so completeness is
// proven by the audit rather than by scanning. Disabled rules are included
// (KTD-4): a disabled rule referencing an alias means the alias is staged, not
// dead, and deleting it would break the rule on re-enable.
func collectRoots(cfg *common.CommonDevice) []string {
	var roots []string

	addRef := func(ref *common.ObjectRef) {
		if ref != nil && ref.Name != "" {
			roots = append(roots, ref.Name)
		}
	}
	addEndpoint := func(ep common.RuleEndpoint) {
		addRef(ep.AddressRef)
		addRef(ep.PortRef)
	}

	for _, rule := range cfg.FirewallRules {
		addEndpoint(rule.Source)
		addEndpoint(rule.Destination)
		addRef(rule.TargetRef)
	}

	for _, rule := range cfg.NAT.OutboundRules {
		addEndpoint(rule.Source)
		addEndpoint(rule.Destination)
		addRef(rule.TargetRef)
		addRef(rule.SourcePortRef)
		addRef(rule.NatPortRef)
	}

	for _, rule := range cfg.NAT.InboundRules {
		addEndpoint(rule.Source)
		addEndpoint(rule.Destination)
		addRef(rule.InternalIPRef)
		addRef(rule.InternalPortRef)
		addRef(rule.ExternalPortRef)
		addRef(rule.LocalPortRef)
	}

	for _, route := range cfg.Routing.StaticRoutes {
		addRef(route.NetworkRef)
	}

	for _, srv := range cfg.VPN.OpenVPN.Servers {
		addRef(srv.LocalNetworkRef)
		addRef(srv.LocalNetworkV6Ref)
		addRef(srv.RemoteNetworkRef)
		addRef(srv.RemoteNetworkV6Ref)
	}

	for _, csc := range cfg.VPN.OpenVPN.ClientSpecificConfigs {
		addRef(csc.LocalNetworkRef)
		addRef(csc.LocalNetworkV6Ref)
		addRef(csc.RemoteNetworkRef)
		addRef(csc.RemoteNetworkV6Ref)
	}

	return roots
}
