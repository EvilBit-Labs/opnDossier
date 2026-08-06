package analysis

import (
	"testing"

	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// objectRef builds an alias reference for a policy field in tests.
func objectRef(name string) *common.ObjectRef { return &common.ObjectRef{Name: name} }

// hostAlias builds a static host alias with the given members.
func hostAlias(members ...string) common.NamedObject {
	return common.NamedObject{Type: common.NamedObjectTypeHost, Members: members}
}

// flaggedNames extracts the object names from findings. It returns nil (not an
// empty slice) for no findings so equality checks match a nil want.
func flaggedNames(findings []common.UnusedObjectFinding) []string {
	if len(findings) == 0 {
		return nil
	}

	names := make([]string, len(findings))
	for i, f := range findings {
		names[i] = f.Name
	}

	return names
}

// fwRuleSrc returns a firewall rule whose source references addressAlias.
func fwRuleSrc(addressAlias string) common.FirewallRule {
	return common.FirewallRule{
		Source: common.RuleEndpoint{AddressRef: objectRef(addressAlias)},
	}
}

// unusedObjectCase is one table row for the reachability detector.
type unusedObjectCase struct {
	name       string
	cfg        *common.CommonDevice
	wantUnused []string
}

// basicUnusedCases covers nil-safety, the empty registry, and the simplest
// referenced / unreferenced pair.
func basicUnusedCases() []unusedObjectCase {
	return []unusedObjectCase{
		{name: "returns nil for nil config", cfg: nil, wantUnused: nil},
		{name: "returns nil when no named objects defined", cfg: &common.CommonDevice{}, wantUnused: nil},
		{
			name: "detects alias referenced by no rule",
			cfg: &common.CommonDevice{
				NamedObjects: common.NamedObjects{"orphan": hostAlias("10.0.0.1")},
			},
			wantUnused: []string{"orphan"},
		},
		{
			name: "does not flag alias referenced by firewall rule",
			cfg: &common.CommonDevice{
				NamedObjects:  common.NamedObjects{"web": hostAlias("10.0.0.1")},
				FirewallRules: []common.FirewallRule{fwRuleSrc("web")},
			},
			wantUnused: nil,
		},
	}
}

// rootSiteUnusedCases exercises every Tracked root site in the Surface Audit —
// each asserts an alias referenced only via that surface is not flagged.
func rootSiteUnusedCases() []unusedObjectCase {
	return []unusedObjectCase{
		{
			name: "does not flag alias referenced only by NAT match endpoint",
			cfg: &common.CommonDevice{
				NamedObjects: common.NamedObjects{"mgmt": hostAlias("10.0.0.1")},
				NAT: common.NATConfig{InboundRules: []common.InboundNATRule{{
					Source: common.RuleEndpoint{AddressRef: objectRef("mgmt")},
				}}},
			},
			wantUnused: nil,
		},
		{
			name: "does not flag alias referenced only by NAT redirect target",
			cfg: &common.CommonDevice{
				NamedObjects: common.NamedObjects{"backend": hostAlias("10.0.0.9")},
				NAT: common.NATConfig{InboundRules: []common.InboundNATRule{
					{InternalIPRef: objectRef("backend")},
				}},
			},
			wantUnused: nil,
		},
		{
			name: "does not flag alias referenced only by NAT translation address",
			cfg: &common.CommonDevice{
				NamedObjects: common.NamedObjects{"natpool": hostAlias("203.0.113.5")},
				NAT: common.NATConfig{OutboundRules: []common.NATRule{
					{TargetRef: objectRef("natpool")},
				}},
			},
			wantUnused: nil,
		},
		{
			name: "does not flag alias referenced only by firewall redirect target",
			cfg: &common.CommonDevice{
				NamedObjects:  common.NamedObjects{"redir": hostAlias("10.0.0.7")},
				FirewallRules: []common.FirewallRule{{TargetRef: objectRef("redir")}},
			},
			wantUnused: nil,
		},
		{
			name: "does not flag alias referenced only by NAT port alias",
			cfg: &common.CommonDevice{
				NamedObjects: common.NamedObjects{
					"svcports": {Type: common.NamedObjectTypePort, Members: []string{"8080", "8443"}},
				},
				NAT: common.NATConfig{InboundRules: []common.InboundNATRule{
					{ExternalPortRef: objectRef("svcports")},
				}},
			},
			wantUnused: nil,
		},
		{
			name: "does not flag alias referenced only by static route",
			cfg: &common.CommonDevice{
				NamedObjects: common.NamedObjects{
					"branch_nets": {Type: common.NamedObjectTypeNetwork, Members: []string{"10.1.0.0/16"}},
				},
				Routing: common.Routing{StaticRoutes: []common.StaticRoute{
					{NetworkRef: objectRef("branch_nets")},
				}},
			},
			wantUnused: nil,
		},
		{
			name: "does not flag alias referenced only by OpenVPN local network",
			cfg: &common.CommonDevice{
				NamedObjects: common.NamedObjects{
					"vpn_lan": {Type: common.NamedObjectTypeNetwork, Members: []string{"10.8.0.0/24"}},
				},
				VPN: common.VPN{OpenVPN: common.OpenVPNConfig{Servers: []common.OpenVPNServer{
					{LocalNetworkRef: objectRef("vpn_lan")},
				}}},
			},
			wantUnused: nil,
		},
		{
			name: "does not flag alias referenced only by OpenVPN V6 remote network",
			cfg: &common.CommonDevice{
				NamedObjects: common.NamedObjects{
					"vpn6": {Type: common.NamedObjectTypeNetwork, Members: []string{"2001:db8::/48"}},
				},
				VPN: common.VPN{OpenVPN: common.OpenVPNConfig{ClientSpecificConfigs: []common.OpenVPNCSC{
					{RemoteNetworkV6Ref: objectRef("vpn6")},
				}}},
			},
			wantUnused: nil,
		},
		{
			name: "does not flag alias referenced only by disabled rule",
			cfg: &common.CommonDevice{
				NamedObjects: common.NamedObjects{"staged": hostAlias("10.0.0.2")},
				FirewallRules: []common.FirewallRule{{
					Disabled: true,
					Source:   common.RuleEndpoint{AddressRef: objectRef("staged")},
				}},
			},
			wantUnused: nil,
		},
	}
}

// graphUnusedCases covers transitive reachability, nested groups (including the
// dynamic "networkgroup" traversal guard for KTD-2), opaque types, and cycles.
func graphUnusedCases() []unusedObjectCase {
	return []unusedObjectCase{
		{
			name: "flags alias referenced only by another unused alias",
			cfg: &common.CommonDevice{NamedObjects: common.NamedObjects{
				"stale_group": hostAlias("legacy_host"),
				"legacy_host": hostAlias("10.0.0.3"),
			}},
			wantUnused: []string{"legacy_host", "stale_group"},
		},
		{
			name: "does not flag alias nested under a used group",
			cfg: &common.CommonDevice{
				NamedObjects: common.NamedObjects{
					"prod_group": hostAlias("web_a"),
					"web_a":      hostAlias("10.0.0.4"),
				},
				FirewallRules: []common.FirewallRule{fwRuleSrc("prod_group")},
			},
			wantUnused: nil,
		},
		{
			name: "does not flag alias nested under a used networkgroup-typed group",
			cfg: &common.CommonDevice{
				// Vendor "networkgroup" type is classified dynamic by isDynamic;
				// mirroring resolveNode would drop the group->member edge and
				// falsely flag web_b. Reachability must not gate on isDynamic (KTD-2).
				NamedObjects: common.NamedObjects{
					"netgroup": {Type: common.NamedObjectType("networkgroup"), Members: []string{"web_b"}},
					"web_b":    hostAlias("10.0.0.5"),
				},
				FirewallRules: []common.FirewallRule{fwRuleSrc("netgroup")},
			},
			wantUnused: nil,
		},
		{
			name: "flags unreferenced dynamic url alias",
			cfg: &common.CommonDevice{NamedObjects: common.NamedObjects{
				"blocklist": {Type: common.NamedObjectTypeURL, Members: []string{"https://example.com/list.txt"}},
			}},
			wantUnused: []string{"blocklist"},
		},
		{
			name: "handles cyclic alias graph without hanging",
			cfg: &common.CommonDevice{NamedObjects: common.NamedObjects{
				"a": hostAlias("b"),
				"b": hostAlias("a"),
			}},
			wantUnused: []string{"a", "b"},
		},
	}
}

func TestDetectUnusedObjects(t *testing.T) {
	t.Parallel()

	cases := basicUnusedCases()
	cases = append(cases, rootSiteUnusedCases()...)
	cases = append(cases, graphUnusedCases()...)

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, tt.wantUnused, flaggedNames(DetectUnusedObjects(tt.cfg)))
		})
	}
}

func TestDetectUnusedObjects_DeterministicOrder(t *testing.T) {
	t.Parallel()

	cfg := &common.CommonDevice{NamedObjects: common.NamedObjects{
		"zebra": hostAlias("10.0.0.1"),
		"alpha": hostAlias("10.0.0.2"),
		"mike":  hostAlias("10.0.0.3"),
	}}

	// Multiple runs must produce identical, name-sorted output despite Go's
	// non-deterministic map iteration (GOTCHAS §3.1).
	for range 5 {
		got := DetectUnusedObjects(cfg)
		assert.Equal(t, []string{"alpha", "mike", "zebra"}, flaggedNames(got))
	}
}

func TestUnusedObjects_WiredIntoConsumers(t *testing.T) {
	t.Parallel()

	cfg := &common.CommonDevice{NamedObjects: common.NamedObjects{
		"orphan": hostAlias("10.0.0.1"),
	}}

	// Aggregate consumer (JSON/YAML export path).
	analysis := ComputeAnalysis(cfg)
	require.Len(t, analysis.UnusedObjects, 1)
	assert.Equal(t, "orphan", analysis.UnusedObjects[0].Name)

	// Observation consumer (audit-findings path).
	var found bool

	for _, o := range ScanObservations(cfg) {
		if o.Component == "namedObject[orphan]" {
			found = true

			assert.Contains(t, o.Recommendation, "confirm")
		}
	}

	assert.True(t, found, "unused object should surface as an Observation")
}

func TestDetectUnusedObjects_FindingShape(t *testing.T) {
	t.Parallel()

	cfg := &common.CommonDevice{NamedObjects: common.NamedObjects{
		"orphan": {
			Type:        common.NamedObjectTypeHost,
			Members:     []string{"10.0.0.1", "10.0.0.2"},
			Description: "decommissioned web tier",
		},
	}}

	got := DetectUnusedObjects(cfg)
	require.Len(t, got, 1)

	f := got[0]
	assert.Equal(t, "orphan", f.Name)
	assert.Equal(t, "host", f.Type)
	assert.Equal(t, 2, f.MemberCount)
	assert.Equal(t, "decommissioned web tier", f.Description)
	assert.Equal(t, common.SeverityLow, f.Severity)
	// Remediation hedges rather than instructing deletion (KTD-4).
	assert.Contains(t, f.Recommendation, "confirm")
	assert.NotContains(t, f.Recommendation, "safe to delete")
}
