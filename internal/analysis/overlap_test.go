package analysis

import (
	"testing"

	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
	"github.com/stretchr/testify/assert"
)

// baseOverlapRule returns a firewall rule where every dimension is a
// wildcard ("any"/empty): Source and Destination match all addresses and
// ports, Protocol matches all layer-4 protocols, and IPProtocol is unset
// (family wildcard). Test cases narrow only the dimension(s) under test so
// unrelated dimensions never gate the result.
func baseOverlapRule() common.FirewallRule {
	return common.FirewallRule{
		Protocol: "any",
		Source: common.RuleEndpoint{
			Address: "any",
			Port:    "",
		},
		Destination: common.RuleEndpoint{
			Address: "any",
			Port:    "",
		},
	}
}

//nolint:funlen // table-driven test; length is in data not logic
func TestCoverage(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name             string
		earlier          common.FirewallRule
		later            common.FirewallRule
		namedObjects     common.NamedObjects
		wantCoverage     Coverage
		wantAliasBlocked bool
	}{
		{
			name: "CIDR subset: /8 covers /16",
			earlier: func() common.FirewallRule {
				r := baseOverlapRule()
				r.Destination.Address = "10.0.0.0/8"
				return r
			}(),
			later: func() common.FirewallRule {
				r := baseOverlapRule()
				r.Destination.Address = "10.1.0.0/16"
				return r
			}(),
			wantCoverage:     CoverFull,
			wantAliasBlocked: false,
		},
		{
			name:    "any address covers a specific host",
			earlier: baseOverlapRule(),
			later: func() common.FirewallRule {
				r := baseOverlapRule()
				r.Destination.Address = "10.0.0.5"
				return r
			}(),
			wantCoverage:     CoverFull,
			wantAliasBlocked: false,
		},
		{
			name: "network covers host in network",
			earlier: func() common.FirewallRule {
				r := baseOverlapRule()
				r.Destination.Address = "10.0.0.0/8"
				return r
			}(),
			later: func() common.FirewallRule {
				r := baseOverlapRule()
				r.Destination.Address = "10.0.0.5"
				return r
			}(),
			wantCoverage:     CoverFull,
			wantAliasBlocked: false,
		},
		{
			name: "port range covers single port",
			earlier: func() common.FirewallRule {
				r := baseOverlapRule()
				r.Destination.Port = "1-1024"
				return r
			}(),
			later: func() common.FirewallRule {
				r := baseOverlapRule()
				r.Destination.Port = "443"
				return r
			}(),
			wantCoverage:     CoverFull,
			wantAliasBlocked: false,
		},
		{
			name: "port range partially overlaps another range",
			earlier: func() common.FirewallRule {
				r := baseOverlapRule()
				r.Destination.Port = "1-1024"
				return r
			}(),
			later: func() common.FirewallRule {
				r := baseOverlapRule()
				r.Destination.Port = "500-2000"
				return r
			}(),
			wantCoverage:     CoverPartial,
			wantAliasBlocked: false,
		},
		{
			name: "port list covers single port",
			earlier: func() common.FirewallRule {
				r := baseOverlapRule()
				r.Destination.Port = "80,443"
				return r
			}(),
			later: func() common.FirewallRule {
				r := baseOverlapRule()
				r.Destination.Port = "443"
				return r
			}(),
			wantCoverage:     CoverFull,
			wantAliasBlocked: false,
		},
		{
			name: "port list partially overlaps another list",
			earlier: func() common.FirewallRule {
				r := baseOverlapRule()
				r.Destination.Port = "80,443"
				return r
			}(),
			later: func() common.FirewallRule {
				r := baseOverlapRule()
				r.Destination.Port = "443,8443"
				return r
			}(),
			wantCoverage:     CoverPartial,
			wantAliasBlocked: false,
		},
		{
			name:    "any address and port cover a narrow rule entirely",
			earlier: baseOverlapRule(),
			later: func() common.FirewallRule {
				r := baseOverlapRule()
				r.Destination.Address = "192.168.1.1"
				r.Destination.Port = "22"
				return r
			}(),
			wantCoverage:     CoverFull,
			wantAliasBlocked: false,
		},
		{
			name: "explicit differing families never overlap",
			earlier: func() common.FirewallRule {
				r := baseOverlapRule()
				r.IPProtocol = common.IPProtocolInet
				return r
			}(),
			later: func() common.FirewallRule {
				r := baseOverlapRule()
				r.IPProtocol = common.IPProtocolInet6
				return r
			}(),
			wantCoverage:     CoverNone,
			wantAliasBlocked: false,
		},
		{
			name: "empty IPProtocol is a wildcard against an explicit family",
			earlier: func() common.FirewallRule {
				r := baseOverlapRule()
				r.IPProtocol = ""
				return r
			}(),
			later: func() common.FirewallRule {
				r := baseOverlapRule()
				r.IPProtocol = common.IPProtocolInet
				return r
			}(),
			wantCoverage:     CoverFull,
			wantAliasBlocked: false,
		},
		{
			name: "inet46 covers inet",
			earlier: func() common.FirewallRule {
				r := baseOverlapRule()
				r.IPProtocol = common.IPProtocolInet46
				return r
			}(),
			later: func() common.FirewallRule {
				r := baseOverlapRule()
				r.IPProtocol = common.IPProtocolInet
				return r
			}(),
			wantCoverage:     CoverFull,
			wantAliasBlocked: false,
		},
		{
			name: "inet46 covers inet6",
			earlier: func() common.FirewallRule {
				r := baseOverlapRule()
				r.IPProtocol = common.IPProtocolInet46
				return r
			}(),
			later: func() common.FirewallRule {
				r := baseOverlapRule()
				r.IPProtocol = common.IPProtocolInet6
				return r
			}(),
			wantCoverage:     CoverFull,
			wantAliasBlocked: false,
		},
		{
			name: "negated source on an otherwise-partial overlap is indeterminate",
			earlier: func() common.FirewallRule {
				r := baseOverlapRule()
				r.Destination.Port = "1-1024"
				r.Source.Negated = true
				return r
			}(),
			later: func() common.FirewallRule {
				r := baseOverlapRule()
				r.Destination.Port = "500-2000"
				return r
			}(),
			wantCoverage:     CoverIndeterminate,
			wantAliasBlocked: false,
		},
		{
			// R10 false-positive regression: the negation downgrade must also
			// fire when the raw (pre-negation) coverage is CoverFull, not just
			// CoverPartial. A negated endpoint whose literal EXACTLY matches
			// the other side's literal makes addressRelation return CoverFull
			// (identical strings short-circuit before any negation-aware
			// logic runs), but "NOT 10.0.0.0/8" actually matches every address
			// OUTSIDE that range under pf semantics — the opposite of what the
			// literal match implies. Before this guard covered CoverFull too,
			// this case silently produced a confirmed CoverFull result.
			name: "negated source with identical literal is indeterminate, not full",
			earlier: func() common.FirewallRule {
				r := baseOverlapRule()
				r.Source.Address = "10.0.0.0/8"
				r.Source.Negated = true
				return r
			}(),
			later: func() common.FirewallRule {
				r := baseOverlapRule()
				r.Source.Address = "10.0.0.0/8"
				return r
			}(),
			wantCoverage:     CoverIndeterminate,
			wantAliasBlocked: false,
		},
		{
			name: "unresolvable alias endpoints with different names do not match",
			earlier: func() common.FirewallRule {
				r := baseOverlapRule()
				r.Destination.Address = "ALIAS_A"
				r.Destination.AddressRef = &common.ObjectRef{Name: "ALIAS_A"}
				return r
			}(),
			later: func() common.FirewallRule {
				r := baseOverlapRule()
				r.Destination.Address = "ALIAS_B"
				r.Destination.AddressRef = &common.ObjectRef{Name: "ALIAS_B"}
				return r
			}(),
			namedObjects:     common.NamedObjects{},
			wantCoverage:     CoverNone,
			wantAliasBlocked: true,
		},
		{
			name: "alias member containment resolves cleanly and is not alias-blocked",
			earlier: func() common.FirewallRule {
				r := baseOverlapRule()
				// Narrower than later's destination network: address dimension
				// overlaps only partially, so the alias-resolved port
				// containment (Full on its own) does not force an overall
				// Full result — it must combine correctly into Partial.
				r.Destination.Address = "10.0.1.0/24"
				r.Destination.Port = "WEB"
				r.Destination.PortRef = &common.ObjectRef{Name: "WEB"}
				return r
			}(),
			later: func() common.FirewallRule {
				r := baseOverlapRule()
				r.Destination.Address = "10.0.0.0/16"
				r.Destination.Port = "443"
				return r
			}(),
			namedObjects: common.NamedObjects{
				"WEB": common.NamedObject{
					Name:    "WEB",
					Type:    common.NamedObjectTypePort,
					Members: []string{"80", "443"},
				},
			},
			wantCoverage:     CoverPartial,
			wantAliasBlocked: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			gotCoverage, gotAliasBlocked := coverage(tt.earlier, tt.later, tt.namedObjects)

			assert.Equal(t, tt.wantCoverage, gotCoverage, "coverage mismatch")
			assert.Equal(t, tt.wantAliasBlocked, gotAliasBlocked, "aliasBlocked mismatch")
		})
	}
}

// TestProtocolCoverage exercises protocolCoverage directly across the four
// combinations of specific-vs-specific, specific-vs-any, any-vs-specific,
// and any-vs-any layer-4 protocols.
func TestProtocolCoverage(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		earlier string
		later   string
		want    Coverage
	}{
		{name: "tcp vs udp is CoverNone", earlier: "tcp", later: "udp", want: CoverNone},
		{name: "tcp vs any is CoverPartial", earlier: "tcp", later: "any", want: CoverPartial},
		{name: "any vs tcp is CoverFull", earlier: "any", later: "tcp", want: CoverFull},
		{name: "tcp vs tcp is CoverFull", earlier: "tcp", later: "tcp", want: CoverFull},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, tt.want, protocolCoverage(tt.earlier, tt.later))
		})
	}
}
