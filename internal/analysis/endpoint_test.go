package analysis_test

import (
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/analysis"
	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
	"github.com/stretchr/testify/assert"
)

func TestIsAnyAddress(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		addr string
		want bool
	}{
		// The converters normalize <any/>, <any>1</any> and
		// <network>any</network> to this literal.
		{"any literal", "any", true},
		// Vendor XML is not case-normalized.
		{"uppercase", "ANY", true},
		{"mixed case", "Any", true},
		// An omitted or empty <source>/<destination> element matches every
		// host: a rule with no source matches every source.
		{"empty", "", true},
		{"whitespace only", "   ", true},
		// Wildcard CIDRs are what automation and hand-edited configs write.
		{"ipv4 wildcard", "0.0.0.0/0", true},
		{"ipv6 wildcard", "::/0", true},
		// Specific addresses must not be swept up.
		{"host", "192.168.1.1", false},
		{"subnet", "192.168.1.0/24", false},
		{"large but bounded subnet", "10.0.0.0/8", false},
		{"single host cidr", "0.0.0.0/32", false},
		{"hostname", "fw.example.com", false},
		{"alias name", "MgmtHosts", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, tt.want, analysis.IsAnyAddress(tt.addr))
		})
	}
}

func TestIsAnyPort(t *testing.T) {
	t.Parallel()

	assert.True(t, analysis.IsAnyPort(""))
	assert.True(t, analysis.IsAnyPort("any"))
	assert.True(t, analysis.IsAnyPort("ANY"))
	assert.False(t, analysis.IsAnyPort("443"))
	assert.False(t, analysis.IsAnyPort("8000-9000"))
	assert.False(t, analysis.IsAnyPort("MgmtPorts"))
}

func TestIsAnyProtocol(t *testing.T) {
	t.Parallel()

	assert.True(t, analysis.IsAnyProtocol(""))
	assert.True(t, analysis.IsAnyProtocol("   "))
	assert.True(t, analysis.IsAnyProtocol("any"))
	assert.True(t, analysis.IsAnyProtocol("ANY"))
	assert.False(t, analysis.IsAnyProtocol("tcp"))
	assert.False(t, analysis.IsAnyProtocol("udp"))
	assert.False(t, analysis.IsAnyProtocol("icmp"))
}

// TestIsWideOpenPassRule_AllAnySpellings guards the false negatives that
// motivated IsAnyAddress: a pass rule matching all traffic must be recognized
// however the config spells "any", not only as the literal the converters
// normalize <any/> to.
func TestIsWideOpenPassRule_AllAnySpellings(t *testing.T) {
	t.Parallel()

	spellings := []string{"any", "ANY", "", "   ", "0.0.0.0/0", "::/0"}
	for _, s := range spellings {
		t.Run("addr="+s, func(t *testing.T) {
			t.Parallel()

			rule := common.FirewallRule{
				Type:        common.RuleTypePass,
				Source:      common.RuleEndpoint{Address: s},
				Destination: common.RuleEndpoint{Address: s},
			}
			assert.True(t, analysis.IsWideOpenPassRule(rule),
				"a pass rule with source and destination %q matches all traffic", s)
		})
	}
}

func TestIsWideOpenPassRule_NotWideOpen(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		rule common.FirewallRule
	}{
		{"disabled", common.FirewallRule{
			Type: common.RuleTypePass, Disabled: true,
			Source: common.RuleEndpoint{Address: "any"}, Destination: common.RuleEndpoint{Address: "any"},
		}},
		{"block rule", common.FirewallRule{
			Type:   common.RuleTypeBlock,
			Source: common.RuleEndpoint{Address: "any"}, Destination: common.RuleEndpoint{Address: "any"},
		}},
		{"scoped source", common.FirewallRule{
			Type:   common.RuleTypePass,
			Source: common.RuleEndpoint{Address: "198.51.100.0/24"}, Destination: common.RuleEndpoint{Address: "any"},
		}},
		{"scoped destination port", common.FirewallRule{
			Type:        common.RuleTypePass,
			Source:      common.RuleEndpoint{Address: "any"},
			Destination: common.RuleEndpoint{Address: "any", Port: "443"},
		}},
		{"specific protocol", common.FirewallRule{
			Type:     common.RuleTypePass,
			Protocol: "tcp",
			Source:   common.RuleEndpoint{Address: "any"}, Destination: common.RuleEndpoint{Address: "any"},
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			assert.False(t, analysis.IsWideOpenPassRule(tt.rule))
		})
	}
}

// TestIsAnyEndpoint_RespectsNegation guards the difference between an address
// spelling and an endpoint. A negated endpoint matches the complement of what
// its address names, so a negated 0.0.0.0/0 or ::/0 matches nothing at all.
// Judging it by address alone reports a rule that passes no traffic as wide
// open. A negated any, or a negated endpoint with no address, still counts as
// any, because neither firewall inverts any.
func TestIsAnyEndpoint_RespectsNegation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		ep   common.RuleEndpoint
		want bool
	}{
		{"any", common.RuleEndpoint{Address: "any"}, true},
		{"empty", common.RuleEndpoint{Address: ""}, true},
		{"ipv4 wildcard", common.RuleEndpoint{Address: "0.0.0.0/0"}, true},
		{"ipv6 wildcard", common.RuleEndpoint{Address: "::/0"}, true},
		{"uppercase", common.RuleEndpoint{Address: "ANY"}, true},

		// Neither firewall inverts any, so a negated any still matches everything.
		{"NOT any", common.RuleEndpoint{Address: "any", Negated: true}, true},
		{"NOT uppercase", common.RuleEndpoint{Address: "ANY", Negated: true}, true},
		{"NOT empty", common.RuleEndpoint{Address: "", Negated: true}, true},
		{"NOT blank", common.RuleEndpoint{Address: "   ", Negated: true}, true},
		{"NOT padded any", common.RuleEndpoint{Address: " any ", Negated: true}, true},

		// Both firewalls do invert a wildcard network, which yields the empty set.
		{"NOT ipv4 wildcard", common.RuleEndpoint{Address: "0.0.0.0/0", Negated: true}, false},
		{"NOT ipv6 wildcard", common.RuleEndpoint{Address: "::/0", Negated: true}, false},

		// A negated specific address was never "any" either way.
		{"host", common.RuleEndpoint{Address: "192.168.1.1"}, false},
		{"NOT host", common.RuleEndpoint{Address: "192.168.1.1", Negated: true}, false},
		{"NOT range", common.RuleEndpoint{Address: "10.0.0.0/8", Negated: true}, false},
		{"NOT interface net", common.RuleEndpoint{Address: "lan", Negated: true}, false},
		{"NOT alias", common.RuleEndpoint{Address: "Company_Hosts", Negated: true}, false},

		// A negated list matches every address outside the entries' overlap,
		// every address when they do not overlap, so it counts as any.
		{"list", common.RuleEndpoint{Address: "WEB_HOST,DB_HOST"}, false},
		{"NOT list", common.RuleEndpoint{Address: "WEB_HOST,DB_HOST", Negated: true}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, tt.want, analysis.IsAnyEndpoint(tt.ep))
		})
	}
}

// TestIsWideOpenPassRule_NegatedEndpointIsNotWideOpen pins the consequence at
// the rule level: FIREWALL-022 and FIREWALL-023 are the highest-severity rule
// checks, and a false positive there reports a critical finding against a rule
// that passes nothing.
func TestIsWideOpenPassRule_NegatedEndpointIsNotWideOpen(t *testing.T) {
	t.Parallel()

	wideOpen := func() common.FirewallRule {
		return common.FirewallRule{
			Type:        common.RuleTypePass,
			Source:      common.RuleEndpoint{Address: "0.0.0.0/0"},
			Destination: common.RuleEndpoint{Address: "0.0.0.0/0"},
		}
	}

	t.Run("baseline is wide open", func(t *testing.T) {
		t.Parallel()
		assert.True(t, analysis.IsWideOpenPassRule(wideOpen()))
	})

	t.Run("negated source", func(t *testing.T) {
		t.Parallel()

		r := wideOpen()
		r.Source.Negated = true
		assert.False(t, analysis.IsWideOpenPassRule(r))
	})

	t.Run("negated destination", func(t *testing.T) {
		t.Parallel()

		r := wideOpen()
		r.Destination.Negated = true
		assert.False(t, analysis.IsWideOpenPassRule(r))
	})

	t.Run("negated ipv6 wildcard source", func(t *testing.T) {
		t.Parallel()

		r := wideOpen()
		r.Source = common.RuleEndpoint{Address: "::/0", Negated: true}
		assert.False(t, analysis.IsWideOpenPassRule(r))
	})

	t.Run("both negated", func(t *testing.T) {
		t.Parallel()

		r := wideOpen()
		r.Source.Negated = true
		r.Destination.Negated = true
		assert.False(t, analysis.IsWideOpenPassRule(r))
	})
}

// TestIsWideOpenPassRule_NegatedAnyIsWideOpen is the other half: neither
// firewall inverts any, so a pass rule from or to a negated any still passes
// all traffic. A negated endpoint with no address counts as any as well.
func TestIsWideOpenPassRule_NegatedAnyIsWideOpen(t *testing.T) {
	t.Parallel()

	for _, addr := range []string{"any", "ANY", ""} {
		t.Run("addr="+addr, func(t *testing.T) {
			t.Parallel()

			negated := common.RuleEndpoint{Address: addr, Negated: true}
			plain := common.RuleEndpoint{Address: addr}

			for _, r := range []common.FirewallRule{
				{Type: common.RuleTypePass, Source: negated, Destination: plain},
				{Type: common.RuleTypePass, Source: plain, Destination: negated},
				{Type: common.RuleTypePass, Source: negated, Destination: negated},
			} {
				assert.True(t, analysis.IsWideOpenPassRule(r),
					"source %+v, destination %+v", r.Source, r.Destination)
			}
		})
	}
}
