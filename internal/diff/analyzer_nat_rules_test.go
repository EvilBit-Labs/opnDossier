package diff

import (
	"strings"
	"testing"

	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNATRulesEqual_ComparesEveryField guards the under-reporting that
// motivated per-rule NAT comparison. A field missing from the equality helper
// does not weaken a diff entry, it removes the entry.
func TestNATRulesEqual_ComparesEveryField(t *testing.T) {
	t.Parallel()

	assertEqualityCoversEveryField(t, natRulesEqual, map[string]string{
		"UUID": "identity; the pairing keys on it",
	})
}

// TestInboundNATRulesEqual_ComparesEveryField is the same guard for port
// forwards, where InternalIP is the translation target.
func TestInboundNATRulesEqual_ComparesEveryField(t *testing.T) {
	t.Parallel()

	assertEqualityCoversEveryField(t, inboundNATRulesEqual, map[string]string{
		"UUID": "identity; the pairing keys on it",
	})
}

// TestCompareNAT_DetectsContentChanges is the end-to-end half: CompareNAT
// compared only len(OutboundRules) and len(InboundRules), so any edit that left
// the counts intact reported nothing at all. Only port forwards saved by
// OPNsense 26.1 or later carry a UUID, so this is the path most real configs
// take.
func TestCompareNAT_DetectsContentChanges(t *testing.T) {
	t.Parallel()

	base := common.NATConfig{
		OutboundMode: common.OutboundAdvanced,
		OutboundRules: []common.NATRule{{
			Interfaces: []string{"wan"}, Protocol: "tcp", Description: "lan egress",
			Source: common.RuleEndpoint{Address: "192.168.1.0/24"},
			Target: "203.0.113.1",
		}},
		InboundRules: []common.InboundNATRule{{
			Interfaces: []string{"wan"}, Protocol: "tcp", Description: "web",
			ExternalPort: "443", InternalIP: "192.168.1.10", InternalPort: "443",
		}},
	}

	tests := []struct {
		name    string
		mutate  func(*common.NATConfig)
		wantHit string
	}{
		{"outbound target retargeted", func(c *common.NATConfig) {
			c.OutboundRules[0].Target = "203.0.113.99"
		}, "outbound NAT rule"},
		{"outbound moved to another interface", func(c *common.NATConfig) {
			c.OutboundRules[0].Interfaces = []string{"opt1"}
		}, "outbound NAT rule"},
		{"outbound disabled", func(c *common.NATConfig) {
			c.OutboundRules[0].Disabled = true
		}, "outbound NAT rule"},
		{"port forward retargeted to another host", func(c *common.NATConfig) {
			c.InboundRules[0].InternalIP = "192.168.1.66"
		}, "port forward"},
		{"port forward internal port changed", func(c *common.NATConfig) {
			c.InboundRules[0].InternalPort = "8443"
		}, "port forward"},
		{"port forward logging turned off", func(c *common.NATConfig) {
			c.InboundRules[0].Log = false
			c.InboundRules[0].NoRDR = true
		}, "port forward"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			oldCfg := deepCopyNAT(base)
			newCfg := deepCopyNAT(base)
			tt.mutate(&newCfg)

			changes := NewAnalyzer().CompareNAT(oldCfg, newCfg)

			require.NotEmpty(t, changes, "a NAT content change must produce a diff entry")

			var found bool
			for _, c := range changes {
				if c.Type == ChangeModified && strings.Contains(c.Description, tt.wantHit) {
					found = true
				}
			}
			assert.True(t, found, "expected a modified %s entry, got %+v", tt.wantHit, changes)
		})
	}
}

// TestCompareNAT_PortForwardResequence_ShowsBothValues covers a port forward
// moved within the ruleset. OPNsense 26.1 and later record its place as a
// sequence, which reaches the model as Priority, and a change there must not
// read as an entry with identical old and new values.
func TestCompareNAT_PortForwardResequence_ShowsBothValues(t *testing.T) {
	t.Parallel()

	oldCfg := common.NATConfig{InboundRules: []common.InboundNATRule{{
		UUID: "b2b2b2b2-0000-4000-8000-000000000001", Interfaces: []string{"wan"}, Protocol: "tcp",
		Description: "web", InternalIP: "192.168.1.10", LocalPort: "8443", Priority: 100,
	}}}
	newCfg := deepCopyNAT(oldCfg)
	newCfg.InboundRules[0].Priority = 300

	changes := NewAnalyzer().CompareNAT(oldCfg, newCfg)
	require.Len(t, changes, 1)
	assert.Equal(t, ChangeModified, changes[0].Type)
	assert.Contains(t, changes[0].OldValue, "priority=100")
	assert.Contains(t, changes[0].NewValue, "priority=300")
}

// deepCopyNAT clones the slices so table cases cannot mutate each other.
func deepCopyNAT(c common.NATConfig) common.NATConfig {
	out := c
	out.OutboundRules = make([]common.NATRule, len(c.OutboundRules))
	copy(out.OutboundRules, c.OutboundRules)
	for i := range out.OutboundRules {
		out.OutboundRules[i].Interfaces = append([]string(nil), c.OutboundRules[i].Interfaces...)
	}
	out.InboundRules = make([]common.InboundNATRule, len(c.InboundRules))
	copy(out.InboundRules, c.InboundRules)
	for i := range out.InboundRules {
		out.InboundRules[i].Interfaces = append([]string(nil), c.InboundRules[i].Interfaces...)
	}
	return out
}
