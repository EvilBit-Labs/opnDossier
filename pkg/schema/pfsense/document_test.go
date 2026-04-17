package pfsense

import (
	"testing"

	opnsense "github.com/EvilBit-Labs/opnDossier/pkg/schema/opnsense"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDocument_Hostname(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		hostname string
		want     string
	}{
		{
			name:     "returns configured hostname",
			hostname: "fw01",
			want:     "fw01",
		},
		{
			name:     "returns empty when not set",
			hostname: "",
			want:     "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			doc := NewDocument()
			doc.System.Hostname = tt.hostname
			assert.Equal(t, tt.want, doc.Hostname())
		})
	}
}

func TestDocument_InterfaceByName(t *testing.T) {
	t.Parallel()

	doc := NewDocument()
	doc.Interfaces.Items["wan"] = Interface{
		Enable: opnsense.BoolFlag(true),
		If:     "em0",
		Descr:  "WAN",
	}
	doc.Interfaces.Items["lan"] = Interface{
		Enable: opnsense.BoolFlag(true),
		If:     "em1",
		Descr:  "LAN",
	}

	tests := []struct {
		name      string
		ifName    string
		wantDescr string
		wantFound bool
	}{
		{
			name:      "finds WAN by physical interface name",
			ifName:    "em0",
			wantDescr: "WAN",
			wantFound: true,
		},
		{
			name:      "finds LAN by physical interface name",
			ifName:    "em1",
			wantDescr: "LAN",
			wantFound: true,
		},
		{
			name:      "returns false for nonexistent interface",
			ifName:    "em99",
			wantDescr: "",
			wantFound: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			iface, found := doc.InterfaceByName(tt.ifName)
			assert.Equal(t, tt.wantFound, found)

			if tt.wantFound {
				assert.Equal(t, tt.wantDescr, iface.Descr)
			} else {
				assert.Equal(t, Interface{}, iface)
			}
		})
	}
}

func TestDocument_FilterRules(t *testing.T) {
	t.Parallel()

	t.Run("returns empty slice for new document", func(t *testing.T) {
		t.Parallel()

		doc := NewDocument()
		rules := doc.FilterRules()
		require.NotNil(t, rules)
		assert.Empty(t, rules)
	})

	t.Run("returns all configured rules", func(t *testing.T) {
		t.Parallel()

		doc := NewDocument()
		doc.Filter.Rule = []FilterRule{
			{Type: "pass", Descr: "Allow HTTP"},
			{Type: "block", Descr: "Block all"},
		}

		rules := doc.FilterRules()
		require.Len(t, rules, 2)
		assert.Equal(t, "Allow HTTP", rules[0].Descr)
		assert.Equal(t, "Block all", rules[1].Descr)
	})
}

func TestNewDocument_InitializesAllFields(t *testing.T) {
	t.Parallel()

	doc := NewDocument()

	assert.NotNil(t, doc.Interfaces.Items, "Interfaces.Items must be initialized")
	assert.NotNil(t, doc.Dhcpd.Items, "Dhcpd.Items must be initialized")
	assert.NotNil(t, doc.DHCPv6Server.Items, "DHCPv6Server.Items must be initialized")
	assert.NotNil(t, doc.Filter.Rule, "Filter.Rule must be initialized")
	assert.NotNil(t, doc.Nat.Inbound, "Nat.Inbound must be initialized")
	assert.NotNil(t, doc.Nat.Outbound.Rule, "Nat.Outbound.Rule must be initialized")
	assert.NotNil(t, doc.Cron.Items, "Cron.Items must be initialized")
	assert.NotNil(t, doc.LoadBalancer.MonitorType, "LoadBalancer.MonitorType must be initialized")
	assert.NotNil(t, doc.IPsec.Phase1, "IPsec.Phase1 must be initialized")
	assert.NotNil(t, doc.IPsec.Phase2, "IPsec.Phase2 must be initialized")
	assert.NotNil(t, doc.IPsec.MobileKeys, "IPsec.MobileKeys must be initialized")
}
