package processor

import (
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/model/common"
	"github.com/stretchr/testify/assert"
)

const mutatedValue = "MUTATED"

func TestNormalize_DoesNotMutateOriginal(t *testing.T) {
	t.Parallel()

	original := &common.CommonDevice{
		FirewallRules: []common.FirewallRule{
			{Type: "pass", Description: "rule-b"},
			{Type: "block", Description: "rule-a"},
		},
		Users: []common.User{
			{Name: "zoe"},
			{Name: "alice"},
		},
		Groups: []common.Group{
			{Name: "staff"},
			{Name: "admins"},
		},
		Sysctl: []common.SysctlItem{
			{Tunable: "z.tunable"},
			{Tunable: "a.tunable"},
		},
		Certificates: []common.Certificate{
			{RefID: "cert1", PrivateKey: "SECRET"},
		},
		DHCP: []common.DHCPScope{
			{Interface: "lan", AdvDHCP6KeyInfoStatementSecret: "dhcpv6-secret"},
		},
		VPN: common.VPN{
			WireGuard: common.WireGuardConfig{
				Clients: []common.WireGuardClient{
					{UUID: "wg1", PSK: "psk-secret"},
				},
			},
		},
	}

	// Save original order
	origRuleDescr := original.FirewallRules[0].Description
	origUserName := original.Users[0].Name
	origGroupName := original.Groups[0].Name
	origSysctl := original.Sysctl[0].Tunable
	origCertKey := original.Certificates[0].PrivateKey
	origDHCPSecret := original.DHCP[0].AdvDHCP6KeyInfoStatementSecret
	origWGPSK := original.VPN.WireGuard.Clients[0].PSK

	p := &CoreProcessor{}
	normalized := p.normalize(original)

	// Normalized should be sorted
	assert.NotNil(t, normalized)

	// Mutate normalized slices to prove independence from original
	normalized.Certificates[0].PrivateKey = mutatedValue
	normalized.DHCP[0].AdvDHCP6KeyInfoStatementSecret = mutatedValue
	normalized.VPN.WireGuard.Clients[0].PSK = mutatedValue

	// Original should be unmodified
	assert.Equal(t, origRuleDescr, original.FirewallRules[0].Description, "original rules should not be reordered")
	assert.Equal(t, origUserName, original.Users[0].Name, "original users should not be reordered")
	assert.Equal(t, origGroupName, original.Groups[0].Name, "original groups should not be reordered")
	assert.Equal(t, origSysctl, original.Sysctl[0].Tunable, "original sysctl should not be reordered")
	assert.Equal(
		t,
		origCertKey,
		original.Certificates[0].PrivateKey,
		"original certificate private key should not be mutated",
	)
	assert.Equal(
		t,
		origDHCPSecret,
		original.DHCP[0].AdvDHCP6KeyInfoStatementSecret,
		"original DHCP secret should not be mutated",
	)
	assert.Equal(t, origWGPSK, original.VPN.WireGuard.Clients[0].PSK, "original WireGuard PSK should not be mutated")
}

func TestNormalize_NilAndEmptySlices(t *testing.T) {
	t.Parallel()

	t.Run("nil slices remain nil", func(t *testing.T) {
		t.Parallel()
		original := &common.CommonDevice{}
		p := &CoreProcessor{}
		normalized := p.normalize(original)

		assert.Nil(t, normalized.Certificates, "nil Certificates should remain nil")
		assert.Nil(t, normalized.DHCP, "nil DHCP should remain nil")
		assert.Nil(t, normalized.VPN.WireGuard.Clients, "nil WireGuard Clients should remain nil")
	})

	t.Run("empty slices are deep-copied", func(t *testing.T) {
		t.Parallel()
		original := &common.CommonDevice{
			Certificates: []common.Certificate{},
			DHCP:         []common.DHCPScope{},
			VPN: common.VPN{
				WireGuard: common.WireGuardConfig{
					Clients: []common.WireGuardClient{},
				},
			},
		}
		p := &CoreProcessor{}
		normalized := p.normalize(original)

		assert.NotNil(t, normalized.Certificates)
		assert.Empty(t, normalized.Certificates)
		assert.NotNil(t, normalized.DHCP)
		assert.Empty(t, normalized.DHCP)
		assert.NotNil(t, normalized.VPN.WireGuard.Clients)
		assert.Empty(t, normalized.VPN.WireGuard.Clients)
	})
}

func TestCanonicalizeIPField(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"empty string", "", ""},
		{"any keyword", "any", "any"},
		{"lan keyword", "lan", "lan"},
		{"wan keyword", "wan", "wan"},
		{"bare IPv4", "192.168.1.1", "192.168.1.1/32"},
		{"IPv4 CIDR", "10.0.0.0/8", "10.0.0.0/8"},
		{"non-canonical CIDR", "192.168.1.100/24", "192.168.1.0/24"},
		{"bare IPv6", "::1", "::1/128"},
		{"alias name", "LAN_SUBNET", "LAN_SUBNET"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			field := tt.input
			canonicalizeIPField(&field)
			assert.Equal(t, tt.want, field)
		})
	}
}
