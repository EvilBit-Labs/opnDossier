package diff

import (
	"testing"

	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCompareDHCP_DnsmasqRangeV6 reports a change to the DHCPv6 range a
// dnsmasq scope carries beside its IPv4 range.
func TestCompareDHCP_DnsmasqRangeV6(t *testing.T) {
	t.Parallel()

	scope := func(v6 *common.DHCPRange) common.DHCPScope {
		return common.DHCPScope{
			Interface: "lan",
			Source:    common.DHCPSourceDnsmasq,
			Enabled:   true,
			Range:     common.DHCPRange{From: "192.168.1.100", To: "192.168.1.199"},
			RangeV6:   v6,
		}
	}

	tests := []struct {
		name    string
		old     *common.DHCPRange
		new     *common.DHCPRange
		wantOld string
		wantNew string
	}{
		{
			name:    "range moved",
			old:     &common.DHCPRange{From: "::1000", To: "::2000"},
			new:     &common.DHCPRange{From: "::1000", To: "::3000"},
			wantOld: "::1000 - ::2000",
			wantNew: "::1000 - ::3000",
		},
		{name: "range added", new: &common.DHCPRange{From: "::1000", To: "::2000"}, wantNew: "::1000 - ::2000"},
		{name: "range removed", old: &common.DHCPRange{From: "::1000", To: "::2000"}, wantOld: "::1000 - ::2000"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			changes := NewAnalyzer().CompareDHCP(
				[]common.DHCPScope{scope(tt.old)}, []common.DHCPScope{scope(tt.new)})
			require.Len(t, changes, 1)
			assert.Equal(t, ChangeModified, changes[0].Type)
			assert.Equal(t, "dhcpd.dnsmasq.lan.rangeV6", changes[0].Path)
			assert.Equal(t, tt.wantOld, changes[0].OldValue)
			assert.Equal(t, tt.wantNew, changes[0].NewValue)
		})
	}

	same := []common.DHCPScope{scope(&common.DHCPRange{From: "::1000", To: "::2000"})}
	assert.Empty(t, NewAnalyzer().CompareDHCP(same, same))
}

// TestCompareDHCP_ScopesWithoutInterface keeps scopes that name no interface
// apart: every Kea subnet, and dnsmasq ranges no interface's network holds.
// With one name per server, the later scope hid a change to the earlier one.
func TestCompareDHCP_ScopesWithoutInterface(t *testing.T) {
	t.Parallel()

	for _, source := range []common.DHCPSource{common.DHCPSourceDnsmasq, common.DHCPSourceKea} {
		t.Run(string(source), func(t *testing.T) {
			t.Parallel()

			scopes := func(firstEnabled bool) []common.DHCPScope {
				return []common.DHCPScope{
					{
						Source:  source,
						Enabled: firstEnabled,
						Range:   common.DHCPRange{From: "172.16.0.100", To: "172.16.0.199"},
					},
					{Source: source, Enabled: true, Range: common.DHCPRange{From: "172.17.0.100", To: "172.17.0.199"}},
				}
			}

			changes := NewAnalyzer().CompareDHCP(scopes(true), scopes(false))
			require.Len(t, changes, 1)
			assert.Equal(t, "dhcpd."+string(source)+"[172.16.0.100].enabled", changes[0].Path)
			assert.Empty(t, NewAnalyzer().CompareDHCP(scopes(true), scopes(true)))
		})
	}
}

// TestCompareDHCP_ScopesSharingAName numbers scopes that would share a name,
// so the second is compared too.
func TestCompareDHCP_ScopesSharingAName(t *testing.T) {
	t.Parallel()

	scopes := func(secondEnabled bool) []common.DHCPScope {
		return []common.DHCPScope{
			{Source: common.DHCPSourceKea, Enabled: true},
			{Source: common.DHCPSourceKea, Enabled: secondEnabled},
		}
	}

	changes := NewAnalyzer().CompareDHCP(scopes(true), scopes(false))
	require.Len(t, changes, 1)
	assert.Equal(t, "dhcpd.kea[]#2.enabled", changes[0].Path)
}
