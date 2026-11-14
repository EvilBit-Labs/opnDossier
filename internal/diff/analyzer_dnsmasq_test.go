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
// apart by their subnet: every Kea subnet, and dnsmasq ranges no interface's
// network holds. With one name per server, the later scope hid a change to
// the earlier one.
func TestCompareDHCP_ScopesWithoutInterface(t *testing.T) {
	t.Parallel()

	for _, source := range []common.DHCPSource{common.DHCPSourceDnsmasq, common.DHCPSourceKea} {
		t.Run(string(source), func(t *testing.T) {
			t.Parallel()

			scopes := func(firstEnabled bool) []common.DHCPScope {
				return []common.DHCPScope{
					{
						Source: source, Subnet: "172.16.0.0/24", Enabled: firstEnabled,
						Range: common.DHCPRange{From: "172.16.0.100", To: "172.16.0.199"},
					},
					{
						Source: source, Subnet: "172.17.0.0/24", Enabled: true,
						Range: common.DHCPRange{From: "172.17.0.100", To: "172.17.0.199"},
					},
				}
			}

			changes := NewAnalyzer().CompareDHCP(scopes(true), scopes(false))
			require.Len(t, changes, 1)
			assert.Equal(t, "dhcpd."+string(source)+"[172.16.0.0/24].enabled", changes[0].Path)
			assert.Empty(t, NewAnalyzer().CompareDHCP(scopes(true), scopes(true)))
		})
	}
}

// TestCompareDHCP_SubnetKeepsScopeAcrossPoolEdit reports a pool edit and a
// reservation edit on a subnet as changes to that subnet. Keyed by the pool
// start, the scope read as removed and added and the reservation change was
// lost.
func TestCompareDHCP_SubnetKeepsScopeAcrossPoolEdit(t *testing.T) {
	t.Parallel()

	scope := func(from, ip string) []common.DHCPScope {
		return []common.DHCPScope{{
			Source: common.DHCPSourceKea, Subnet: "10.0.1.0/24", Enabled: true,
			Range:        common.DHCPRange{From: from, To: "10.0.1.199"},
			StaticLeases: []common.DHCPStaticLease{{MAC: "aa:bb:cc:00:00:01", IPAddress: ip, Hostname: "printer"}},
		}}
	}

	changes := NewAnalyzer().CompareDHCP(scope("10.0.1.100", "10.0.1.10"), scope("10.0.1.50", "10.0.1.11"))
	paths := make([]string, 0, len(changes))
	for _, c := range changes {
		paths = append(paths, c.Path)
	}
	assert.Equal(t, []string{
		"dhcpd.kea[10.0.1.0/24].staticmap[aa:bb:cc:00:00:01].ipaddr",
		"dhcpd.kea[10.0.1.0/24].range",
	}, paths)
}

// TestCompareDHCP_ScopesWithoutIdentity pairs scopes that have neither an
// interface nor a subnet, or share one, by what they hold, not by position:
// deleting the first of three moves no reservation onto its neighbor.
func TestCompareDHCP_ScopesWithoutIdentity(t *testing.T) {
	t.Parallel()

	scope := func(mac, ip string) common.DHCPScope {
		return common.DHCPScope{
			Source:       common.DHCPSourceKea,
			Enabled:      true,
			StaticLeases: []common.DHCPStaticLease{{MAC: mac, IPAddress: ip}},
		}
	}
	a := scope("aa:bb:cc:00:00:01", "10.0.1.10")
	b := scope("aa:bb:cc:00:00:02", "10.0.2.10")
	c := scope("aa:bb:cc:00:00:03", "10.0.3.10")

	changes := NewAnalyzer().CompareDHCP([]common.DHCPScope{a, b, c}, []common.DHCPScope{b, c})
	require.Len(t, changes, 1)
	assert.Equal(t, ChangeRemoved, changes[0].Type)
	assert.Equal(t, "dhcpd.kea[]", changes[0].Path)

	// An edited scope pairs with the one that keeps its reservations.
	editedB := b
	editedB.Enabled = false
	changes = NewAnalyzer().CompareDHCP([]common.DHCPScope{a, b}, []common.DHCPScope{editedB, a})
	require.Len(t, changes, 1)
	assert.Equal(t, "dhcpd.kea[].enabled", changes[0].Path)

	// Two scopes edited and swapped pair by their reservations, not by
	// position.
	editedA := a
	editedA.Enabled = false
	changes = NewAnalyzer().CompareDHCP([]common.DHCPScope{a, b}, []common.DHCPScope{editedB, editedA})
	require.Len(t, changes, 2)
	for _, c := range changes {
		assert.Equal(t, "dhcpd.kea[].enabled", c.Path)
	}

	// A subnet two scopes share identifies neither.
	shared := func(s common.DHCPScope) common.DHCPScope {
		s.Subnet = "10.0.0.0/16"
		return s
	}
	changes = NewAnalyzer().CompareDHCP(
		[]common.DHCPScope{shared(a), shared(b), shared(c)}, []common.DHCPScope{shared(b), shared(c)})
	require.Len(t, changes, 1)
	assert.Equal(t, ChangeRemoved, changes[0].Type)

	// Shared on the old side only: the scope left in the new config keeps
	// its partner rather than pairing with the first old scope of its subnet.
	changes = NewAnalyzer().CompareDHCP([]common.DHCPScope{shared(a), shared(b)}, []common.DHCPScope{shared(b)})
	require.Len(t, changes, 1)
	assert.Equal(t, ChangeRemoved, changes[0].Type)
}

// TestCompareDHCP_IPv6OnlyScopeName names a scope with no identity and only a
// DHCPv6 range by that range's start.
func TestCompareDHCP_IPv6OnlyScopeName(t *testing.T) {
	t.Parallel()

	keep := common.DHCPScope{Interface: "lan", Source: common.DHCPSourceDnsmasq, Enabled: true}
	v6 := common.DHCPScope{
		Source:  common.DHCPSourceDnsmasq,
		Enabled: true,
		RangeV6: &common.DHCPRange{From: "fd00:9::100", To: "fd00:9::1ff"},
	}

	changes := NewAnalyzer().CompareDHCP([]common.DHCPScope{keep, v6}, []common.DHCPScope{keep})
	require.Len(t, changes, 1)
	assert.Equal(t, "dhcpd.dnsmasq[fd00:9::100]", changes[0].Path)
}
