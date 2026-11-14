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
	assert.Equal(t, "dhcpd.kea[]#2.enabled", changes[0].Path, "the second unnamed scope is b")

	// Two scopes edited and swapped pair by their reservations, not by
	// position.
	editedA := a
	editedA.Enabled = false
	changes = NewAnalyzer().CompareDHCP([]common.DHCPScope{a, b}, []common.DHCPScope{editedB, editedA})
	require.Len(t, changes, 2)
	assert.Equal(t, "dhcpd.kea[].enabled", changes[0].Path)
	assert.Equal(t, "dhcpd.kea[]#2.enabled", changes[1].Path)

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

// changePaths returns the path of each change, in order.
func changePaths(changes []Change) []string {
	paths := make([]string, 0, len(changes))
	for _, c := range changes {
		paths = append(paths, c.Path)
	}

	return paths
}

// TestCompareDHCP_UniqueIdentityPairsOnlyByIdentity keeps a scope with an
// identity of its own from pairing with any other scope, however alike.
func TestCompareDHCP_UniqueIdentityPairsOnlyByIdentity(t *testing.T) {
	t.Parallel()

	lan := common.DHCPScope{
		Interface: "lan", Enabled: true,
		Range: common.DHCPRange{From: "192.168.1.100", To: "192.168.1.199"},
	}
	isc := func(iface, from, to string) common.DHCPScope {
		return common.DHCPScope{Interface: iface, Enabled: true, Range: common.DHCPRange{From: from, To: to}}
	}
	nas := []common.DHCPStaticLease{{MAC: "aa:bb:cc:00:00:09", IPAddress: "10.0.1.10", Hostname: "nas"}}

	tests := []struct {
		name     string
		old, new []common.DHCPScope
		want     []string
	}{
		{
			name: "an ISC scope moved between interfaces with the same range (c1)",
			old:  []common.DHCPScope{lan, isc("opt1", "10.0.5.100", "10.0.5.199")},
			new:  []common.DHCPScope{lan, isc("opt2", "10.0.5.100", "10.0.5.199")},
			want: []string{"dhcpd.opt1", "dhcpd.opt2"},
		},
		{
			name: "an ISC scope moved with its reservation (c2)",
			old: []common.DHCPScope{func() common.DHCPScope {
				s := isc("opt1", "10.0.1.100", "10.0.1.199")
				s.StaticLeases = nas
				return s
			}()},
			new: []common.DHCPScope{func() common.DHCPScope {
				s := isc("opt2", "10.0.2.100", "10.0.2.199")
				s.StaticLeases = []common.DHCPStaticLease{
					{MAC: "aa:bb:cc:00:00:09", IPAddress: "10.0.2.10", Hostname: "nas"},
				}
				return s
			}()},
			want: []string{"dhcpd.opt1", "dhcpd.opt2"},
		},
		{
			name: "unrelated scopes sharing one setting (c4)",
			old: []common.DHCPScope{lan, func() common.DHCPScope {
				s := isc("opt1", "10.0.1.100", "10.0.1.199")
				s.Gateway = "none"
				return s
			}()},
			new: []common.DHCPScope{lan, func() common.DHCPScope {
				s := isc("opt2", "10.0.2.100", "10.0.2.199")
				s.Gateway, s.Enabled = "none", false
				return s
			}()},
			want: []string{"dhcpd.opt1", "dhcpd.opt2"},
		},
		{
			name: "an ISC scope against a dnsmasq scope on one interface",
			old:  []common.DHCPScope{lan},
			new: []common.DHCPScope{func() common.DHCPScope {
				s := lan
				s.Source = common.DHCPSourceDnsmasq
				return s
			}()},
			want: []string{"dhcpd.lan", "dhcpd.dnsmasq.lan"},
		},
		{
			name: "a Kea subnet changed with the same pool (k4)",
			old: []common.DHCPScope{{
				Source: common.DHCPSourceKea, Subnet: "10.0.1.0/24", Enabled: true,
				Range: common.DHCPRange{From: "10.0.1.100", To: "10.0.1.199"}, StaticLeases: nas,
			}},
			new: []common.DHCPScope{{
				Source: common.DHCPSourceKea, Subnet: "10.0.0.0/23", Enabled: true,
				Range: common.DHCPRange{From: "10.0.1.100", To: "10.0.1.199"}, StaticLeases: nas,
			}},
			want: []string{"dhcpd.kea[10.0.1.0/24]", "dhcpd.kea[10.0.0.0/23]"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			changes := NewAnalyzer().CompareDHCP(tt.old, tt.new)
			require.Len(t, changes, 2)
			assert.Equal(t, ChangeRemoved, changes[0].Type)
			assert.Equal(t, ChangeAdded, changes[1].Type)
			assert.Equal(t, tt.want, changePaths(changes))
		})
	}
}

// TestCompareDHCP_ServersNeverPair keeps scopes of two servers apart even
// when neither has an identity and they hold the same reservation.
func TestCompareDHCP_ServersNeverPair(t *testing.T) {
	t.Parallel()

	lease := []common.DHCPStaticLease{{MAC: "aa:bb:cc:00:00:01", IPAddress: "10.0.1.10"}}
	changes := NewAnalyzer().CompareDHCP(
		[]common.DHCPScope{{Source: common.DHCPSourceKea, Enabled: true, StaticLeases: lease}},
		[]common.DHCPScope{{Source: common.DHCPSourceDnsmasq, Enabled: false, StaticLeases: lease}})
	assert.Equal(t, []string{"dhcpd.kea[]", "dhcpd.dnsmasq[]"}, changePaths(changes))
}

// TestCompareDHCP_SharedKeyNames gives scopes that share an identity a name
// each, so their changes print apart (d3).
func TestCompareDHCP_SharedKeyNames(t *testing.T) {
	t.Parallel()

	scopes := func(enabled bool) []common.DHCPScope {
		return []common.DHCPScope{
			{
				Source: common.DHCPSourceDnsmasq, Subnet: "10.0.0.0/8", Enabled: enabled,
				Range: common.DHCPRange{From: "10.1.0.100", To: "10.1.0.199"},
			},
			{
				Source: common.DHCPSourceDnsmasq, Subnet: "10.0.0.0/8", Enabled: enabled,
				Range: common.DHCPRange{From: "10.2.0.100", To: "10.2.0.199"},
			},
		}
	}

	assert.Equal(t, []string{
		"dhcpd.dnsmasq[10.0.0.0/8,10.1.0.100].enabled",
		"dhcpd.dnsmasq[10.0.0.0/8,10.2.0.100].enabled",
	}, changePaths(NewAnalyzer().CompareDHCP(scopes(true), scopes(false))))
}

// TestCompareDHCP_SimilarityWeights pins the weights that decide which of two
// candidates an edited scope pairs with. On a tie the earlier candidate wins,
// so each case lists the weaker candidate first.
func TestCompareDHCP_SimilarityWeights(t *testing.T) {
	t.Parallel()

	lease := []common.DHCPStaticLease{{MAC: "aa:bb:cc:00:00:01", IPAddress: "10.0.1.10"}}
	v6 := &common.DHCPRange{From: "fd00:9::100", To: "fd00:9::1ff"}
	pool := common.DHCPRange{From: "10.0.1.100", To: "10.0.1.199"}
	kea := func(s common.DHCPScope) common.DHCPScope {
		s.Source = common.DHCPSourceKea
		return s
	}

	tests := []struct {
		name     string
		old      common.DHCPScope
		weak     common.DHCPScope
		strong   common.DHCPScope
		wantPath string
	}{
		{
			name:     "a description outweighs a reservation",
			old:      kea(common.DHCPScope{Description: "guest", StaticLeases: lease, Enabled: true}),
			weak:     kea(common.DHCPScope{StaticLeases: lease}),
			strong:   kea(common.DHCPScope{Description: "guest"}),
			wantPath: "dhcpd.kea[]",
		},
		{
			name:     "a pool outweighs a reservation",
			old:      kea(common.DHCPScope{Range: pool, StaticLeases: lease, Enabled: true}),
			weak:     kea(common.DHCPScope{StaticLeases: lease}),
			strong:   kea(common.DHCPScope{Range: pool}),
			wantPath: "dhcpd.kea[]",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			changes := NewAnalyzer().CompareDHCP([]common.DHCPScope{tt.old}, []common.DHCPScope{tt.weak, tt.strong})
			var added []string
			for _, c := range changes {
				if c.Type == ChangeAdded {
					added = append(added, c.Path)
				}
			}
			assert.Equal(t, []string{tt.wantPath}, added, "the weaker candidate is the one left over")
		})
	}

	// A DHCPv6 range alone is enough to pair.
	changes := NewAnalyzer().CompareDHCP(
		[]common.DHCPScope{kea(common.DHCPScope{RangeV6: v6, Enabled: true})},
		[]common.DHCPScope{kea(common.DHCPScope{RangeV6: v6})})
	assert.Equal(t, []string{"dhcpd.kea[fd00:9::100].enabled"}, changePaths(changes))

	// A gateway alone is not.
	changes = NewAnalyzer().CompareDHCP(
		[]common.DHCPScope{kea(common.DHCPScope{Gateway: "10.0.0.1", Enabled: true})},
		[]common.DHCPScope{kea(common.DHCPScope{Gateway: "10.0.0.1"})})
	assert.Len(t, changes, 2)
}

// TestCompareDHCP_PairedChangesSortedByName reports paired scopes in name
// order, whatever order the config lists them in.
func TestCompareDHCP_PairedChangesSortedByName(t *testing.T) {
	t.Parallel()

	scopes := func(enabled bool) []common.DHCPScope {
		return []common.DHCPScope{{Interface: "opt2", Enabled: enabled}, {Interface: "opt1", Enabled: enabled}}
	}

	assert.Equal(t, []string{"dhcpd.opt1.enabled", "dhcpd.opt2.enabled"},
		changePaths(NewAnalyzer().CompareDHCP(scopes(true), scopes(false))))
}

// TestCompareDHCP_SharedKeyPairsWithinGroup keeps scopes that share an
// identity from pairing with a scope that has none.
func TestCompareDHCP_SharedKeyPairsWithinGroup(t *testing.T) {
	t.Parallel()

	lease := []common.DHCPStaticLease{{MAC: "aa:bb:cc:00:00:01", IPAddress: "10.1.0.10"}}
	old := []common.DHCPScope{
		{Source: common.DHCPSourceDnsmasq, Subnet: "10.0.0.0/8", StaticLeases: lease},
		{Source: common.DHCPSourceDnsmasq, Subnet: "10.0.0.0/8"},
	}
	changes := NewAnalyzer().CompareDHCP(old, []common.DHCPScope{{Source: common.DHCPSourceDnsmasq, StaticLeases: lease}})
	require.Len(t, changes, 3)
	for _, c := range changes[:2] {
		assert.Equal(t, ChangeRemoved, c.Type)
	}
	assert.Equal(t, ChangeAdded, changes[2].Type)
}
