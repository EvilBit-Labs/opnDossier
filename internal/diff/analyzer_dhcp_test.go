package diff

import (
	"testing"

	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// CompareDHCP — section-level guards
// ---------------------------------------------------------------------------

func TestCompareDHCP_BothEmpty(t *testing.T) {
	t.Parallel()
	analyzer := NewAnalyzer()
	changes := analyzer.CompareDHCP([]common.DHCPScope{}, []common.DHCPScope{})
	assert.Nil(t, changes)
}

func TestCompareDHCP_BothNil(t *testing.T) {
	t.Parallel()
	analyzer := NewAnalyzer()
	changes := analyzer.CompareDHCP(nil, nil)
	assert.Nil(t, changes)
}

func TestCompareDHCP_SectionAdded(t *testing.T) {
	t.Parallel()
	analyzer := NewAnalyzer()
	old := []common.DHCPScope{}
	newCfg := []common.DHCPScope{
		{Interface: "lan", Enabled: true},
	}

	changes := analyzer.CompareDHCP(old, newCfg)

	require.Len(t, changes, 1)
	assert.Equal(t, ChangeAdded, changes[0].Type)
	assert.Equal(t, SectionDHCP, changes[0].Section)
	assert.Equal(t, "dhcpd", changes[0].Path)
	assert.Equal(t, "DHCP configuration section added", changes[0].Description)
}

func TestCompareDHCP_SectionRemoved(t *testing.T) {
	t.Parallel()
	analyzer := NewAnalyzer()
	old := []common.DHCPScope{
		{Interface: "lan", Enabled: true},
	}
	newCfg := []common.DHCPScope{}

	changes := analyzer.CompareDHCP(old, newCfg)

	require.Len(t, changes, 1)
	assert.Equal(t, ChangeRemoved, changes[0].Type)
	assert.Equal(t, SectionDHCP, changes[0].Section)
	assert.Equal(t, "dhcpd", changes[0].Path)
	assert.Equal(t, "DHCP configuration section removed", changes[0].Description)
}

// ---------------------------------------------------------------------------
// CompareDHCP — per-interface comparison
// ---------------------------------------------------------------------------

func TestCompareDHCP_InterfaceAdded(t *testing.T) {
	t.Parallel()
	analyzer := NewAnalyzer()
	old := []common.DHCPScope{
		{Interface: "lan", Enabled: true},
	}
	newCfg := []common.DHCPScope{
		{Interface: "lan", Enabled: true},
		{Interface: "opt1", Enabled: true},
	}

	changes := analyzer.CompareDHCP(old, newCfg)

	require.Len(t, changes, 1)
	assert.Equal(t, ChangeAdded, changes[0].Type)
	assert.Equal(t, "dhcpd.opt1", changes[0].Path)
	assert.Contains(t, changes[0].Description, "opt1")
}

func TestCompareDHCP_InterfaceRemoved(t *testing.T) {
	t.Parallel()
	analyzer := NewAnalyzer()
	old := []common.DHCPScope{
		{Interface: "lan", Enabled: true},
		{Interface: "opt1", Enabled: true},
	}
	newCfg := []common.DHCPScope{
		{Interface: "lan", Enabled: true},
	}

	changes := analyzer.CompareDHCP(old, newCfg)

	require.Len(t, changes, 1)
	assert.Equal(t, ChangeRemoved, changes[0].Type)
	assert.Equal(t, "dhcpd.opt1", changes[0].Path)
	assert.Contains(t, changes[0].Description, "opt1")
}

func TestCompareDHCP_IdenticalInterfaces(t *testing.T) {
	t.Parallel()
	analyzer := NewAnalyzer()
	scope := common.DHCPScope{
		Interface: "lan",
		Enabled:   true,
		Range:     common.DHCPRange{From: "10.0.0.100", To: "10.0.0.200"},
	}

	changes := analyzer.CompareDHCP([]common.DHCPScope{scope}, []common.DHCPScope{scope})

	assert.Empty(t, changes)
}

func TestCompareDHCP_RangeChanged(t *testing.T) {
	t.Parallel()
	analyzer := NewAnalyzer()
	old := []common.DHCPScope{
		{
			Interface: "lan",
			Enabled:   true,
			Range:     common.DHCPRange{From: "10.0.0.100", To: "10.0.0.200"},
		},
	}
	newCfg := []common.DHCPScope{
		{
			Interface: "lan",
			Enabled:   true,
			Range:     common.DHCPRange{From: "10.0.0.50", To: "10.0.0.250"},
		},
	}

	changes := analyzer.CompareDHCP(old, newCfg)

	require.Len(t, changes, 1)
	assert.Equal(t, ChangeModified, changes[0].Type)
	assert.Equal(t, "dhcpd.lan.range", changes[0].Path)
	assert.Equal(t, "10.0.0.100 - 10.0.0.200", changes[0].OldValue)
	assert.Equal(t, "10.0.0.50 - 10.0.0.250", changes[0].NewValue)
}

func TestCompareDHCP_EnabledStateChanged(t *testing.T) {
	t.Parallel()
	analyzer := NewAnalyzer()
	old := []common.DHCPScope{
		{Interface: "lan", Enabled: true},
	}
	newCfg := []common.DHCPScope{
		{Interface: "lan", Enabled: false},
	}

	changes := analyzer.CompareDHCP(old, newCfg)

	require.Len(t, changes, 1)
	assert.Equal(t, ChangeModified, changes[0].Type)
	assert.Equal(t, "dhcpd.lan.enabled", changes[0].Path)
	assert.Equal(t, "true", changes[0].OldValue)
	assert.Equal(t, "false", changes[0].NewValue)
}

func TestCompareDHCP_MultipleChanges(t *testing.T) {
	t.Parallel()
	analyzer := NewAnalyzer()
	old := []common.DHCPScope{
		{
			Interface: "lan",
			Enabled:   true,
			Range:     common.DHCPRange{From: "10.0.0.100", To: "10.0.0.200"},
		},
		{Interface: "opt1", Enabled: true},
	}
	newCfg := []common.DHCPScope{
		{
			Interface: "lan",
			Enabled:   false,
			Range:     common.DHCPRange{From: "10.0.0.50", To: "10.0.0.200"},
		},
		{Interface: "opt2", Enabled: true},
	}

	changes := analyzer.CompareDHCP(old, newCfg)

	// Expect: opt1 removed, opt2 added, lan range changed, lan enabled changed
	assert.Len(t, changes, 4)

	// Verify all change types are present
	types := make(map[ChangeType]int)
	for _, c := range changes {
		types[c.Type]++
	}
	assert.Equal(t, 1, types[ChangeRemoved])
	assert.Equal(t, 1, types[ChangeAdded])
	assert.Equal(t, 2, types[ChangeModified])
}

// ---------------------------------------------------------------------------
// compareStaticMappings
// ---------------------------------------------------------------------------

func TestCompareStaticMappings_BothEmpty(t *testing.T) {
	t.Parallel()
	analyzer := NewAnalyzer()
	changes := analyzer.compareStaticMappings("lan", nil, nil)
	assert.Empty(t, changes)
}

func TestCompareStaticMappings_OnlyOldHasMappings(t *testing.T) {
	t.Parallel()
	analyzer := NewAnalyzer()
	old := []common.DHCPStaticLease{
		{MAC: "aa:bb:cc:dd:ee:01", IPAddress: "10.0.0.10", Hostname: "server1"},
		{MAC: "aa:bb:cc:dd:ee:02", IPAddress: "10.0.0.11", Hostname: "server2"},
	}

	changes := analyzer.compareStaticMappings("lan", old, nil)

	require.Len(t, changes, 2)
	for _, c := range changes {
		assert.Equal(t, ChangeRemoved, c.Type)
		assert.Equal(t, SectionDHCP, c.Section)
		assert.Contains(t, c.Path, "dhcpd.lan.staticmap[")
		assert.NotEmpty(t, c.OldValue)
	}
}

func TestCompareStaticMappings_OnlyNewHasMappings(t *testing.T) {
	t.Parallel()
	analyzer := NewAnalyzer()
	newCfg := []common.DHCPStaticLease{
		{MAC: "aa:bb:cc:dd:ee:01", IPAddress: "10.0.0.10", Hostname: "server1"},
		{MAC: "aa:bb:cc:dd:ee:02", IPAddress: "10.0.0.11", Hostname: "server2"},
	}

	changes := analyzer.compareStaticMappings("lan", nil, newCfg)

	require.Len(t, changes, 2)
	for _, c := range changes {
		assert.Equal(t, ChangeAdded, c.Type)
		assert.Equal(t, SectionDHCP, c.Section)
		assert.Contains(t, c.Path, "dhcpd.lan.staticmap[")
		assert.NotEmpty(t, c.NewValue)
	}
}

func TestCompareStaticMappings_SameMappings(t *testing.T) {
	t.Parallel()
	analyzer := NewAnalyzer()
	leases := []common.DHCPStaticLease{
		{MAC: "aa:bb:cc:dd:ee:01", IPAddress: "10.0.0.10", Hostname: "server1"},
		{MAC: "aa:bb:cc:dd:ee:02", IPAddress: "10.0.0.11", Hostname: "server2"},
	}

	changes := analyzer.compareStaticMappings("lan", leases, leases)

	assert.Empty(t, changes)
}

func TestCompareStaticMappings_IPAddressChanged(t *testing.T) {
	t.Parallel()
	analyzer := NewAnalyzer()
	old := []common.DHCPStaticLease{
		{MAC: "aa:bb:cc:dd:ee:01", IPAddress: "10.0.0.10", Hostname: "server1"},
	}
	newCfg := []common.DHCPStaticLease{
		{MAC: "aa:bb:cc:dd:ee:01", IPAddress: "10.0.0.99", Hostname: "server1"},
	}

	changes := analyzer.compareStaticMappings("lan", old, newCfg)

	require.Len(t, changes, 1)
	assert.Equal(t, ChangeModified, changes[0].Type)
	assert.Contains(t, changes[0].Path, "ipaddr")
	assert.Equal(t, "10.0.0.10", changes[0].OldValue)
	assert.Equal(t, "10.0.0.99", changes[0].NewValue)
}

func TestCompareStaticMappings_HostnameChanged(t *testing.T) {
	t.Parallel()
	analyzer := NewAnalyzer()
	old := []common.DHCPStaticLease{
		{MAC: "aa:bb:cc:dd:ee:01", IPAddress: "10.0.0.10", Hostname: "old-host"},
	}
	newCfg := []common.DHCPStaticLease{
		{MAC: "aa:bb:cc:dd:ee:01", IPAddress: "10.0.0.10", Hostname: "new-host"},
	}

	changes := analyzer.compareStaticMappings("lan", old, newCfg)

	require.Len(t, changes, 1)
	assert.Equal(t, ChangeModified, changes[0].Type)
	assert.Contains(t, changes[0].Path, "hostname")
	assert.Equal(t, "old-host", changes[0].OldValue)
	assert.Equal(t, "new-host", changes[0].NewValue)
}

func TestCompareStaticMappings_BothIPAndHostnameChanged(t *testing.T) {
	t.Parallel()
	analyzer := NewAnalyzer()
	old := []common.DHCPStaticLease{
		{MAC: "aa:bb:cc:dd:ee:01", IPAddress: "10.0.0.10", Hostname: "old-host"},
	}
	newCfg := []common.DHCPStaticLease{
		{MAC: "aa:bb:cc:dd:ee:01", IPAddress: "10.0.0.99", Hostname: "new-host"},
	}

	changes := analyzer.compareStaticMappings("lan", old, newCfg)

	require.Len(t, changes, 2)
	// One for IP, one for hostname
	paths := make(map[string]bool)
	for _, c := range changes {
		paths[c.Path] = true
		assert.Equal(t, ChangeModified, c.Type)
	}
	assert.True(t, paths["dhcpd.lan.staticmap[aa:bb:cc:dd:ee:01].ipaddr"])
	assert.True(t, paths["dhcpd.lan.staticmap[aa:bb:cc:dd:ee:01].hostname"])
}

func TestCompareStaticMappings_MixedAddRemoveModify(t *testing.T) {
	t.Parallel()
	analyzer := NewAnalyzer()
	old := []common.DHCPStaticLease{
		{MAC: "aa:bb:cc:dd:ee:01", IPAddress: "10.0.0.10", Hostname: "kept"},
		{MAC: "aa:bb:cc:dd:ee:02", IPAddress: "10.0.0.11", Hostname: "removed"},
		{MAC: "aa:bb:cc:dd:ee:03", IPAddress: "10.0.0.12", Hostname: "modified"},
	}
	newCfg := []common.DHCPStaticLease{
		{MAC: "aa:bb:cc:dd:ee:01", IPAddress: "10.0.0.10", Hostname: "kept"},
		{MAC: "aa:bb:cc:dd:ee:03", IPAddress: "10.0.0.99", Hostname: "modified"},
		{MAC: "aa:bb:cc:dd:ee:04", IPAddress: "10.0.0.13", Hostname: "added"},
	}

	changes := analyzer.compareStaticMappings("lan", old, newCfg)

	// 1 removed (ee:02), 1 added (ee:04), 1 modified IP (ee:03)
	require.Len(t, changes, 3)

	types := make(map[ChangeType]int)
	for _, c := range changes {
		types[c.Type]++
	}
	assert.Equal(t, 1, types[ChangeRemoved])
	assert.Equal(t, 1, types[ChangeAdded])
	assert.Equal(t, 1, types[ChangeModified])
}

// ---------------------------------------------------------------------------
// CompareDHCP — static leases integration via CompareDHCP
// ---------------------------------------------------------------------------

func TestCompareDHCP_StaticLeasesViaCompareDHCP(t *testing.T) {
	t.Parallel()
	analyzer := NewAnalyzer()
	old := []common.DHCPScope{
		{
			Interface: "lan",
			Enabled:   true,
			Range:     common.DHCPRange{From: "10.0.0.100", To: "10.0.0.200"},
			StaticLeases: []common.DHCPStaticLease{
				{MAC: "aa:bb:cc:dd:ee:01", IPAddress: "10.0.0.10", Hostname: "server1"},
			},
		},
	}
	newCfg := []common.DHCPScope{
		{
			Interface: "lan",
			Enabled:   true,
			Range:     common.DHCPRange{From: "10.0.0.100", To: "10.0.0.200"},
			StaticLeases: []common.DHCPStaticLease{
				{MAC: "aa:bb:cc:dd:ee:01", IPAddress: "10.0.0.10", Hostname: "server1"},
				{MAC: "aa:bb:cc:dd:ee:02", IPAddress: "10.0.0.11", Hostname: "server2"},
			},
		},
	}

	changes := analyzer.CompareDHCP(old, newCfg)

	require.Len(t, changes, 1)
	assert.Equal(t, ChangeAdded, changes[0].Type)
	assert.Contains(t, changes[0].Path, "staticmap")
}

// ---------------------------------------------------------------------------
// staticLeaseLabel
// ---------------------------------------------------------------------------

func TestStaticLeaseLabel(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		lease common.DHCPStaticLease
		want  string
	}{
		{
			name:  "hostname present",
			lease: common.DHCPStaticLease{MAC: "aa:bb:cc:dd:ee:01", Hostname: "server1", Description: "desc"},
			want:  "server1",
		},
		{
			name:  "no hostname, description present",
			lease: common.DHCPStaticLease{MAC: "aa:bb:cc:dd:ee:01", Description: "my desc"},
			want:  "my desc",
		},
		{
			name:  "no hostname or description, falls back to MAC",
			lease: common.DHCPStaticLease{MAC: "aa:bb:cc:dd:ee:01"},
			want:  "aa:bb:cc:dd:ee:01",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := staticLeaseLabel(tt.lease)
			assert.Equal(t, tt.want, got)
		})
	}
}

// ---------------------------------------------------------------------------
// formatStaticLease
// ---------------------------------------------------------------------------

func TestFormatStaticLease(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		lease common.DHCPStaticLease
		want  string
	}{
		{
			name:  "IP and MAC only",
			lease: common.DHCPStaticLease{MAC: "aa:bb:cc:dd:ee:01", IPAddress: "10.0.0.10"},
			want:  "ip=10.0.0.10, mac=aa:bb:cc:dd:ee:01",
		},
		{
			name: "all fields",
			lease: common.DHCPStaticLease{
				MAC:         "aa:bb:cc:dd:ee:01",
				IPAddress:   "10.0.0.10",
				Hostname:    "server1",
				Description: "web server",
			},
			want: "ip=10.0.0.10, mac=aa:bb:cc:dd:ee:01, hostname=server1, descr=web server",
		},
		{
			name: "hostname only, no description",
			lease: common.DHCPStaticLease{
				MAC:       "aa:bb:cc:dd:ee:01",
				IPAddress: "10.0.0.10",
				Hostname:  "server1",
			},
			want: "ip=10.0.0.10, mac=aa:bb:cc:dd:ee:01, hostname=server1",
		},
		{
			name: "description only, no hostname",
			lease: common.DHCPStaticLease{
				MAC:         "aa:bb:cc:dd:ee:01",
				IPAddress:   "10.0.0.10",
				Description: "my desc",
			},
			want: "ip=10.0.0.10, mac=aa:bb:cc:dd:ee:01, descr=my desc",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := formatStaticLease(tt.lease)
			assert.Equal(t, tt.want, got)
		})
	}
}

// ---------------------------------------------------------------------------
// CompareDHCP — edge cases
// ---------------------------------------------------------------------------

func TestCompareDHCP_RangeFromChangedOnly(t *testing.T) {
	t.Parallel()
	analyzer := NewAnalyzer()
	old := []common.DHCPScope{
		{Interface: "lan", Range: common.DHCPRange{From: "10.0.0.100", To: "10.0.0.200"}},
	}
	newCfg := []common.DHCPScope{
		{Interface: "lan", Range: common.DHCPRange{From: "10.0.0.50", To: "10.0.0.200"}},
	}

	changes := analyzer.CompareDHCP(old, newCfg)

	require.Len(t, changes, 1)
	assert.Equal(t, ChangeModified, changes[0].Type)
	assert.Contains(t, changes[0].Path, "range")
}

func TestCompareDHCP_RangeToChangedOnly(t *testing.T) {
	t.Parallel()
	analyzer := NewAnalyzer()
	old := []common.DHCPScope{
		{Interface: "lan", Range: common.DHCPRange{From: "10.0.0.100", To: "10.0.0.200"}},
	}
	newCfg := []common.DHCPScope{
		{Interface: "lan", Range: common.DHCPRange{From: "10.0.0.100", To: "10.0.0.250"}},
	}

	changes := analyzer.CompareDHCP(old, newCfg)

	require.Len(t, changes, 1)
	assert.Equal(t, ChangeModified, changes[0].Type)
}

func TestCompareDHCP_MultipleInterfacesSorted(t *testing.T) {
	t.Parallel()
	analyzer := NewAnalyzer()
	// Use non-alphabetical order to ensure deterministic sorting
	old := []common.DHCPScope{
		{Interface: "opt2", Enabled: true},
		{Interface: "lan", Enabled: true},
		{Interface: "opt1", Enabled: true},
	}
	newCfg := []common.DHCPScope{
		{Interface: "opt2", Enabled: true},
		{Interface: "lan", Enabled: true},
		{Interface: "opt1", Enabled: true},
	}

	changes := analyzer.CompareDHCP(old, newCfg)
	assert.Empty(t, changes)
}

func TestCompareStaticMappings_DifferentInterface(t *testing.T) {
	t.Parallel()
	analyzer := NewAnalyzer()
	leases := []common.DHCPStaticLease{
		{MAC: "aa:bb:cc:dd:ee:01", IPAddress: "10.0.0.10"},
	}

	changes := analyzer.compareStaticMappings("opt1", nil, leases)

	require.Len(t, changes, 1)
	assert.Contains(t, changes[0].Path, "dhcpd.opt1.staticmap")
}

func TestCompareStaticMappings_DescriptionInFormat(t *testing.T) {
	t.Parallel()
	analyzer := NewAnalyzer()
	newCfg := []common.DHCPStaticLease{
		{
			MAC:         "aa:bb:cc:dd:ee:01",
			IPAddress:   "10.0.0.10",
			Description: "printer",
		},
	}

	changes := analyzer.compareStaticMappings("lan", nil, newCfg)

	require.Len(t, changes, 1)
	assert.Contains(t, changes[0].NewValue, "descr=printer")
	// Label should fall back to description since hostname is empty
	assert.Contains(t, changes[0].Description, "printer")
}
