package pfsense

import (
	"encoding/xml"
	"testing"

	opnsense "github.com/EvilBit-Labs/opnDossier/pkg/schema/opnsense"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDHCPv6_XMLRoundTrip(t *testing.T) {
	t.Parallel()

	original := DHCPv6{
		Items: map[string]DHCPv6Interface{
			"lan": {
				Enable:     "1",
				RAMode:     "assist",
				RAPriority: "medium",
				Range: opnsense.Range{
					From: "::1000",
					To:   "::2000",
				},
			},
			"opt0": {
				Enable: "1",
				RAMode: "unmanaged",
			},
		},
	}

	out, err := xml.Marshal(&original)
	require.NoError(t, err)

	var decoded DHCPv6
	err = xml.Unmarshal(out, &decoded)
	require.NoError(t, err)
	require.Len(t, decoded.Items, 2, "round-trip must preserve exact key count")

	lanIface, ok := decoded.Get("lan")
	require.True(t, ok, "lan must exist after round-trip")
	assert.Equal(t, "1", lanIface.Enable)
	assert.Equal(t, "assist", lanIface.RAMode)
	assert.Equal(t, "medium", lanIface.RAPriority)
	assert.Equal(t, "::1000", lanIface.Range.From)
	assert.Equal(t, "::2000", lanIface.Range.To)

	opt0Iface, ok := decoded.Get("opt0")
	require.True(t, ok, "opt0 must exist after round-trip")
	assert.Equal(t, "unmanaged", opt0Iface.RAMode)
}

func TestDHCPv6_Get(t *testing.T) {
	t.Parallel()

	t.Run("returns interface when present", func(t *testing.T) {
		t.Parallel()

		d := DHCPv6{
			Items: map[string]DHCPv6Interface{
				"lan": {Enable: "1", RAMode: "assist"},
			},
		}

		iface, ok := d.Get("lan")
		assert.True(t, ok)
		assert.Equal(t, "assist", iface.RAMode)
	})

	t.Run("returns false for missing key", func(t *testing.T) {
		t.Parallel()

		d := DHCPv6{
			Items: map[string]DHCPv6Interface{
				"lan": {Enable: "1"},
			},
		}

		_, ok := d.Get("wan")
		assert.False(t, ok)
	})

	t.Run("returns false for nil map", func(t *testing.T) {
		t.Parallel()

		d := DHCPv6{}

		_, ok := d.Get("lan")
		assert.False(t, ok)
	})
}

func TestDHCPv6_Names(t *testing.T) {
	t.Parallel()

	t.Run("returns sorted names", func(t *testing.T) {
		t.Parallel()

		d := DHCPv6{
			Items: map[string]DHCPv6Interface{
				"opt0": {},
				"lan":  {},
				"wan":  {},
			},
		}

		names := d.Names()
		assert.Equal(t, []string{"lan", "opt0", "wan"}, names)
	})

	t.Run("returns empty slice for nil map", func(t *testing.T) {
		t.Parallel()

		d := DHCPv6{}
		names := d.Names()
		assert.Equal(t, []string{}, names)
	})
}

func TestInterfaces_Names(t *testing.T) {
	t.Parallel()

	t.Run("returns sorted names", func(t *testing.T) {
		t.Parallel()

		ifaces := Interfaces{
			Items: map[string]Interface{
				"opt0": {If: "em2"},
				"lan":  {If: "em1"},
				"wan":  {If: "em0"},
			},
		}

		names := ifaces.Names()
		assert.Equal(t, []string{"lan", "opt0", "wan"}, names)
	})

	t.Run("returns empty slice for nil map", func(t *testing.T) {
		t.Parallel()

		ifaces := Interfaces{}
		names := ifaces.Names()
		assert.Equal(t, []string{}, names)
	})
}

func TestInterfaces_Wan(t *testing.T) {
	t.Parallel()

	t.Run("returns WAN when present", func(t *testing.T) {
		t.Parallel()

		ifaces := Interfaces{
			Items: map[string]Interface{
				"wan": {If: "em0", Descr: "WAN"},
			},
		}

		iface, ok := ifaces.Wan()
		assert.True(t, ok)
		assert.Equal(t, "em0", iface.If)
	})

	t.Run("returns false when absent", func(t *testing.T) {
		t.Parallel()

		ifaces := Interfaces{
			Items: map[string]Interface{
				"lan": {If: "em1"},
			},
		}

		_, ok := ifaces.Wan()
		assert.False(t, ok)
	})
}

func TestInterfaces_Lan(t *testing.T) {
	t.Parallel()

	t.Run("returns LAN when present", func(t *testing.T) {
		t.Parallel()

		ifaces := Interfaces{
			Items: map[string]Interface{
				"lan": {If: "em1", Descr: "LAN"},
			},
		}

		iface, ok := ifaces.Lan()
		assert.True(t, ok)
		assert.Equal(t, "em1", iface.If)
	})

	t.Run("returns false when absent", func(t *testing.T) {
		t.Parallel()

		ifaces := Interfaces{
			Items: map[string]Interface{
				"wan": {If: "em0"},
			},
		}

		_, ok := ifaces.Lan()
		assert.False(t, ok)
	})
}

func TestDhcpd_Names(t *testing.T) {
	t.Parallel()

	t.Run("returns sorted names", func(t *testing.T) {
		t.Parallel()

		d := Dhcpd{
			Items: map[string]DhcpdInterface{
				"opt0": {},
				"lan":  {},
			},
		}

		names := d.Names()
		assert.Equal(t, []string{"lan", "opt0"}, names)
	})

	t.Run("returns empty slice for nil map", func(t *testing.T) {
		t.Parallel()

		d := Dhcpd{}
		names := d.Names()
		assert.Equal(t, []string{}, names)
	})
}

func TestDhcpd_Wan(t *testing.T) {
	t.Parallel()

	t.Run("returns WAN DHCP when present", func(t *testing.T) {
		t.Parallel()

		d := Dhcpd{
			Items: map[string]DhcpdInterface{
				"wan": {Gateway: "192.168.1.1"},
			},
		}

		iface, ok := d.Wan()
		assert.True(t, ok)
		assert.Equal(t, "192.168.1.1", iface.Gateway)
	})

	t.Run("returns false when absent", func(t *testing.T) {
		t.Parallel()

		d := Dhcpd{
			Items: map[string]DhcpdInterface{
				"lan": {},
			},
		}

		_, ok := d.Wan()
		assert.False(t, ok)
	})
}

func TestDhcpd_Lan(t *testing.T) {
	t.Parallel()

	t.Run("returns LAN DHCP when present", func(t *testing.T) {
		t.Parallel()

		d := Dhcpd{
			Items: map[string]DhcpdInterface{
				"lan": {Gateway: "10.0.0.1"},
			},
		}

		iface, ok := d.Lan()
		assert.True(t, ok)
		assert.Equal(t, "10.0.0.1", iface.Gateway)
	})

	t.Run("returns false when absent", func(t *testing.T) {
		t.Parallel()

		d := Dhcpd{Items: map[string]DhcpdInterface{}}

		_, ok := d.Lan()
		assert.False(t, ok)
	})
}
