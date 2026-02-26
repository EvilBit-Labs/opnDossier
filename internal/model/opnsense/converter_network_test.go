package opnsense_test

import (
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/model/opnsense"
	"github.com/EvilBit-Labs/opnDossier/internal/schema"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConverter_Bridges(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		bridges []schema.Bridge
		wantLen int
	}{
		{
			name:    "empty bridges returns nil",
			bridges: nil,
			wantLen: 0,
		},
		{
			name: "single bridge with STP",
			bridges: []schema.Bridge{
				{
					Bridgeif: "bridge0",
					Members:  "opt1,opt2",
					Descr:    "LAN Bridge",
					STP:      true,
					Created:  "2024-01-01",
					Updated:  "2024-06-15",
				},
			},
			wantLen: 1,
		},
		{
			name: "multiple bridges",
			bridges: []schema.Bridge{
				{Bridgeif: "bridge0", Members: "opt1,opt2", Descr: "Internal"},
				{Bridgeif: "bridge1", Members: "opt3", Descr: "DMZ"},
			},
			wantLen: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			doc := schema.NewOpnSenseDocument()
			doc.Bridges.Bridge = tt.bridges

			device, err := opnsense.NewConverter().ToCommonDevice(doc)
			require.NoError(t, err)

			if tt.wantLen == 0 {
				assert.Nil(t, device.Bridges)
				return
			}
			require.Len(t, device.Bridges, tt.wantLen)
		})
	}
}

func TestConverter_Bridges_FieldMapping(t *testing.T) {
	t.Parallel()

	doc := schema.NewOpnSenseDocument()
	doc.Bridges.Bridge = []schema.Bridge{
		{
			Bridgeif: "bridge0",
			Members:  "opt1,opt2,opt3",
			Descr:    "LAN Bridge",
			STP:      true,
			Created:  "2024-01-01",
			Updated:  "2024-06-15",
		},
	}

	device, err := opnsense.NewConverter().ToCommonDevice(doc)
	require.NoError(t, err)
	require.Len(t, device.Bridges, 1)

	b := device.Bridges[0]
	assert.Equal(t, "bridge0", b.BridgeIf)
	assert.Equal(t, []string{"opt1", "opt2", "opt3"}, b.Members)
	assert.Equal(t, "LAN Bridge", b.Description)
	assert.True(t, b.STP)
	assert.Equal(t, "2024-01-01", b.Created)
	assert.Equal(t, "2024-06-15", b.Updated)
}

func TestConverter_Bridges_EmptyMembers(t *testing.T) {
	t.Parallel()

	doc := schema.NewOpnSenseDocument()
	doc.Bridges.Bridge = []schema.Bridge{
		{Bridgeif: "bridge0", Members: ""},
	}

	device, err := opnsense.NewConverter().ToCommonDevice(doc)
	require.NoError(t, err)
	require.Len(t, device.Bridges, 1)
	assert.Nil(t, device.Bridges[0].Members)
}

func TestConverter_PPPs(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		ppps    []schema.PPP
		wantLen int
	}{
		{
			name:    "empty PPPs returns nil",
			ppps:    nil,
			wantLen: 0,
		},
		{
			name: "single PPPoE",
			ppps: []schema.PPP{
				{If: "pppoe0", Type: "pppoe", Descr: "WAN PPPoE"},
			},
			wantLen: 1,
		},
		{
			name: "mixed PPP types",
			ppps: []schema.PPP{
				{If: "pppoe0", Type: "pppoe", Descr: "WAN"},
				{If: "pptp0", Type: "pptp", Descr: "VPN"},
				{If: "l2tp0", Type: "l2tp", Descr: "Remote"},
			},
			wantLen: 3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			doc := schema.NewOpnSenseDocument()
			doc.PPPInterfaces.Ppp = tt.ppps

			device, err := opnsense.NewConverter().ToCommonDevice(doc)
			require.NoError(t, err)

			if tt.wantLen == 0 {
				assert.Nil(t, device.PPPs)
				return
			}
			require.Len(t, device.PPPs, tt.wantLen)
		})
	}
}

func TestConverter_PPPs_FieldMapping(t *testing.T) {
	t.Parallel()

	doc := schema.NewOpnSenseDocument()
	doc.PPPInterfaces.Ppp = []schema.PPP{
		{If: "pppoe0", Type: "pppoe", Descr: "ISP Connection"},
	}

	device, err := opnsense.NewConverter().ToCommonDevice(doc)
	require.NoError(t, err)
	require.Len(t, device.PPPs, 1)

	p := device.PPPs[0]
	assert.Equal(t, "pppoe0", p.Interface)
	assert.Equal(t, "pppoe", p.Type)
	assert.Equal(t, "ISP Connection", p.Description)
}

func TestConverter_GIFs(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		gifs    []schema.GIF
		wantLen int
	}{
		{
			name:    "empty GIFs returns nil",
			gifs:    nil,
			wantLen: 0,
		},
		{
			name: "single GIF tunnel",
			gifs: []schema.GIF{
				{
					Gifif:   "gif0",
					If:      "wan",
					Remote:  "209.51.181.2",
					Descr:   "HE IPv6 Tunnel",
					Created: "2024-03-01",
					Updated: "2024-03-15",
				},
			},
			wantLen: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			doc := schema.NewOpnSenseDocument()
			doc.GIFInterfaces.Gif = tt.gifs

			device, err := opnsense.NewConverter().ToCommonDevice(doc)
			require.NoError(t, err)

			if tt.wantLen == 0 {
				assert.Nil(t, device.GIFs)
				return
			}
			require.Len(t, device.GIFs, tt.wantLen)
		})
	}
}

func TestConverter_GIFs_FieldMapping(t *testing.T) {
	t.Parallel()

	doc := schema.NewOpnSenseDocument()
	doc.GIFInterfaces.Gif = []schema.GIF{
		{
			Gifif:   "gif0",
			If:      "wan",
			Remote:  "209.51.181.2",
			Descr:   "HE IPv6 Tunnel",
			Created: "2024-03-01",
			Updated: "2024-03-15",
		},
	}

	device, err := opnsense.NewConverter().ToCommonDevice(doc)
	require.NoError(t, err)
	require.Len(t, device.GIFs, 1)

	g := device.GIFs[0]
	assert.Equal(t, "gif0", g.Interface)
	assert.Equal(t, "wan", g.Local)
	assert.Equal(t, "209.51.181.2", g.Remote)
	assert.Equal(t, "HE IPv6 Tunnel", g.Description)
	assert.Equal(t, "2024-03-01", g.Created)
	assert.Equal(t, "2024-03-15", g.Updated)
}

//nolint:dupl // tunnel converter tests (GIF/GRE/LAGG) are structurally similar by design
func TestConverter_GREs(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		gres    []schema.GRE
		wantLen int
	}{
		{
			name:    "empty GREs returns nil",
			gres:    nil,
			wantLen: 0,
		},
		{
			name: "single GRE tunnel",
			gres: []schema.GRE{
				{
					Greif:   "gre0",
					If:      "wan",
					Remote:  "198.51.100.1",
					Descr:   "Datacenter GRE",
					Created: "2024-02-01",
					Updated: "2024-02-10",
				},
			},
			wantLen: 1,
		},
		{
			name: "multiple GRE tunnels",
			gres: []schema.GRE{
				{Greif: "gre0", If: "wan", Remote: "198.51.100.1", Descr: "DC1"},
				{Greif: "gre1", If: "opt1", Remote: "198.51.100.2", Descr: "DC2"},
			},
			wantLen: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			doc := schema.NewOpnSenseDocument()
			doc.GREInterfaces.Gre = tt.gres

			device, err := opnsense.NewConverter().ToCommonDevice(doc)
			require.NoError(t, err)

			if tt.wantLen == 0 {
				assert.Nil(t, device.GREs)
				return
			}
			require.Len(t, device.GREs, tt.wantLen)
		})
	}
}

func TestConverter_GREs_FieldMapping(t *testing.T) {
	t.Parallel()

	doc := schema.NewOpnSenseDocument()
	doc.GREInterfaces.Gre = []schema.GRE{
		{
			Greif:   "gre0",
			If:      "wan",
			Remote:  "198.51.100.1",
			Descr:   "Datacenter GRE",
			Created: "2024-02-01",
			Updated: "2024-02-10",
		},
	}

	device, err := opnsense.NewConverter().ToCommonDevice(doc)
	require.NoError(t, err)
	require.Len(t, device.GREs, 1)

	g := device.GREs[0]
	assert.Equal(t, "gre0", g.Interface)
	assert.Equal(t, "wan", g.Local)
	assert.Equal(t, "198.51.100.1", g.Remote)
	assert.Equal(t, "Datacenter GRE", g.Description)
	assert.Equal(t, "2024-02-01", g.Created)
	assert.Equal(t, "2024-02-10", g.Updated)
}

//nolint:dupl // tunnel converter tests (GIF/GRE/LAGG) are structurally similar by design
func TestConverter_LAGGs(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		laggs   []schema.LAGG
		wantLen int
	}{
		{
			name:    "empty LAGGs returns nil",
			laggs:   nil,
			wantLen: 0,
		},
		{
			name: "single LACP bond",
			laggs: []schema.LAGG{
				{
					Laggif:  "lagg0",
					Members: "ix0,ix1",
					Proto:   "lacp",
					Descr:   "LAN LACP Bond",
					Created: "2024-01-15",
					Updated: "2024-01-20",
				},
			},
			wantLen: 1,
		},
		{
			name: "multiple LAGG protocols",
			laggs: []schema.LAGG{
				{Laggif: "lagg0", Members: "ix0,ix1", Proto: "lacp", Descr: "LACP"},
				{Laggif: "lagg1", Members: "ix2,ix3", Proto: "failover", Descr: "Failover"},
			},
			wantLen: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			doc := schema.NewOpnSenseDocument()
			doc.LAGGInterfaces.Lagg = tt.laggs

			device, err := opnsense.NewConverter().ToCommonDevice(doc)
			require.NoError(t, err)

			if tt.wantLen == 0 {
				assert.Nil(t, device.LAGGs)
				return
			}
			require.Len(t, device.LAGGs, tt.wantLen)
		})
	}
}

func TestConverter_LAGGs_FieldMapping(t *testing.T) {
	t.Parallel()

	doc := schema.NewOpnSenseDocument()
	doc.LAGGInterfaces.Lagg = []schema.LAGG{
		{
			Laggif:  "lagg0",
			Members: "ix0,ix1,ix2",
			Proto:   "lacp",
			Descr:   "Server Bond",
			Created: "2024-01-15",
			Updated: "2024-01-20",
		},
	}

	device, err := opnsense.NewConverter().ToCommonDevice(doc)
	require.NoError(t, err)
	require.Len(t, device.LAGGs, 1)

	l := device.LAGGs[0]
	assert.Equal(t, "lagg0", l.Interface)
	assert.Equal(t, []string{"ix0", "ix1", "ix2"}, l.Members)
	assert.Equal(t, "lacp", l.Protocol)
	assert.Equal(t, "Server Bond", l.Description)
	assert.Equal(t, "2024-01-15", l.Created)
	assert.Equal(t, "2024-01-20", l.Updated)
}

func TestConverter_VirtualIPs(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		vips    []schema.VIP
		wantLen int
	}{
		{
			name:    "empty VIPs returns nil",
			vips:    nil,
			wantLen: 0,
		},
		{
			name: "mixed VIP modes",
			vips: []schema.VIP{
				{Mode: "carp", Interface: "wan", Subnet: "203.0.113.100", Descr: "WAN CARP"},
				{Mode: "ipalias", Interface: "lan", Subnet: "192.168.1.200", Descr: "LAN Alias"},
				{Mode: "proxyarp", Interface: "wan", Subnet: "203.0.113.64", Descr: "Proxy ARP"},
			},
			wantLen: 3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			doc := schema.NewOpnSenseDocument()
			doc.VirtualIP.Vip = tt.vips

			device, err := opnsense.NewConverter().ToCommonDevice(doc)
			require.NoError(t, err)

			if tt.wantLen == 0 {
				assert.Nil(t, device.VirtualIPs)
				return
			}
			require.Len(t, device.VirtualIPs, tt.wantLen)
		})
	}
}

func TestConverter_VirtualIPs_FieldMapping(t *testing.T) {
	t.Parallel()

	doc := schema.NewOpnSenseDocument()
	doc.VirtualIP.Vip = []schema.VIP{
		{Mode: "carp", Interface: "wan", Subnet: "203.0.113.100", Descr: "WAN CARP VIP"},
	}

	device, err := opnsense.NewConverter().ToCommonDevice(doc)
	require.NoError(t, err)
	require.Len(t, device.VirtualIPs, 1)

	v := device.VirtualIPs[0]
	assert.Equal(t, "carp", v.Mode)
	assert.Equal(t, "wan", v.Interface)
	assert.Equal(t, "203.0.113.100", v.Subnet)
	assert.Equal(t, "WAN CARP VIP", v.Description)
}

func TestConverter_InterfaceGroups(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		groups  []schema.IfGroupEntry
		wantLen int
	}{
		{
			name:    "empty groups returns nil",
			groups:  nil,
			wantLen: 0,
		},
		{
			name: "single group with multiple members",
			groups: []schema.IfGroupEntry{
				{IfName: "INTERNAL", Members: "lan opt1 opt2"},
			},
			wantLen: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			doc := schema.NewOpnSenseDocument()
			doc.InterfaceGroups.IfGroupEntry = tt.groups

			device, err := opnsense.NewConverter().ToCommonDevice(doc)
			require.NoError(t, err)

			if tt.wantLen == 0 {
				assert.Nil(t, device.InterfaceGroups)
				return
			}
			require.Len(t, device.InterfaceGroups, tt.wantLen)
		})
	}
}

func TestConverter_InterfaceGroups_FieldMapping(t *testing.T) {
	t.Parallel()

	doc := schema.NewOpnSenseDocument()
	doc.InterfaceGroups.IfGroupEntry = []schema.IfGroupEntry{
		{IfName: "INTERNAL", Members: "lan opt1 opt2"},
	}

	device, err := opnsense.NewConverter().ToCommonDevice(doc)
	require.NoError(t, err)
	require.Len(t, device.InterfaceGroups, 1)

	ig := device.InterfaceGroups[0]
	assert.Equal(t, "INTERNAL", ig.Name)
	assert.Equal(t, []string{"lan", "opt1", "opt2"}, ig.Members)
}

func TestConverter_InterfaceGroups_SpaceSeparated(t *testing.T) {
	t.Parallel()

	doc := schema.NewOpnSenseDocument()
	doc.InterfaceGroups.IfGroupEntry = []schema.IfGroupEntry{
		{IfName: "GROUP1", Members: "  lan   opt1  "},
	}

	device, err := opnsense.NewConverter().ToCommonDevice(doc)
	require.NoError(t, err)
	require.Len(t, device.InterfaceGroups, 1)

	// splitNonEmpty trims whitespace from each part
	assert.Equal(t, []string{"lan", "opt1"}, device.InterfaceGroups[0].Members)
}
