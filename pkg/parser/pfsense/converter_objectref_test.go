package pfsense_test

import (
	"testing"

	pfsense "github.com/EvilBit-Labs/opnDossier/pkg/parser/pfsense"
	opnsense "github.com/EvilBit-Labs/opnDossier/pkg/schema/opnsense"
	pfsenseSchema "github.com/EvilBit-Labs/opnDossier/pkg/schema/pfsense"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestConverter_ObjectRefs_AllSurfaces proves the pfSense converter populates
// the unused-object-detection ObjectRef fields (#203) from a real parsed
// document across every Tracked surface — including the pfSense-only OpenVPN
// network refs (V4 and V6), which OPNsense deliberately omits. Without this, a
// field-mapping typo would compile and pass every detector test while silently
// reintroducing an R6 false positive.
func TestConverter_ObjectRefs_AllSurfaces(t *testing.T) {
	t.Parallel()

	doc := pfsenseSchema.NewDocument()
	doc.Aliases.Alias = []pfsenseSchema.Alias{
		{Name: "BRANCH_NET", Type: "network", Address: "10.1.0.0/16"},
		{Name: "NAT_POOL", Type: "host", Address: "203.0.113.5"},
		{Name: "BACKEND", Type: "host", Address: "10.0.0.9"},
		{Name: "VPN_LAN", Type: "network", Address: "10.8.0.0/24"},
		{Name: "VPN6", Type: "network", Address: "2001:db8::/48"},
	}
	// Static route destination network.
	doc.StaticRoutes.Route = []opnsense.StaticRoute{
		{Network: "BRANCH_NET", Gateway: "WAN_GW"},
		{Network: "192.168.9.0/24", Gateway: "WAN_GW"}, // literal → nil ref
	}
	// NAT translation targets. pfSense inbound uses <target> for the internal
	// redirect IP.
	doc.Nat.Outbound.Rule = []opnsense.NATRule{{Target: "NAT_POOL"}}
	doc.Nat.Inbound = []pfsenseSchema.InboundRule{{Target: "BACKEND"}}
	// OpenVPN local/remote networks — pfSense DOES accept aliases here (KTD-1).
	doc.OpenVPN.Servers = []opnsense.OpenVPNServer{
		{Local_network: "VPN_LAN", Remote_networkv6: "VPN6"},
	}

	device, _, err := pfsense.ConvertDocument(doc)
	require.NoError(t, err)

	require.Len(t, device.Routing.StaticRoutes, 2)
	require.NotNil(t, device.Routing.StaticRoutes[0].NetworkRef)
	assert.Equal(t, "BRANCH_NET", device.Routing.StaticRoutes[0].NetworkRef.Name)
	assert.Nil(t, device.Routing.StaticRoutes[1].NetworkRef, "literal route must not carry a ref")

	require.Len(t, device.NAT.OutboundRules, 1)
	require.NotNil(t, device.NAT.OutboundRules[0].TargetRef)
	assert.Equal(t, "NAT_POOL", device.NAT.OutboundRules[0].TargetRef.Name)

	require.Len(t, device.NAT.InboundRules, 1)
	require.NotNil(t, device.NAT.InboundRules[0].InternalIPRef)
	assert.Equal(t, "BACKEND", device.NAT.InboundRules[0].InternalIPRef.Name)

	require.Len(t, device.VPN.OpenVPN.Servers, 1)
	srv := device.VPN.OpenVPN.Servers[0]
	require.NotNil(t, srv.LocalNetworkRef, "pfSense should populate OpenVPN LocalNetworkRef")
	assert.Equal(t, "VPN_LAN", srv.LocalNetworkRef.Name)
	require.NotNil(t, srv.RemoteNetworkV6Ref, "V6 ref must map from the V6 field, not V4")
	assert.Equal(t, "VPN6", srv.RemoteNetworkV6Ref.Name)
	// Fields left empty carry no ref.
	assert.Nil(t, srv.RemoteNetworkRef)
	assert.Nil(t, srv.LocalNetworkV6Ref)
}
