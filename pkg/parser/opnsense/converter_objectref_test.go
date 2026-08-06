package opnsense_test

import (
	"testing"

	opnsense "github.com/EvilBit-Labs/opnDossier/pkg/parser/opnsense"
	schema "github.com/EvilBit-Labs/opnDossier/pkg/schema/opnsense"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestConverter_ObjectRefs_RoutingAndNAT proves the converter populates the
// unused-object-detection ObjectRef fields (#203) from a real parsed document,
// not just when a test hand-builds the CommonDevice. Without this, a
// field-mapping typo in the converter would compile and pass every detector
// test while silently reintroducing an R6 false positive.
func TestConverter_ObjectRefs_RoutingAndNAT(t *testing.T) {
	t.Parallel()

	doc := schema.NewOpnSenseDocument()
	withMVCAliases(doc,
		schema.Alias{Name: "BRANCH_NET", Type: "network", Content: "10.1.0.0/16"},
		schema.Alias{Name: "NAT_POOL", Type: "host", Content: "203.0.113.5"},
		schema.Alias{Name: "BACKEND", Type: "host", Content: "10.0.0.9"},
		schema.Alias{Name: "SVC_PORTS", Type: "port", Content: "8080"},
	)
	// Alias in the static-route destination network.
	doc.StaticRoutes.Route = []schema.StaticRoute{
		{Network: "BRANCH_NET", Gateway: "WAN_GW"},
		{Network: "192.168.9.0/24", Gateway: "WAN_GW"}, // literal → nil ref
	}
	// Aliases in NAT translation targets/ports.
	doc.Nat.Outbound.Rule = []schema.NATRule{{Target: "NAT_POOL"}}
	doc.Nat.Inbound = []schema.InboundRule{
		{InternalIP: "BACKEND", InternalPort: "SVC_PORTS"},
	}

	device, _, err := opnsense.ConvertDocument(doc)
	require.NoError(t, err)

	require.Len(t, device.Routing.StaticRoutes, 2)
	require.NotNil(t, device.Routing.StaticRoutes[0].NetworkRef, "alias route should carry NetworkRef")
	assert.Equal(t, "BRANCH_NET", device.Routing.StaticRoutes[0].NetworkRef.Name)
	assert.Nil(t, device.Routing.StaticRoutes[1].NetworkRef, "literal route must not carry a ref")

	require.Len(t, device.NAT.OutboundRules, 1)
	require.NotNil(t, device.NAT.OutboundRules[0].TargetRef)
	assert.Equal(t, "NAT_POOL", device.NAT.OutboundRules[0].TargetRef.Name)

	require.Len(t, device.NAT.InboundRules, 1)
	require.NotNil(t, device.NAT.InboundRules[0].InternalIPRef)
	assert.Equal(t, "BACKEND", device.NAT.InboundRules[0].InternalIPRef.Name)
	require.NotNil(t, device.NAT.InboundRules[0].InternalPortRef)
	assert.Equal(t, "SVC_PORTS", device.NAT.InboundRules[0].InternalPortRef.Name)
}

// TestConverter_ObjectRefs_OPNsenseOpenVPNStaysNil pins the deliberate
// vendor divergence (KTD-1): OPNsense does not support aliases in OpenVPN
// Local/Remote Network fields (opnsense/core#9105 open), so the OPNsense
// converter must NOT populate those refs even when the field value happens to
// match an alias name. pfSense populates them; this asymmetry is intentional.
func TestConverter_ObjectRefs_OPNsenseOpenVPNStaysNil(t *testing.T) {
	t.Parallel()

	doc := schema.NewOpnSenseDocument()
	withMVCAliases(doc, schema.Alias{Name: "VPN_LAN", Type: "network", Content: "10.8.0.0/24"})
	doc.OpenVPN.Servers = []schema.OpenVPNServer{{Local_network: "VPN_LAN"}}

	device, _, err := opnsense.ConvertDocument(doc)
	require.NoError(t, err)

	require.Len(t, device.VPN.OpenVPN.Servers, 1)
	assert.Nil(t, device.VPN.OpenVPN.Servers[0].LocalNetworkRef,
		"OPNsense must not populate OpenVPN network refs (deliberate divergence)")
}
