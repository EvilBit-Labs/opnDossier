package opnsense_test

import (
	"testing"

	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
	"github.com/EvilBit-Labs/opnDossier/pkg/parser/opnsense"
	schema "github.com/EvilBit-Labs/opnDossier/pkg/schema/opnsense"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// withMVCAliases attaches a populated MVC-path Firewall/Alias/aliases subtree
// to doc, returning doc for chaining.
func withMVCAliases(doc *schema.OpnSenseDocument, aliases ...schema.Alias) *schema.OpnSenseDocument {
	fw := &schema.Firewall{}
	fw.Alias.Aliases.Alias = aliases
	doc.OPNsense.Firewall = fw
	return doc
}

func TestConverter_NamedObjects_NoAliases(t *testing.T) {
	t.Parallel()

	doc := schema.NewOpnSenseDocument()

	device, warnings, err := opnsense.ConvertDocument(doc)
	require.NoError(t, err)
	assert.Empty(t, warnings)
	assert.Nil(t, device.NamedObjects)
}

func TestConverter_NamedObjects_MVCPath_HostNetworkPort(t *testing.T) {
	t.Parallel()

	doc := withMVCAliases(schema.NewOpnSenseDocument(),
		schema.Alias{
			Name:        "WEB_SERVERS",
			Type:        "host",
			Content:     "10.20.30.40\n10.20.30.41",
			Description: "Web server hosts",
		},
		schema.Alias{
			Name:        "INTERNAL_NET",
			Type:        "network",
			Content:     "10.20.0.0/16",
			Description: "Internal network",
		},
		schema.Alias{
			Name:        "WEB_PORTS",
			Type:        "port",
			Content:     "80\n443",
			Description: "Standard web ports",
		},
	)

	device, warnings, err := opnsense.ConvertDocument(doc)
	require.NoError(t, err)
	assert.Empty(t, warnings)
	require.Len(t, device.NamedObjects, 3)

	host, ok := device.NamedObjects["WEB_SERVERS"]
	require.True(t, ok)
	assert.Equal(t, common.NamedObjectTypeHost, host.Type)
	assert.Equal(t, []string{"10.20.30.40", "10.20.30.41"}, host.Members)
	assert.Equal(t, "Web server hosts", host.Description)

	network, ok := device.NamedObjects["INTERNAL_NET"]
	require.True(t, ok)
	assert.Equal(t, common.NamedObjectTypeNetwork, network.Type)
	assert.Equal(t, []string{"10.20.0.0/16"}, network.Members)

	port, ok := device.NamedObjects["WEB_PORTS"]
	require.True(t, ok)
	assert.Equal(t, common.NamedObjectTypePort, port.Type)
	assert.Equal(t, []string{"80", "443"}, port.Members)
}

func TestConverter_NamedObjects_NestedAliasReference(t *testing.T) {
	t.Parallel()

	// ALL_SERVERS references WEB_SERVERS by name plus a literal address.
	// Resolution (flattening the nested reference) is U1's responsibility;
	// this test only proves the raw member list is captured as-is.
	doc := withMVCAliases(schema.NewOpnSenseDocument(),
		schema.Alias{Name: "WEB_SERVERS", Type: "host", Content: "10.20.30.40"},
		schema.Alias{Name: "ALL_SERVERS", Type: "host", Content: "WEB_SERVERS\n10.20.30.50"},
	)

	device, warnings, err := opnsense.ConvertDocument(doc)
	require.NoError(t, err)
	assert.Empty(t, warnings)
	require.Len(t, device.NamedObjects, 2)

	all, ok := device.NamedObjects["ALL_SERVERS"]
	require.True(t, ok)
	assert.Equal(t, []string{"WEB_SERVERS", "10.20.30.50"}, all.Members)
}

func TestConverter_NamedObjects_LegacyTopLevelPath(t *testing.T) {
	t.Parallel()

	// MVC subtree absent (doc.OPNsense.Firewall stays nil); only the legacy
	// top-level <aliases> is populated.
	doc := schema.NewOpnSenseDocument()
	doc.Aliases.Alias = []schema.Alias{
		{Name: "LEGACY_HOSTS", Type: "host", Address: "10.5.5.1 10.5.5.2"},
	}

	device, warnings, err := opnsense.ConvertDocument(doc)
	require.NoError(t, err)
	assert.Empty(t, warnings)
	require.Len(t, device.NamedObjects, 1)

	obj, ok := device.NamedObjects["LEGACY_HOSTS"]
	require.True(t, ok)
	assert.Equal(t, common.NamedObjectTypeHost, obj.Type)
	assert.Equal(t, []string{"10.5.5.1", "10.5.5.2"}, obj.Members)
}

func TestConverter_NamedObjects_UnknownType_Warns(t *testing.T) {
	t.Parallel()

	doc := withMVCAliases(schema.NewOpnSenseDocument(),
		schema.Alias{Name: "WEIRD_ALIAS", Type: "urltable", Content: "http://example.com/list.txt"},
	)

	device, warnings, err := opnsense.ConvertDocument(doc)
	require.NoError(t, err)
	require.Len(t, warnings, 1)
	assert.Equal(t, "NamedObjects[WEIRD_ALIAS].Type", warnings[0].Field)
	assert.Equal(t, "urltable", warnings[0].Value)
	assert.Equal(t, common.SeverityLow, warnings[0].Severity)

	// The alias is still captured (fail-open), just with an unvalidated Type.
	obj, ok := device.NamedObjects["WEIRD_ALIAS"]
	require.True(t, ok)
	assert.Equal(t, common.NamedObjectType("urltable"), obj.Type)
}

func TestConverter_NamedObjects_EmptyName_Warns(t *testing.T) {
	t.Parallel()

	doc := withMVCAliases(schema.NewOpnSenseDocument(),
		schema.Alias{Name: "", Type: "host", Content: "10.0.0.1", UUID: "abc-123"},
	)

	device, warnings, err := opnsense.ConvertDocument(doc)
	require.NoError(t, err)
	require.Len(t, warnings, 1)
	assert.Equal(t, "NamedObjects[0]", warnings[0].Field)
	assert.Equal(t, "abc-123", warnings[0].Value)
	assert.Nil(t, device.NamedObjects)
}

func TestConverter_FirewallRules_ObjectRef_AddressAndPort(t *testing.T) {
	t.Parallel()

	doc := withMVCAliases(schema.NewOpnSenseDocument(),
		schema.Alias{Name: "WEB_SERVERS", Type: "host", Content: "10.20.30.40"},
		schema.Alias{Name: "WEB_PORTS", Type: "port", Content: "80\n443"},
	)
	doc.Filter.Rule = []schema.Rule{
		{
			Type:      "pass",
			Interface: schema.InterfaceList{"wan"},
			Source: schema.Source{
				Address: "WEB_SERVERS",
			},
			Destination: schema.Destination{
				Network: "lan",
				Port:    "WEB_PORTS",
			},
		},
	}

	device, warnings, err := opnsense.ConvertDocument(doc)
	require.NoError(t, err)
	assert.Empty(t, warnings)
	require.Len(t, device.FirewallRules, 1)

	rule := device.FirewallRules[0]

	// Inline resolved values are preserved regardless of the alias ref.
	assert.Equal(t, "WEB_SERVERS", rule.Source.Address)
	require.NotNil(t, rule.Source.AddressRef)
	assert.Equal(t, "WEB_SERVERS", rule.Source.AddressRef.Name)
	assert.Nil(t, rule.Source.PortRef)

	assert.Equal(t, "lan", rule.Destination.Address)
	assert.Nil(t, rule.Destination.AddressRef)
	assert.Equal(t, "WEB_PORTS", rule.Destination.Port)
	require.NotNil(t, rule.Destination.PortRef)
	assert.Equal(t, "WEB_PORTS", rule.Destination.PortRef.Name)
}

func TestConverter_FirewallRules_ObjectRef_LiteralValuesStayNil(t *testing.T) {
	t.Parallel()

	doc := withMVCAliases(schema.NewOpnSenseDocument(),
		schema.Alias{Name: "WEB_SERVERS", Type: "host", Content: "10.20.30.40"},
	)
	doc.Filter.Rule = []schema.Rule{
		{
			Type:      "pass",
			Interface: schema.InterfaceList{"lan"},
			Source: schema.Source{
				Network: "lan",
			},
			Destination: schema.Destination{
				Address: "192.0.2.1",
				Port:    "443",
			},
		},
	}

	device, warnings, err := opnsense.ConvertDocument(doc)
	require.NoError(t, err)
	assert.Empty(t, warnings)
	require.Len(t, device.FirewallRules, 1)

	rule := device.FirewallRules[0]
	assert.Nil(t, rule.Source.AddressRef)
	assert.Nil(t, rule.Source.PortRef)
	assert.Nil(t, rule.Destination.AddressRef)
	assert.Nil(t, rule.Destination.PortRef)
}
