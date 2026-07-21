package pfsense_test

import (
	"testing"

	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
	"github.com/EvilBit-Labs/opnDossier/pkg/parser/pfsense"
	opnsense "github.com/EvilBit-Labs/opnDossier/pkg/schema/opnsense"
	schema "github.com/EvilBit-Labs/opnDossier/pkg/schema/pfsense"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConverter_NamedObjects_NoAliases(t *testing.T) {
	t.Parallel()

	doc := schema.NewDocument()

	device, warnings, err := pfsense.ConvertDocument(doc)
	require.NoError(t, err)
	assert.Empty(t, nonGapWarnings(warnings))
	assert.Nil(t, device.NamedObjects)
}

func TestConverter_NamedObjects_HostNetworkPort(t *testing.T) {
	t.Parallel()

	doc := schema.NewDocument()
	doc.Aliases.Alias = []schema.Alias{
		{
			Name:    "WEB_SERVERS",
			Type:    "host",
			Address: "10.20.30.40 10.20.30.41",
			Descr:   "Web server hosts",
		},
		{
			Name:    "INTERNAL_NET",
			Type:    "network",
			Address: "10.20.0.0/16",
			Descr:   "Internal network",
		},
		{
			Name:    "WEB_PORTS",
			Type:    "port",
			Address: "80 443",
			Descr:   "Standard web ports",
		},
	}

	device, warnings, err := pfsense.ConvertDocument(doc)
	require.NoError(t, err)
	assert.Empty(t, nonGapWarnings(warnings))
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
	doc := schema.NewDocument()
	doc.Aliases.Alias = []schema.Alias{
		{Name: "WEB_SERVERS", Type: "host", Address: "10.20.30.40"},
		{Name: "ALL_SERVERS", Type: "host", Address: "WEB_SERVERS 10.20.30.50"},
	}

	device, warnings, err := pfsense.ConvertDocument(doc)
	require.NoError(t, err)
	assert.Empty(t, nonGapWarnings(warnings))
	require.Len(t, device.NamedObjects, 2)

	all, ok := device.NamedObjects["ALL_SERVERS"]
	require.True(t, ok)
	assert.Equal(t, []string{"WEB_SERVERS", "10.20.30.50"}, all.Members)
}

func TestConverter_NamedObjects_EmptyAliases_YieldsNoRegistry(t *testing.T) {
	t.Parallel()

	// Mirrors the shipped config-pfSense.xml fixture's empty <aliases></aliases>.
	doc := schema.NewDocument()

	device, warnings, err := pfsense.ConvertDocument(doc)
	require.NoError(t, err)
	assert.Empty(t, nonGapWarnings(warnings))
	assert.Nil(t, device.NamedObjects)
}

func TestConverter_NamedObjects_UnknownType_Warns(t *testing.T) {
	t.Parallel()

	doc := schema.NewDocument()
	doc.Aliases.Alias = []schema.Alias{
		{Name: "WEIRD_ALIAS", Type: "urltable", Address: "http://example.com/list.txt"},
	}

	device, warnings, err := pfsense.ConvertDocument(doc)
	require.NoError(t, err)
	warnings = nonGapWarnings(warnings)
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

	doc := schema.NewDocument()
	doc.Aliases.Alias = []schema.Alias{
		{Name: "", Type: "host", Address: "10.0.0.1"},
	}

	device, warnings, err := pfsense.ConvertDocument(doc)
	require.NoError(t, err)
	warnings = nonGapWarnings(warnings)
	require.Len(t, warnings, 1)
	assert.Equal(t, "NamedObjects[0]", warnings[0].Field)
	assert.Nil(t, device.NamedObjects)
}

func TestConverter_FirewallRules_ObjectRef_AddressAndPort(t *testing.T) {
	t.Parallel()

	doc := schema.NewDocument()
	doc.Aliases.Alias = []schema.Alias{
		{Name: "WEB_SERVERS", Type: "host", Address: "10.20.30.40"},
		{Name: "WEB_PORTS", Type: "port", Address: "80 443"},
	}
	doc.Filter.Rule = []schema.FilterRule{
		{
			Type:      "pass",
			Interface: opnsense.InterfaceList{"wan"},
			Source: opnsense.Source{
				Address: "WEB_SERVERS",
			},
			Destination: opnsense.Destination{
				Network: "lan",
				Port:    "WEB_PORTS",
			},
		},
	}

	device, warnings, err := pfsense.ConvertDocument(doc)
	require.NoError(t, err)
	assert.Empty(t, nonGapWarnings(warnings))
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

	doc := schema.NewDocument()
	doc.Aliases.Alias = []schema.Alias{
		{Name: "WEB_SERVERS", Type: "host", Address: "10.20.30.40"},
	}
	doc.Filter.Rule = []schema.FilterRule{
		{
			Type:      "pass",
			Interface: opnsense.InterfaceList{"lan"},
			Source: opnsense.Source{
				Network: "lan",
			},
			Destination: opnsense.Destination{
				Address: "192.0.2.1",
				Port:    "443",
			},
		},
	}

	device, warnings, err := pfsense.ConvertDocument(doc)
	require.NoError(t, err)
	assert.Empty(t, nonGapWarnings(warnings))
	require.Len(t, device.FirewallRules, 1)

	rule := device.FirewallRules[0]
	assert.Nil(t, rule.Source.AddressRef)
	assert.Nil(t, rule.Source.PortRef)
	assert.Nil(t, rule.Destination.AddressRef)
	assert.Nil(t, rule.Destination.PortRef)
}

// TestConverter_FirewallRules_ObjectRef_MacroAndAnyNeverAliasRef proves that
// an interface/network macro (<network>lan</network>) or the <any/> wildcard
// is never mistaken for a named-object (alias) reference, even when an alias
// happens to share that exact name. Regression for the AddressRef derivation
// previously using EffectiveAddress() (which also surfaces Network/Any)
// instead of the address-field-only AliasAddress().
func TestConverter_FirewallRules_ObjectRef_MacroAndAnyNeverAliasRef(t *testing.T) {
	t.Parallel()

	// The registry deliberately contains aliases literally named "lan" and
	// "any" so a naive name-based lookup against EffectiveAddress() would
	// wrongly resolve the macro/wildcard endpoints below to these aliases.
	doc := schema.NewDocument()
	doc.Aliases.Alias = []schema.Alias{
		{Name: "lan", Type: "host", Address: "10.0.0.1"},
		{Name: "any", Type: "host", Address: "10.0.0.2"},
		{Name: "WEB_SERVERS", Type: "host", Address: "10.20.30.40"},
	}
	doc.Filter.Rule = []schema.FilterRule{
		{
			Type:      "pass",
			Interface: opnsense.InterfaceList{"wan"},
			Source: opnsense.Source{
				Network: "lan", // interface macro, must NOT resolve to alias "lan"
			},
			Destination: opnsense.Destination{
				Any: new(""), // any wildcard, must NOT resolve to alias "any"
			},
		},
		{
			Type:      "pass",
			Interface: opnsense.InterfaceList{"wan"},
			Source: opnsense.Source{
				Address: "WEB_SERVERS", // genuine alias reference must still resolve
			},
			Destination: opnsense.Destination{
				Address: "203.0.113.5",
			},
		},
	}

	device, warnings, err := pfsense.ConvertDocument(doc)
	require.NoError(t, err)
	assert.Empty(t, nonGapWarnings(warnings))
	require.Len(t, device.FirewallRules, 2)

	macroRule := device.FirewallRules[0]
	assert.Equal(t, "lan", macroRule.Source.Address, "EffectiveAddress must still surface the macro")
	assert.Nil(t, macroRule.Source.AddressRef, "interface macro must not be treated as an alias ref")
	assert.Equal(t, "any", macroRule.Destination.Address, "EffectiveAddress must still surface the wildcard")
	assert.Nil(t, macroRule.Destination.AddressRef, "any wildcard must not be treated as an alias ref")

	aliasRule := device.FirewallRules[1]
	require.NotNil(t, aliasRule.Source.AddressRef, "a genuine <address> alias reference must still resolve")
	assert.Equal(t, "WEB_SERVERS", aliasRule.Source.AddressRef.Name)
	assert.Nil(t, aliasRule.Destination.AddressRef, "a literal IP address must not resolve as an alias ref")
}
