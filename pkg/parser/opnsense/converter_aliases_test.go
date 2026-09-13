package opnsense_test

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/cfgparser"
	"github.com/EvilBit-Labs/opnDossier/internal/sanitizer"
	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
	"github.com/EvilBit-Labs/opnDossier/pkg/parser"
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
	doc := withMVCAliases(schema.NewOpnSenseDocument(),
		schema.Alias{Name: "lan", Type: "host", Content: "10.0.0.1"},
		schema.Alias{Name: "any", Type: "host", Content: "10.0.0.2"},
		schema.Alias{Name: "WEB_SERVERS", Type: "host", Content: "10.20.30.40"},
	)
	doc.Filter.Rule = []schema.Rule{
		{
			Type:      "pass",
			Interface: schema.InterfaceList{"wan"},
			Source: schema.Source{
				Network: "lan", // interface macro, must NOT resolve to alias "lan"
			},
			Destination: schema.Destination{
				Any: new(""), // any wildcard, must NOT resolve to alias "any"
			},
		},
		{
			Type:      "pass",
			Interface: schema.InterfaceList{"wan"},
			Source: schema.Source{
				Address: "WEB_SERVERS", // genuine alias reference must still resolve
			},
			Destination: schema.Destination{
				Address: "203.0.113.5",
			},
		},
		{
			Type:      "pass",
			Interface: schema.InterfaceList{"wan"},
			Source: schema.Source{
				// Both <address> and <any/> present: EffectiveAddress picks
				// Address over Any, so AddressRef must resolve to the alias
				// too — AliasAddress follows the same Network > Address order.
				Address: "WEB_SERVERS",
				Any:     new(""),
			},
			Destination: schema.Destination{
				Address: "203.0.113.6",
			},
		},
	}

	device, warnings, err := opnsense.ConvertDocument(doc)
	require.NoError(t, err)
	assert.Empty(t, warnings)
	require.Len(t, device.FirewallRules, 3)

	macroRule := device.FirewallRules[0]
	assert.Equal(t, "lan", macroRule.Source.Address, "EffectiveAddress must still surface the macro")
	assert.Nil(t, macroRule.Source.AddressRef, "interface macro must not be treated as an alias ref")
	assert.Equal(t, "any", macroRule.Destination.Address, "EffectiveAddress must still surface the wildcard")
	assert.Nil(t, macroRule.Destination.AddressRef, "any wildcard must not be treated as an alias ref")

	aliasRule := device.FirewallRules[1]
	require.NotNil(t, aliasRule.Source.AddressRef, "a genuine <address> alias reference must still resolve")
	assert.Equal(t, "WEB_SERVERS", aliasRule.Source.AddressRef.Name)
	assert.Nil(t, aliasRule.Destination.AddressRef, "a literal IP address must not resolve as an alias ref")

	addressAndAnyRule := device.FirewallRules[2]
	assert.Equal(t, "WEB_SERVERS", addressAndAnyRule.Source.Address,
		"EffectiveAddress picks Address over Any")
	require.NotNil(t, addressAndAnyRule.Source.AddressRef,
		"an <address> alias must resolve even when <any/> is also present")
	assert.Equal(t, "WEB_SERVERS", addressAndAnyRule.Source.AddressRef.Name)
}

// TestConverter_NamedObjects_MergesLegacyAndMVCWithoutDuplication proves that
// when a config populates BOTH the MVC-model alias path and the legacy
// top-level <aliases> path, convertNamedObjects merges them into one
// registry rather than duplicating entries -- and that an overlapping name
// resolves to the legacy entry, per the documented (if incidental)
// tie-breaking in convertNamedObjects.
func TestConverter_NamedObjects_MergesLegacyAndMVCWithoutDuplication(t *testing.T) {
	t.Parallel()

	doc := withMVCAliases(schema.NewOpnSenseDocument(),
		schema.Alias{Name: "MVC_ONLY", Type: "host", Content: "10.0.0.1"},
		schema.Alias{Name: "SHARED_ALIAS", Type: "host", Content: "10.0.0.2"},
	)
	doc.Aliases.Alias = []schema.Alias{
		{Name: "LEGACY_ONLY", Type: "host", Address: "10.0.0.3"},
		{Name: "SHARED_ALIAS", Type: "host", Content: "10.0.0.4"},
	}

	device, warnings, err := opnsense.ConvertDocument(doc)
	require.NoError(t, err)
	assert.Empty(t, warnings)

	// Three unique names, not four raw entries: SHARED_ALIAS must not
	// duplicate.
	require.Len(t, device.NamedObjects, 3)

	mvcOnly, ok := device.NamedObjects["MVC_ONLY"]
	require.True(t, ok)
	assert.Equal(t, []string{"10.0.0.1"}, mvcOnly.Members)

	legacyOnly, ok := device.NamedObjects["LEGACY_ONLY"]
	require.True(t, ok)
	assert.Equal(t, []string{"10.0.0.3"}, legacyOnly.Members)

	shared, ok := device.NamedObjects["SHARED_ALIAS"]
	require.True(t, ok)
	assert.Equal(t, []string{"10.0.0.4"}, shared.Members, "legacy entry wins on a name collision")
}

// TestParser_OPNsenseLegacyAliasesFixture parses
// testdata/opnsense-legacy-aliases.xml end-to-end through the full XML
// dispatch (internal/cfgparser.XMLParser, not direct struct construction)
// and proves the legacy top-level <aliases> block populates
// common.NamedObjects. Before U3, handleStartElement had no "aliases" case,
// so this fixture converted to namedObjects: null.
func TestParser_OPNsenseLegacyAliasesFixture(t *testing.T) {
	t.Parallel()

	device := parseLegacyAliasesFixture(t)

	require.Len(t, device.NamedObjects, 2)

	legacyHosts, ok := device.NamedObjects["LEGACY_HOSTS"]
	require.True(t, ok)
	assert.Equal(t, common.NamedObjectTypeHost, legacyHosts.Type)
	assert.Equal(t, []string{"10.5.5.1", "10.5.5.2"}, legacyHosts.Members)

	legacySecret, ok := device.NamedObjects["LEGACY_SECRET"]
	require.True(t, ok)
	assert.Equal(t, []string{"10.5.5.3"}, legacySecret.Members)
}

// legacySecretMarker is the secret-shaped value embedded in
// testdata/opnsense-legacy-aliases.xml's LEGACY_SECRET alias description: a
// base64-encoded opaque blob (no field-name pattern like "descr" matches any
// redaction rule by name) that the sanitizer's certificate/public-key
// value-detector rules catch regardless of field name in aggressive mode.
// It deliberately contains no whitespace, so the sanitizer's per-token value
// detection -- which splits a CharData leaf on whitespace before running any
// ValueDetector, see internal/sanitizer.replaceTokens -- sees it as a single
// token.
// secret-*shaped* so the redaction assertion below has something to detect.
//
//nolint:gosec // G101: not a credential -- a base64 test marker whose only job is to be
const legacySecretMarker = "c3VwZXItc2VjcmV0LWxlZ2FjeS1hbGlhcy1hcGkta2V5LTAxMjM0NTY3ODk="

// TestParser_OPNsenseLegacyAliasesFixture_SecretRedacted proves the legacy
// top-level <aliases> path -- unreachable before U3 -- is covered by the
// sanitizer's redaction rules like any other config path: the secret-shaped
// alias description in testdata/opnsense-legacy-aliases.xml never survives
// sanitize-then-convert, whether inspected as JSON output or as the parsed
// NamedObjects.Description value directly.
func TestParser_OPNsenseLegacyAliasesFixture_SecretRedacted(t *testing.T) {
	t.Parallel()

	raw, err := os.ReadFile(legacyAliasesFixturePath())
	require.NoError(t, err)
	require.Contains(t, string(raw), legacySecretMarker, "fixture must still carry the secret this test redacts")

	var sanitized bytes.Buffer
	san := sanitizer.NewSanitizer(sanitizer.ModeAggressive)
	require.NoError(t, san.SanitizeXML(bytes.NewReader(raw), &sanitized))
	assert.NotContains(t, sanitized.String(), legacySecretMarker, "sanitized XML must not carry the secret in clear")

	factory := parser.NewFactory(cfgparser.NewXMLParser())
	device, _, err := factory.CreateDevice(context.Background(), &sanitized, common.DeviceTypeUnknown, false)
	require.NoError(t, err)
	require.NotNil(t, device)

	legacySecret, ok := device.NamedObjects["LEGACY_SECRET"]
	require.True(t, ok)
	assert.NotContains(t, legacySecret.Description, legacySecretMarker)

	jsonOut, err := json.Marshal(device)
	require.NoError(t, err)
	assert.NotContains(t, string(jsonOut), legacySecretMarker, "secret must not survive into JSON export")
}

// legacyAliasesFixturePath returns the path to
// testdata/opnsense-legacy-aliases.xml relative to this test's working
// directory (the package directory, per Go test convention).
func legacyAliasesFixturePath() string {
	return filepath.Join("..", "..", "..", "testdata", "opnsense-legacy-aliases.xml")
}

// parseLegacyAliasesFixture opens and parses
// testdata/opnsense-legacy-aliases.xml through the full parser pipeline,
// failing the test on any error.
func parseLegacyAliasesFixture(t *testing.T) *common.CommonDevice {
	t.Helper()

	f, err := os.Open(legacyAliasesFixturePath())
	require.NoError(t, err)
	defer f.Close()

	factory := parser.NewFactory(cfgparser.NewXMLParser())
	device, warnings, err := factory.CreateDevice(context.Background(), f, common.DeviceTypeUnknown, false)
	require.NoError(t, err)
	assert.Empty(t, warnings)
	require.NotNil(t, device)

	return device
}
