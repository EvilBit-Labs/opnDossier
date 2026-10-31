package opnsense_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/analysis"
	"github.com/EvilBit-Labs/opnDossier/internal/cfgparser"
	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
	"github.com/EvilBit-Labs/opnDossier/pkg/parser"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// parseAliasModelXML runs doc through the real parser. These tests decode XML
// rather than build schema.Alias values, because the bugs they guard against are
// in which element a field is bound to.
func parseAliasModelXML(t *testing.T, doc string) *common.CommonDevice {
	t.Helper()

	factory := parser.NewFactory(cfgparser.NewXMLParser())
	device, _, err := factory.CreateDevice(
		context.Background(), strings.NewReader(doc), common.DeviceTypeUnknown, false,
	)
	require.NoError(t, err)
	require.NotNil(t, device)

	return device
}

// aliasModelDoc wraps alias elements in the MVC-model path. An empty first alias
// sits ahead of them, so a reader of the first entry alone does not pass.
func aliasModelDoc(aliases string) string {
	return `<?xml version="1.0"?><opnsense><OPNsense><Firewall><Alias version="1.0.1"><aliases>` +
		`<alias uuid="c1c1c1c1-0000-4000-8000-0000000000ff"><enabled>1</enabled><name>FIRST</name>` +
		`<type>host</type><content>10.0.0.1</content><description>first</description></alias>` +
		aliases + `</aliases></Alias></Firewall></OPNsense></opnsense>`
}

// legacyAliasDoc wraps alias elements in the legacy top-level path.
func legacyAliasDoc(aliases string) string {
	return `<?xml version="1.0"?><opnsense><aliases>` +
		`<alias><name>FIRST</name><type>host</type><address>10.0.0.1</address><descr>first</descr></alias>` +
		aliases + `</aliases></opnsense>`
}

// TestParser_AliasModelFixture reads each field the model adds to an alias from
// the fixture written in the shape the model uses.
func TestParser_AliasModelFixture(t *testing.T) {
	t.Parallel()

	doc, err := os.ReadFile(filepath.Join("..", "..", "..", "testdata", "opnsense-alias-model.xml"))
	require.NoError(t, err)

	device := parseAliasModelXML(t, string(doc))
	objects := device.NamedObjects
	require.Len(t, objects, 9)

	assert.Equal(t, common.NamedObject{
		Name:        "BLOCKLIST",
		Type:        common.NamedObjectTypeNetwork,
		Members:     []string{"198.51.100.0/24", "203.0.113.0/24"},
		Description: "Networks dropped at the WAN",
	}, objects["BLOCKLIST"])

	assert.True(t, objects["PARTNERS"].Disabled)
	assert.Equal(t, "IPv4", objects["GEO_BLOCK"].Proto)
	assert.Equal(t, ".allowed[].address", objects["FEED"].PathExpression)
	assert.Equal(t, "lan", objects["TRACKED"].Interface)
	assert.Equal(t, "2592000", objects["EXT_BLOCK"].Expire)
}

// TestConverter_AliasDisabled_ReadsAsTheFirewallDoes covers each shape of
// <enabled>. An element that is present and 0 or empty reads as disabled. Absent
// reads as enabled, so a config that gains the element reports nothing. Anything
// else is enabled, as filter_tables.conf and !empty() read it, including no, which
// shared.IsValueTrue would read the other way.
func TestConverter_AliasDisabled_ReadsAsTheFirewallDoes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		element string
		want    bool
	}{
		{name: "absent", element: "", want: false},
		{name: "one", element: "<enabled>1</enabled>", want: false},
		{name: "zero", element: "<enabled>0</enabled>", want: true},
		{name: "self-closing", element: "<enabled/>", want: true},
		{name: "empty", element: "<enabled></enabled>", want: true},
		{name: "not a word the firewall knows", element: "<enabled>no</enabled>", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			device := parseAliasModelXML(t, aliasModelDoc(
				`<alias uuid="c1c1c1c1-0000-4000-8000-000000000001">`+tt.element+
					`<name>TARGET</name><type>host</type><content>10.0.0.2</content></alias>`))

			require.Contains(t, device.NamedObjects, "TARGET")
			assert.Equal(t, tt.want, device.NamedObjects["TARGET"].Disabled)
			assert.False(t, device.NamedObjects["FIRST"].Disabled)
		})
	}
}

// TestConverter_AliasDisabled_NeverSetWithoutTheElement covers the path that has
// no such setting.
func TestConverter_AliasDisabled_NeverSetWithoutTheElement(t *testing.T) {
	t.Parallel()

	device := parseAliasModelXML(t, legacyAliasDoc(
		`<alias><name>TARGET</name><type>host</type><address>10.0.0.2</address></alias>`))

	require.Contains(t, device.NamedObjects, "TARGET")
	assert.False(t, device.NamedObjects["TARGET"].Disabled)
}

// TestConverter_AliasDescription_ReadsEitherElement covers both element names on
// both paths. The model's <description> wins, since it is the one the firewall
// reads; the fixtures once held <descr> in the model path, which OPNsense does
// not write there and which hid that <description> was never read.
func TestConverter_AliasDescription_ReadsEitherElement(t *testing.T) {
	t.Parallel()

	const body = `<name>TARGET</name><type>host</type><address>10.0.0.2</address>`

	tests := []struct {
		name string
		doc  func(string) string
		xml  string
		want string
	}{
		{"model path, description", aliasModelDoc, `<description>model</description>`, "model"},
		{"model path, descr", aliasModelDoc, `<descr>legacy</descr>`, "legacy"},
		{"model path, both", aliasModelDoc, `<descr>legacy</descr><description>model</description>`, "model"},
		{"model path, empty description", aliasModelDoc, `<description/><descr>legacy</descr>`, "legacy"},
		{"legacy path, descr", legacyAliasDoc, `<descr>legacy</descr>`, "legacy"},
		{"legacy path, neither", legacyAliasDoc, ``, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			device := parseAliasModelXML(t, tt.doc(`<alias>`+body+tt.xml+`</alias>`))

			require.Contains(t, device.NamedObjects, "TARGET")
			assert.Equal(t, tt.want, device.NamedObjects["TARGET"].Description)
		})
	}
}

// TestConverter_AliasExpire covers each shape of <expire> on the model path. An
// absent element and an empty one are the same setting, so a config that gains
// the empty element reports nothing.
func TestConverter_AliasExpire(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		element string
		want    string
	}{
		{name: "absent", element: "", want: ""},
		{name: "empty", element: "<expire/>", want: ""},
		{name: "set", element: "<expire>3600</expire>", want: "3600"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			device := parseAliasModelXML(t, aliasModelDoc(
				`<alias uuid="c1c1c1c1-0000-4000-8000-000000000001"><enabled>1</enabled>`+
					`<name>TARGET</name><type>external</type><content/>`+tt.element+`</alias>`))

			require.Contains(t, device.NamedObjects, "TARGET")
			assert.Equal(t, tt.want, device.NamedObjects["TARGET"].Expire)
			assert.Empty(t, device.NamedObjects["FIRST"].Expire)
		})
	}
}

// TestConverter_AliasMembers_KeepEveryLegacySource pins that no legacy element
// hides another. OPNsense up to 17.7 loads a url alias from <address> and 18.1 and
// later from <aliasurl>, so a change to either can change what a rule matches.
// Only <content>, which the model writes alone, stands for the whole list.
func TestConverter_AliasMembers_KeepEveryLegacySource(t *testing.T) {
	t.Parallel()

	const (
		content = "<content>10.0.0.5\n10.0.0.6</content>"
		url     = "<url>https://lists.example.org/table.txt</url>"
		alias1  = "<aliasurl>https://lists.example.org/first.txt</aliasurl>"
		alias2  = "<aliasurl>https://lists.example.org/second.txt</aliasurl>"
		address = "<address>10.0.0.7 10.0.0.8</address>"

		tableURL  = "https://lists.example.org/table.txt"
		firstURL  = "https://lists.example.org/first.txt"
		secondURL = "https://lists.example.org/second.txt"
		addressA  = "10.0.0.7"
		addressB  = "10.0.0.8"
	)

	tests := []struct {
		name string
		xml  string
		want []string
	}{
		{"content alone stands for the list", content + url + alias1 + address, []string{"10.0.0.5", "10.0.0.6"}},
		{"url alone", url, []string{tableURL}},
		{"every aliasurl", alias1 + alias2, []string{firstURL, secondURL}},
		{"address alone", address, []string{addressA, addressB}},
		{"url, aliasurl and address", url + alias1 + address, []string{tableURL, firstURL, addressA, addressB}},
		{"aliasurl and address", alias1 + alias2 + address, []string{firstURL, secondURL, addressA, addressB}},
		{"url and address", url + address, []string{tableURL, addressA, addressB}},
		{"an empty aliasurl among them", "<aliasurl/>" + alias2, []string{secondURL}},
		{"an empty aliasurl beside address", "<aliasurl/>" + address, []string{addressA, addressB}},
		{"an empty url beside aliasurl", "<url/>" + alias1, []string{firstURL}},
		{"url with whitespace around it", "<url>\n  " + tableURL + "  \n</url>", []string{tableURL}},
		{
			"url with a line break inside it",
			"<url>" + tableURL + "\n" + firstURL + "</url>",
			[]string{tableURL, firstURL},
		},
		{"aliasurl with whitespace around it", "<aliasurl>\n  " + firstURL + "  \n</aliasurl>", []string{firstURL}},
		{"address across lines", "<address>10.0.0.7\n10.0.0.8</address>", []string{addressA, addressB}},
		{"none", "", nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			device := parseAliasModelXML(t, legacyAliasDoc(
				`<alias><name>TARGET</name><type>url</type>`+tt.xml+`</alias>`))

			require.Contains(t, device.NamedObjects, "TARGET")
			assert.Equal(t, tt.want, device.NamedObjects["TARGET"].Members)
		})
	}
}

// TestConverter_OutboundNAT_AliasInNetwork decodes the shape firewall_nat_out_edit.php
// writes. A rule in that shape used to carry no reference, so the alias read as
// unused.
func TestConverter_OutboundNAT_AliasInNetwork(t *testing.T) {
	t.Parallel()

	doc := func(source, destination string) string {
		return `<?xml version="1.0"?><opnsense><OPNsense><Firewall><Alias version="1.0.1"><aliases>` +
			`<alias><name>SOURCES</name><type>network</type><content>10.0.0.0/24</content></alias>` +
			`<alias><name>TARGETS</name><type>network</type><content>10.0.1.0/24</content></alias>` +
			`<alias><name>lan</name><type>network</type><content>10.0.2.0/24</content></alias>` +
			`</aliases></Alias></Firewall></OPNsense><nat><outbound><mode>advanced</mode>` +
			`<rule><interface>wan</interface>` + source + destination + `</rule>` +
			`</outbound></nat></opnsense>`
	}

	tests := []struct {
		name        string
		source      string
		destination string
		wantSource  *common.ObjectRef
		wantDest    *common.ObjectRef
	}{
		{
			name:        "both in network, as the GUI writes them",
			source:      `<source><network>SOURCES</network></source>`,
			destination: `<destination><network>TARGETS</network></destination>`,
			wantSource:  &common.ObjectRef{Name: "SOURCES"},
			wantDest:    &common.ObjectRef{Name: "TARGETS"},
		},
		{
			name:        "both in address",
			source:      `<source><address>SOURCES</address></source>`,
			destination: `<destination><address>TARGETS</address></destination>`,
			wantSource:  &common.ObjectRef{Name: "SOURCES"},
			wantDest:    &common.ObjectRef{Name: "TARGETS"},
		},
		{
			name:        "literals carry no reference",
			source:      `<source><network>10.9.0.0/24</network></source>`,
			destination: `<destination><network>10.9.1.0/24</network></destination>`,
		},
		{
			name:        "any carries no reference",
			source:      `<source><any>1</any></source>`,
			destination: `<destination><any>1</any></destination>`,
		},
		{
			// The firewall lets an alias replace an interface of the same name.
			name:        "a name that is both a macro and an alias is the alias",
			source:      `<source><network>lan</network></source>`,
			destination: `<destination><any>1</any></destination>`,
			wantSource:  &common.ObjectRef{Name: "lan"},
		},
		{
			name:        "a macro no alias shares carries no reference",
			source:      `<source><network>wanip</network></source>`,
			destination: `<destination><any>1</any></destination>`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			device := parseAliasModelXML(t, doc(tt.source, tt.destination))

			require.Len(t, device.NAT.OutboundRules, 1)
			assert.Equal(t, tt.wantSource, device.NAT.OutboundRules[0].Source.AddressRef)
			assert.Equal(t, tt.wantDest, device.NAT.OutboundRules[0].Destination.AddressRef)
		})
	}
}

// TestParser_AliasModelFixture_OutboundAliasesAreInUse pins what the reference is
// for: the two aliases only the fixture's outbound NAT rule names are not listed
// as unused, and the one nothing names still is.
func TestParser_AliasModelFixture_OutboundAliasesAreInUse(t *testing.T) {
	t.Parallel()

	doc, err := os.ReadFile(filepath.Join("..", "..", "..", "testdata", "opnsense-alias-model.xml"))
	require.NoError(t, err)

	findings := analysis.DetectUnusedObjects(parseAliasModelXML(t, string(doc)))

	require.Len(t, findings, 1, "%+v", findings)
	assert.Equal(t, "SPARE", findings[0].Name)
}
