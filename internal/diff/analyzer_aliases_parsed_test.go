package diff

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/cfgparser"
	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
	"github.com/EvilBit-Labs/opnDossier/pkg/parser"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The tests in this file run alias changes from XML through the real parsers
// and the engine, on configs in the shape each vendor writes. A device built by
// hand holds whatever the test sets, which is how an alias element that was never
// bound, and a reference no parser produced, once passed this package's tests.

// aliasModelFixture is the shipped config written in the shape of OPNsense's alias
// model.
const aliasModelFixture = "opnsense-alias-model.xml"

// readAliasDoc returns a shipped config as text, to be edited before it is parsed.
func readAliasDoc(t *testing.T, elem ...string) string {
	t.Helper()

	data, err := os.ReadFile(filepath.Join(append([]string{"..", "..", "testdata"}, elem...)...))
	require.NoError(t, err)

	return string(data)
}

// parseAliasDoc runs doc through the parser the engine gets in production.
func parseAliasDoc(t *testing.T, doc string) *common.CommonDevice {
	t.Helper()

	device, _, err := parser.NewFactory(cfgparser.NewXMLParser()).
		CreateDevice(context.Background(), strings.NewReader(doc), common.DeviceTypeUnknown, false)
	require.NoError(t, err)

	return device
}

// diffAliasDocs diffs two configs given as text.
func diffAliasDocs(t *testing.T, oldDoc, newDoc string, opts Options) []Change {
	t.Helper()

	result, err := NewEngine(parseAliasDoc(t, oldDoc), parseAliasDoc(t, newDoc), opts, nil).
		Compare(context.Background())
	require.NoError(t, err)

	return result.Changes
}

// editAliasDoc replaces from with to inside the block of the named alias. It
// fails when from is not there, so an edit that stops matching the fixture cannot
// turn a test into a comparison of a config with itself.
func editAliasDoc(t *testing.T, doc, name, from, to string) string {
	t.Helper()

	nameAt := strings.Index(doc, "<name>"+name+"</name>")
	require.GreaterOrEqual(t, nameAt, 0, "no alias named %s", name)

	start := strings.LastIndex(doc[:nameAt], "<alias")
	require.GreaterOrEqual(t, start, 0)

	length := strings.Index(doc[start:], "</alias>")
	require.GreaterOrEqual(t, length, 0)

	block := doc[start : start+length]
	require.Contains(t, block, from)

	return doc[:start] + strings.Replace(block, from, to, 1) + doc[start+length:]
}

// aliasModelFieldCase is one row of TestCompare_AliasModelFields.
type aliasModelFieldCase struct {
	name       string
	alias      string
	from, to   string
	wantPath   string
	wantOld    string
	wantNew    string
	wantImpact string
}

// aliasModelFieldCases change one element of an alias at a time.
func aliasModelFieldCases() []aliasModelFieldCase {
	return []aliasModelFieldCase{
		{
			name:  "disabling an alias a block rule names lets its members through",
			alias: "BLOCKLIST", from: "<enabled>1</enabled>", to: "<enabled>0</enabled>",
			wantPath: "aliases.alias[BLOCKLIST].enabled", wantOld: "true", wantNew: "false", wantImpact: "medium",
		},
		{
			name:  "enabling an alias a pass rule names opens its members",
			alias: "PARTNERS", from: "<enabled>0</enabled>", to: "<enabled>1</enabled>",
			wantPath: "aliases.alias[PARTNERS].enabled", wantOld: "false", wantNew: "true", wantImpact: "medium",
		},
		{
			name:  "an empty enabled element loads no members either",
			alias: "BLOCKLIST", from: "<enabled>1</enabled>", to: "<enabled/>",
			wantPath: "aliases.alias[BLOCKLIST].enabled", wantOld: "true", wantNew: "false", wantImpact: "medium",
		},
		{
			name:  "removing the enabled element from a disabled alias reads as enabling it",
			alias: "PARTNERS", from: "<enabled>0</enabled>", to: "",
			wantPath: "aliases.alias[PARTNERS].enabled", wantOld: "false", wantNew: "true", wantImpact: "medium",
		},
		{
			name:  "disabling an alias no rule names",
			alias: "SPARE", from: "<enabled>1</enabled>", to: "<enabled>0</enabled>",
			wantPath: "aliases.alias[SPARE].enabled", wantOld: "true", wantNew: "false", wantImpact: "low",
		},
		{
			name:  "address families widened",
			alias: "GEO_BLOCK", from: "<proto>IPv4</proto>", to: "<proto>IPv4,IPv6</proto>",
			wantPath: "aliases.alias[GEO_BLOCK].proto", wantOld: "IPv4", wantNew: "IPv4,IPv6", wantImpact: "medium",
		},
		{
			name:  "address families set on an alias that had none",
			alias: "BLOCKLIST", from: "<proto/>", to: "<proto>IPv6</proto>",
			wantPath: "aliases.alias[BLOCKLIST].proto", wantOld: "", wantNew: "IPv6", wantImpact: "medium",
		},
		{
			name:     "path expression changed",
			alias:    "FEED",
			from:     "<path_expression>.allowed[].address</path_expression>",
			to:       "<path_expression>.all[].address</path_expression>",
			wantPath: "aliases.alias[FEED].path_expression",
			wantOld:  ".allowed[].address", wantNew: ".all[].address", wantImpact: "medium",
		},
		{
			name:  "tracked interface changed",
			alias: "TRACKED", from: "<interface>lan</interface>", to: "<interface>opt1</interface>",
			wantPath: "aliases.alias[TRACKED].interface", wantOld: "lan", wantNew: "opt1", wantImpact: "medium",
		},
		{
			name:  "expire time lowered on an external alias a block rule names",
			alias: "EXT_BLOCK", from: "<expire>2592000</expire>", to: "<expire>60</expire>",
			wantPath: "aliases.alias[EXT_BLOCK].expire",
			wantOld:  "2592000", wantNew: "60", wantImpact: "medium",
		},
		{
			name:  "expire time removed reads as purging nothing",
			alias: "EXT_BLOCK", from: "<expire>2592000</expire>", to: "",
			wantPath: "aliases.alias[EXT_BLOCK].expire",
			wantOld:  "2592000", wantNew: "", wantImpact: "medium",
		},
		{
			name:  "expire time set on an alias that had none",
			alias: "BLOCKLIST", from: "<expire/>", to: "<expire>60</expire>",
			wantPath: "aliases.alias[BLOCKLIST].expire",
			wantOld:  "", wantNew: "60", wantImpact: "medium",
		},
		{
			// OPNsense leaves an external alias's table as it is, so this overstates
			// the change. Over-rating is the safe direction.
			name:  "disabling an external alias is reported as any other",
			alias: "EXT_BLOCK", from: "<enabled>1</enabled>", to: "<enabled>0</enabled>",
			wantPath: "aliases.alias[EXT_BLOCK].enabled", wantOld: "true", wantNew: "false", wantImpact: "medium",
		},
		{
			name:     "description changed is reported and not rated",
			alias:    "SPARE",
			from:     "<description>Referenced by nothing</description>",
			to:       "<description>Kept for the next migration</description>",
			wantPath: "aliases.alias[SPARE].description",
			wantOld:  "Referenced by nothing", wantNew: "Kept for the next migration",
		},
		{
			name:  "members of an alias an outbound NAT source names",
			alias: "NAT_NETS", from: "192.168.10.0/24", to: "0.0.0.0/0",
			wantPath: "aliases.alias[NAT_NETS].members",
			wantOld:  "192.168.10.0/24", wantNew: "0.0.0.0/0", wantImpact: "medium",
		},
		{
			name:  "members of an alias an outbound NAT destination names",
			alias: "NAT_PEERS", from: "203.0.113.128/25", to: "0.0.0.0/0",
			wantPath: "aliases.alias[NAT_PEERS].members",
			wantOld:  "203.0.113.128/25", wantNew: "0.0.0.0/0", wantImpact: "medium",
		},
	}
}

// TestCompare_AliasModelFields changes one element of an alias in the model's
// shape at a time. Each of these used to print "No changes detected".
func TestCompare_AliasModelFields(t *testing.T) {
	t.Parallel()

	for _, tt := range aliasModelFieldCases() {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			oldDoc := readAliasDoc(t, aliasModelFixture)
			newDoc := editAliasDoc(t, oldDoc, tt.alias, tt.from, tt.to)

			got := diffAliasDocs(t, oldDoc, newDoc, Options{})

			require.Len(t, got, 1, "%+v", got)
			assert.Equal(t, SectionAliases, got[0].Section)
			assert.Equal(t, tt.wantPath, got[0].Path)
			assert.Equal(t, tt.wantOld, got[0].OldValue)
			assert.Equal(t, tt.wantNew, got[0].NewValue)
			assert.Equal(t, tt.wantImpact, got[0].SecurityImpact)
		})
	}
}

// TestCompare_AliasModelFields_SameReading covers edits that do not change how the
// firewall reads the alias, which must report nothing. Every shipped alias
// outside the model fixture lacks <enabled>, so an absent element reading as a
// change would mark each of them changed on the first config that gains it.
func TestCompare_AliasModelFields_SameReading(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		from, to string
	}{
		{name: "enabled element removed", from: "<enabled>1</enabled>", to: ""},
		{name: "enabled by another word", from: "<enabled>1</enabled>", to: "<enabled>yes</enabled>"},
		{name: "empty proto removed", from: "<proto/>", to: ""},
		{name: "empty interface removed", from: "<interface/>", to: ""},
		{name: "empty path expression removed", from: "<path_expression/>", to: ""},
		{name: "empty expire removed", from: "<expire/>", to: ""},
		{name: "counters changed", from: "<counters>0</counters>", to: "<counters>1</counters>"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			oldDoc := readAliasDoc(t, aliasModelFixture)
			newDoc := editAliasDoc(t, oldDoc, "BLOCKLIST", tt.from, tt.to)

			assert.Empty(t, diffAliasDocs(t, oldDoc, newDoc, Options{}))
		})
	}
}

// TestCompare_LegacyAliasSources changes each source a legacy url alias can hold.
// A urltable alias's only content is in <url>, and a url alias keeps its sources
// in <aliasurl> and what it last fetched in <address>, so the first two edits
// used to report nothing.
func TestCompare_LegacyAliasSources(t *testing.T) {
	t.Parallel()

	const fixture = "opnsense-legacy-aliases.xml"

	tests := []struct {
		name     string
		alias    string
		from, to string
		wantPath string
		wantNew  string
	}{
		{
			name:     "urltable source repointed",
			alias:    "LEGACY_TABLE",
			from:     "https://lists.example.org/table.txt",
			to:       "https://lists.example.org/other.txt",
			wantPath: "aliases.alias[LEGACY_TABLE].members",
			wantNew:  "https://lists.example.org/other.txt",
		},
		{
			// The second of the repeated elements, which a reader of one entry misses.
			name:     "second url source repointed",
			alias:    "LEGACY_URLS",
			from:     "https://lists.example.org/second.txt",
			to:       "https://lists.example.org/other.txt",
			wantPath: "aliases.alias[LEGACY_URLS].members",
			wantNew:  "https://lists.example.org/first.txt, https://lists.example.org/other.txt, 10.5.5.4, 10.5.5.5",
		},
		{
			// OPNsense up to 17.7 loads this element rather than the URLs.
			name:     "address an old url alias fetched changed",
			alias:    "LEGACY_URLS",
			from:     "10.5.5.5",
			to:       "10.5.5.9",
			wantPath: "aliases.alias[LEGACY_URLS].members",
			wantNew:  "https://lists.example.org/first.txt, https://lists.example.org/second.txt, 10.5.5.4, 10.5.5.9",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			oldDoc := readAliasDoc(t, fixture)
			newDoc := editAliasDoc(t, oldDoc, tt.alias, tt.from, tt.to)

			got := diffAliasDocs(t, oldDoc, newDoc, Options{})

			require.Len(t, got, 1, "%+v", got)
			assert.Equal(t, tt.wantPath, got[0].Path)
			assert.Equal(t, tt.wantNew, got[0].NewValue)
		})
	}
}

// legacyURLAliasDoc holds one enabled pass rule that names alias T, a legacy alias
// with an unchanged <aliasurl> and the given <address>. On a url_ports alias the
// rule names it as a port, on a url alias as a source.
func legacyURLAliasDoc(aliasType, address string) string {
	endpoints := `<source><address>T</address></source><destination><any>1</any></destination>`
	if aliasType == "url_ports" {
		endpoints = `<source><any>1</any></source><destination><any>1</any><port>T</port></destination>`
	}

	return `<?xml version="1.0"?><opnsense><aliases>` +
		`<alias><name>FIRST</name><type>host</type><address>10.0.0.1</address></alias>` +
		`<alias><name>T</name><type>` + aliasType + `</type>` +
		`<aliasurl>https://lists.example.org/list.txt</aliasurl>` + address + `</alias>` +
		`</aliases><filter><rule><type>pass</type><interface>wan</interface>` +
		`<ipprotocol>inet</ipprotocol><protocol>tcp</protocol>` + endpoints + `</rule></filter></opnsense>`
}

// TestCompare_LegacyURLAliasAddress_RatedLikeAnyMember pins the reading OPNsense
// up to 17.7 has of a url alias, and the 17.1 tag of a url_ports alias: it loads
// <address>, and <aliasurl> is only where the addresses came from. Widening
// <address> with the URLs unchanged widens the pass rule on those releases.
func TestCompare_LegacyURLAliasAddress_RatedLikeAnyMember(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		aliasType string
		from, to  string
		wantOld   string
		wantNew   string
	}{
		{
			name: "url alias widened", aliasType: "url",
			from: "<address>10.0.0.2</address>", to: "<address>0.0.0.0/0</address>",
			wantOld: "https://lists.example.org/list.txt, 10.0.0.2",
			wantNew: "https://lists.example.org/list.txt, 0.0.0.0/0",
		},
		{
			name: "url alias loses its addresses", aliasType: "url",
			from: "<address>10.0.0.2</address>", to: "",
			wantOld: "https://lists.example.org/list.txt, 10.0.0.2",
			wantNew: "https://lists.example.org/list.txt",
		},
		{
			name: "url_ports alias widened", aliasType: "url_ports",
			from: "<address>22</address>", to: "<address>1:65535</address>",
			wantOld: "https://lists.example.org/list.txt, 22",
			wantNew: "https://lists.example.org/list.txt, 1:65535",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := diffAliasDocs(t,
				legacyURLAliasDoc(tt.aliasType, tt.from), legacyURLAliasDoc(tt.aliasType, tt.to), Options{})

			require.Len(t, got, 1, "%+v", got)
			assert.Equal(t, "aliases.alias[T].members", got[0].Path)
			assert.Equal(t, tt.wantOld, got[0].OldValue)
			assert.Equal(t, tt.wantNew, got[0].NewValue)
			assert.Equal(t, "medium", got[0].SecurityImpact)
		})
	}
}

// TestCompare_LegacyAliasMigratedToModel pins that moving a legacy url alias with
// no <address> into the model reports no members change, and that one holding
// <address> does, since what the firewall loads changes with the migration.
func TestCompare_LegacyAliasMigratedToModel(t *testing.T) {
	t.Parallel()

	legacy := func(address string) string {
		return `<?xml version="1.0"?><opnsense><aliases><alias><name>T</name><type>url</type>` +
			`<aliasurl>https://lists.example.org/first.txt</aliasurl>` +
			`<aliasurl>https://lists.example.org/second.txt</aliasurl>` + address +
			`</alias></aliases></opnsense>`
	}

	const model = `<?xml version="1.0"?><opnsense><OPNsense><Firewall><Alias version="1.0.1"><aliases>` +
		`<alias uuid="c1c1c1c1-0000-4000-8000-000000000001"><enabled>1</enabled><name>T</name><type>url</type>` +
		"<content>https://lists.example.org/first.txt\nhttps://lists.example.org/second.txt</content>" +
		`</alias></aliases></Alias></Firewall></OPNsense></opnsense>`

	assert.Empty(t, diffAliasDocs(t, legacy(""), model, Options{}))

	got := diffAliasDocs(t, legacy("<address>10.0.0.2</address>"), model, Options{})

	require.Len(t, got, 1, "%+v", got)
	assert.Equal(t, "aliases.alias[T].members", got[0].Path)
	assert.Equal(t,
		"https://lists.example.org/first.txt, https://lists.example.org/second.txt, 10.0.0.2", got[0].OldValue)
}

// TestCompare_AliasDescriptionsOfTheModelAreRead pins the fixtures that used to
// hold <descr> in the model path: each now has the element OPNsense writes there,
// and changing it is reported.
func TestCompare_AliasDescriptionsOfTheModelAreRead(t *testing.T) {
	t.Parallel()

	tests := []struct {
		fixture, alias, text string
	}{
		{"opnsense-aliases.xml", "WEB_SERVERS", "Web server hosts"},
		{"opnsense-mvc-rules.xml", "WEB_HOSTS", "Web servers"},
		{"opnsense-port-forwards.xml", "MAIL_HOST", "Mail server"},
		{"opnsense-legacy-port-forwards.xml", "MAIL_HOST", "Mail server"},
	}

	for _, tt := range tests {
		t.Run(tt.fixture, func(t *testing.T) {
			t.Parallel()

			oldDoc := readAliasDoc(t, tt.fixture)
			newDoc := editAliasDoc(t, oldDoc, tt.alias,
				"<description>"+tt.text+"</description>", "<description>changed</description>")

			got := diffAliasDocs(t, oldDoc, newDoc, Options{})

			require.Len(t, got, 1, "%+v", got)
			assert.Equal(t, aliasPath(tt.alias)+".description", got[0].Path)
			assert.Equal(t, tt.text, got[0].OldValue)
			assert.Equal(t, "changed", got[0].NewValue)
		})
	}
}

// pfSenseOutboundDoc adds an outbound NAT rule to the pfSense alias fixture, in
// the shape firewall_nat_out.inc writes: the alias is in <network>.
func pfSenseOutboundDoc(t *testing.T, mode string) string {
	t.Helper()

	doc := readAliasDoc(t, "pfsense", aliasFixture)
	require.Contains(t, doc, "</filter>")

	return strings.Replace(doc, "</filter>", "</filter><nat><outbound>"+mode+
		"<rule><interface>wan</interface><source><network>INTERNAL_NET</network></source>"+
		"<destination><network>EXTERNAL_HOSTS</network></destination></rule>"+
		"</outbound></nat>", 1)
}

// TestCompare_OutboundNATAlias_RatedByMode covers both vendors in the shape their
// GUIs write, in each mode. A manual rule is loaded only in advanced and hybrid
// mode, so in the others the alias is as good as unused.
func TestCompare_OutboundNATAlias_RatedByMode(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		mode string
		want string
	}{
		{"advanced", "<mode>advanced</mode>", "medium"},
		{"hybrid", "<mode>hybrid</mode>", "medium"},
		{"automatic", "<mode>automatic</mode>", "low"},
		{"disabled", "<mode>disabled</mode>", "low"},
		{"unset", "", "low"},
	}

	for _, tt := range tests {
		t.Run("pfSense source "+tt.name, func(t *testing.T) {
			t.Parallel()

			oldDoc := pfSenseOutboundDoc(t, tt.mode)
			newDoc := editAliasDoc(t, oldDoc, "INTERNAL_NET", "10.20.0.0/16", "0.0.0.0/0")

			got := diffAliasDocs(t, oldDoc, newDoc, Options{})

			require.Len(t, got, 1, "%+v", got)
			assert.Equal(t, "aliases.alias[INTERNAL_NET].members", got[0].Path)
			assert.Equal(t, tt.want, got[0].SecurityImpact)
		})

		t.Run("pfSense destination "+tt.name, func(t *testing.T) {
			t.Parallel()

			oldDoc := pfSenseOutboundDoc(t, tt.mode)
			newDoc := editAliasDoc(t, oldDoc, "EXTERNAL_HOSTS", "203.0.113.10", "203.0.113.11")

			got := diffAliasDocs(t, oldDoc, newDoc, Options{})

			require.Len(t, got, 1, "%+v", got)
			assert.Equal(t, "aliases.alias[EXTERNAL_HOSTS].members", got[0].Path)
			assert.Equal(t, tt.want, got[0].SecurityImpact)
		})

		t.Run("OPNsense "+tt.name, func(t *testing.T) {
			t.Parallel()

			oldDoc := strings.Replace(readAliasDoc(t, aliasModelFixture), "<mode>hybrid</mode>", tt.mode, 1)
			newDoc := editAliasDoc(t, oldDoc, "NAT_NETS", "192.168.10.0/24", "0.0.0.0/0")

			got := diffAliasDocs(t, oldDoc, newDoc, Options{})

			require.Len(t, got, 1, "%+v", got)
			assert.Equal(t, "aliases.alias[NAT_NETS].members", got[0].Path)
			assert.Equal(t, tt.want, got[0].SecurityImpact)
		})
	}
}

// TestCompare_OutboundNATAlias_ModeChangeInSameDiff covers a config that stops
// loading the rule in the same change that widens its alias. Either config using
// the alias is enough, so the widening stays medium.
func TestCompare_OutboundNATAlias_ModeChangeInSameDiff(t *testing.T) {
	t.Parallel()

	oldDoc := pfSenseOutboundDoc(t, "<mode>advanced</mode>")
	newDoc := editAliasDoc(t, pfSenseOutboundDoc(t, "<mode>automatic</mode>"),
		"INTERNAL_NET", "10.20.0.0/16", "0.0.0.0/0")

	got := diffAliasDocs(t, oldDoc, newDoc, Options{})

	impacts := make(map[string]string, len(got))
	for i := range got {
		impacts[got[i].Path] = got[i].SecurityImpact
	}
	assert.Equal(t, "medium", impacts["aliases.alias[INTERNAL_NET].members"])
	assert.Equal(t, "medium", impacts["nat.outbound.mode"])
}

// TestCompare_AliasRemovedWhileARuleNamesIt pins the entries a removal produces.
// The rule's reference goes with the alias, so the rule is reported too, with the
// same text on both sides, and the alias entry is the one that says what changed.
func TestCompare_AliasRemovedWhileARuleNamesIt(t *testing.T) {
	t.Parallel()

	oldDoc := pfSenseOutboundDoc(t, "<mode>advanced</mode>")
	newDoc := editAliasDoc(t, oldDoc, "INTERNAL_NET", "<name>INTERNAL_NET</name>", "<name>RENAMED</name>")

	aliases := diffAliasDocs(t, oldDoc, newDoc, Options{Sections: []string{"aliases"}})
	require.Len(t, aliases, 2, "the old name removed and the new one added: %+v", aliases)
	assert.Equal(t, ChangeRemoved, aliases[0].Type)
	assert.Equal(t, ChangeAdded, aliases[1].Type)

	rules := diffAliasDocs(t, oldDoc, newDoc, Options{Sections: []string{"nat"}})
	require.Len(t, rules, 1, "%+v", rules)
	assert.Equal(t, rules[0].OldValue, rules[0].NewValue)
}

// TestCompare_AliasTextIsSafeToPrint decodes each value that reaches a diff line
// from XML, with a character that would forge or overwrite a terminal line, and
// requires every field of every entry to be free of them. The terminal formatters
// print these fields as they stand. The check is strconv.IsPrint itself rather
// than the predicate under test, which would narrow along with the code.
func TestCompare_AliasTextIsSafeToPrint(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		from, to string
	}{
		{"description with a line feed", "Referenced by nothing", "x&#10;  ~ FORGED"},
		{"description with a carriage return", "Referenced by nothing", "x&#13;EVIL"},
		{"description with a bidirectional override", "Referenced by nothing", "x&#x202E;EVIL"},
		{"member with a carriage return inside it", "192.168.10.99", "192.168&#13;.10.99"},
		{"member with a bidirectional override", "192.168.10.99", "192.168.10.99&#x202E;EVIL"},
		{"member with a left-to-right mark", "192.168.10.99", "192.168.10.99&#x200E;EVIL"},
		{"member with an Arabic letter mark", "192.168.10.99", "192.168.10.99&#x061C;EVIL"},
		{"member with a bidirectional isolate", "192.168.10.99", "192.168.10.99&#x2066;EVIL"},
		{"member with a non-breaking space", "192.168.10.99", "192.168.10.99&#xA0;EVIL"},
		{"member with a line separator", "192.168.10.99", "192.168.10.99&#x2028;EVIL"},
		{"type with a line feed", "<type>host</type>", "<type>host&#10;EVIL</type>"},
		{"proto with a line feed", "<proto/>", "<proto>IPv4&#10;EVIL</proto>"},
		{"interface with a line feed", "<interface/>", "<interface>lan&#10;EVIL</interface>"},
		{"path expression with a line feed", "<path_expression/>", "<path_expression>.a&#10;EVIL</path_expression>"},
		{"expire with a line feed", "<expire/>", "<expire>60&#10;EVIL</expire>"},
		{"name with a line feed", "<name>SPARE</name>", "<name>SPARE&#10;EVIL</name>"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			oldDoc := readAliasDoc(t, aliasModelFixture)
			newDoc := editAliasDoc(t, oldDoc, "SPARE", tt.from, tt.to)

			// Both directions, so the value is on the old side once.
			got := diffAliasDocs(t, oldDoc, newDoc, Options{})
			require.NotEmpty(t, got)
			got = append(got, diffAliasDocs(t, newDoc, oldDoc, Options{})...)

			for i := range got {
				for _, field := range []string{got[i].Path, got[i].Description, got[i].OldValue, got[i].NewValue} {
					assert.Truef(t, printsAsItStands(field), "%q", field)
				}
			}
		})
	}
}

// printsAsItStands reports whether every rune of s is one strconv.IsPrint accepts.
func printsAsItStands(s string) bool {
	return !strings.ContainsFunc(s, func(r rune) bool { return !strconv.IsPrint(r) })
}

// TestEngine_Compare_Aliases_ParsedFixture runs the case #953 reported through
// the parser and the engine: widening the port alias the fixture's only pass
// rule names used to report no changes.
func TestEngine_Compare_Aliases_ParsedFixture(t *testing.T) {
	t.Parallel()

	oldDoc := readAliasDoc(t, "pfsense", aliasFixture)
	newDoc := editAliasDoc(t, oldDoc, "WEB_PORTS", "<address>80 443</address>", "<address>1:65535</address>")

	got := diffAliasDocs(t, oldDoc, newDoc, Options{})

	require.Len(t, got, 1, "%+v", got)
	assert.Equal(t, SectionAliases, got[0].Section)
	assert.Equal(t, "aliases.alias[WEB_PORTS].members", got[0].Path)
	assert.Equal(t, "1:65535", got[0].NewValue)
	assert.Equal(t, "medium", got[0].SecurityImpact)

	// The literal, not SectionAliases: --section passes the user's text through,
	// so a renamed constant must fail here rather than match nothing.
	selected := diffAliasDocs(t, oldDoc, newDoc, Options{Sections: []string{"aliases"}})
	require.Len(t, selected, 1, "--section aliases must keep the change")
	assert.Equal(t, got[0].Path, selected[0].Path)

	assert.Empty(t, diffAliasDocs(t, oldDoc, newDoc, Options{Sections: []string{"firewall"}}),
		"--section firewall must leave the alias change out")
}

// TestEngine_Compare_Normalize_KeepsAliasMemberChange pins that a members change
// is never dropped as formatting only. OPNsense keeps the inner spacing of a
// <content> line, and joined for display `a b` and `a  b` read the same once
// whitespace is collapsed (GOTCHAS §4.5).
func TestEngine_Compare_Normalize_KeepsAliasMemberChange(t *testing.T) {
	t.Parallel()

	oldDoc := readAliasDoc(t, aliasModelFixture)
	before := editAliasDoc(t, oldDoc, "SPARE", "192.168.10.99", "a b")
	after := editAliasDoc(t, oldDoc, "SPARE", "192.168.10.99", "a  b")

	got := diffAliasDocs(t, before, after, Options{Normalize: true})

	require.Len(t, got, 1, "%+v", got)
	assert.Equal(t, "aliases.alias[SPARE].members", got[0].Path)
	assert.Equal(t, got[0].OldValue, got[0].NewValue)
}

// TestEngine_Compare_Normalize_DropsExpireWhitespace pins that the expire entry is
// not a summary: its values are all that was compared, so --normalize may drop a
// whitespace-only edit to it, unlike an edit to the members (GOTCHAS §4.5).
func TestEngine_Compare_Normalize_DropsExpireWhitespace(t *testing.T) {
	t.Parallel()

	oldDoc := readAliasDoc(t, aliasModelFixture)
	newDoc := editAliasDoc(t, oldDoc, "EXT_BLOCK", "<expire>2592000</expire>", "<expire>2592000 </expire>")

	require.Len(t, diffAliasDocs(t, oldDoc, newDoc, Options{}), 1)
	assert.Empty(t, diffAliasDocs(t, oldDoc, newDoc, Options{Normalize: true}))
}

// TestImplementedSections_AreKnown ties the list the engine walks to the two
// methods that classify a section, which is the only caller they have.
func TestImplementedSections_AreKnown(t *testing.T) {
	t.Parallel()

	for _, section := range ImplementedSections() {
		assert.True(t, section.IsValid(), section.String())
		assert.True(t, section.IsImplemented(), section.String())
	}
}
