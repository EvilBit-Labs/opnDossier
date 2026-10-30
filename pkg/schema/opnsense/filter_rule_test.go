package opnsense

import (
	"encoding/xml"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const filterRuleFixture = "opnsense-mvc-rules.xml"

// TestFirewall_FilterRuleFixture_DecodesEveryRule pins the binding of the rules
// kept in the firewall filter model. They used to be bound as one string, which
// holds the white space between the rules and nothing of them.
func TestFirewall_FilterRuleFixture_DecodesEveryRule(t *testing.T) {
	t.Parallel()

	doc := decodePortForwardFixture(t, filterRuleFixture)
	require.NotNil(t, doc.OPNsense.Firewall)

	rules := doc.OPNsense.Firewall.Filter.Rules
	require.Len(t, rules, 10, "nine rules and an empty <rule/>, in document order")
	require.Len(t, doc.Filter.Rule, 3, "the rules under <filter> are a separate store")

	web := rules[0]
	assert.Equal(t, "c3c3c3c3-0000-4000-8000-000000000003", web.UUID)
	assert.Equal(t, "300", web.Sequence)
	assert.Equal(t, "pass", web.Action)
	assert.Equal(t, "wan", web.Interface)
	assert.Equal(t, "TCP", web.Protocol)
	assert.Equal(t, "keep", web.StateType)
	assert.Equal(t, "https", web.DestinationPort)
	assert.Equal(t, "1", web.Log)
	assert.Equal(t, "Web servers from the internet", web.Description)
	require.NotNil(t, web.Enabled)
	assert.Equal(t, "1", *web.Enabled)
	require.NotNil(t, web.DestinationNet)
	assert.Equal(t, "WEB_HOSTS", *web.DestinationNet)

	lists := rules[1]
	require.NotNil(t, lists.SourceNet)
	assert.Equal(t, "lan,MGMT_NETS", *lists.SourceNet)
	assert.Equal(t, "WEB_PORTS", lists.DestinationPort)

	assert.True(t, rules[2].IsPlaceholder())

	everywhere := rules[3]
	assert.Empty(t, everywhere.Interface, "a rule for every interface names none")
	require.NotNil(t, everywhere.IPProtocol)
	assert.Equal(t, "inet46", *everywhere.IPProtocol)

	icmp := rules[4]
	assert.Equal(t, "lan,opt1", icmp.Interface)
	assert.Equal(t, "128,135", icmp.ICMP6Type)
	require.NotNil(t, icmp.Quick)
	assert.Equal(t, "0", *icmp.Quick)

	assert.Equal(t, "1", rules[5].DestinationNot)
	assert.Equal(t, "none", rules[5].StateType)

	factory := rules[6]
	assert.Empty(t, factory.UUID, "the factory default writes no uuid")
	assert.Equal(t, "Default allow LAN to any rule", factory.Description)

	require.NotNil(t, rules[8].Enabled)
	assert.Equal(t, "0", *rules[8].Enabled)
	assert.Equal(t, "out", rules[8].Direction)
}

// TestFirewallFilterRule_BindsEveryFixtureElement fails when a rule in the
// fixture carries an element or attribute the schema does not bind.
// encoding/xml drops those without an error, and the model completeness check
// does not look inside an element that repeats.
func TestFirewallFilterRule_BindsEveryFixtureElement(t *testing.T) {
	t.Parallel()

	bound := xmlElementNames(reflect.TypeFor[FirewallFilterRule]())

	f, err := os.Open(filepath.Join(testdataDir(), filterRuleFixture))
	require.NoError(t, err)
	defer f.Close()

	var (
		path    []string
		checked int
	)

	dec := xml.NewDecoder(f)
	for {
		tok, err := dec.Token()
		if err != nil {
			break
		}

		switch el := tok.(type) {
		case xml.StartElement:
			switch strings.Join(path, ">") {
			case "opnsense>OPNsense>Firewall>Filter>rules":
				for _, attr := range el.Attr {
					assert.Equalf(t, "uuid", attr.Name.Local, "attribute on <%s>", el.Name.Local)
				}
			case "opnsense>OPNsense>Firewall>Filter>rules>rule":
				assert.Truef(t, bound[el.Name.Local], "<%s> under <rule> is not bound by the schema", el.Name.Local)

				checked++
			}

			path = append(path, el.Name.Local)
		case xml.EndElement:
			path = path[:len(path)-1]
		}
	}

	// Seven rules with the 59 elements of the 26.7.5 model, one with the 54 of
	// 26.1 and one with the 24 the factory default writes.
	assert.Equal(t, 7*59+54+24, checked)
	assert.Len(t, bound, 59, "the type binds the 59 elements of the 26.7.5 model")
}

// TestRule_IsPlaceholder_DecodedEmptyElement_ReportsPlaceholder is the Rule
// counterpart to
// TestStaticRoute_IsPlaceholder_DecodedEmptyElement_ReportsPlaceholder.
func TestRule_IsPlaceholder_DecodedEmptyElement_ReportsPlaceholder(t *testing.T) {
	t.Parallel()

	for _, element := range []string{`<rule/>`, `<rule></rule>`, "<rule>\n  </rule>"} {
		var filter Filter
		require.NoError(t, xml.Unmarshal([]byte(`<filter>`+element+`</filter>`), &filter))
		require.Len(t, filter.Rule, 1)

		assert.Equal(t, "rule", filter.Rule[0].XMLName.Local,
			"the decoder sets XMLName, which is why the predicate compares fields by name")
		assert.Truef(t, filter.Rule[0].IsPlaceholder(), "%s is a placeholder", element)
	}
}

// TestRule_IsPlaceholder_RetainsRulesWithData covers the entries whose only
// content decodes through a custom type, and a rule with no type, which is what
// the rule a port forward stored for itself looks like up to 24.7.
func TestRule_IsPlaceholder_RetainsRulesWithData(t *testing.T) {
	t.Parallel()

	for _, body := range []string{
		`<disabled>1</disabled>`,
		`<quick/>`,
		`<source><any>1</any></source>`,
		`<destination><address>10.0.0.5</address></destination>`,
		`<interface>wan</interface>`,
		`<descr>placeholder for later</descr>`,
		`<associated-rule-id>nat_68dd1c2a4b5c61.23456789</associated-rule-id>`,
	} {
		var filter Filter
		require.NoError(t, xml.Unmarshal([]byte(`<filter><rule>`+body+`</rule></filter>`), &filter))
		require.Len(t, filter.Rule, 1)
		assert.Falsef(t, filter.Rule[0].IsPlaceholder(), "a rule holding only %s must be kept", body)
	}

	var uuidOnly Filter
	require.NoError(
		t,
		xml.Unmarshal([]byte(`<filter><rule uuid="b2b2b2b2-0000-4000-8000-000000000009"/></filter>`), &uuidOnly),
	)
	require.Len(t, uuidOnly.Rule, 1)
	assert.False(t, uuidOnly.Rule[0].IsPlaceholder(), "a rule holding only a uuid must be kept")
}

// TestFirewallFilterRule_IsPlaceholder covers the entries OPNsense skips: a
// <rule> with no child element, whatever its attributes. Absent elements take
// defaults that add up to an enabled pass rule from any to any, so an entry
// kept by mistake would not be harmless.
func TestFirewallFilterRule_IsPlaceholder(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		xml  string
		want bool
	}{
		{"self-closing", `<rule/>`, true},
		{"empty", `<rule></rule>`, true},
		{"attribute only", `<rule uuid="c3c3c3c3-0000-4000-8000-000000000001"/>`, true},
		{"one element", `<rule><description>x</description></rule>`, false},
		{"a flag set to its default", `<rule><log>0</log></rule>`, false},
		{"an empty element that overrides a default", `<rule><quick/></rule>`, false},
		{"enabled only", `<rule><enabled>1</enabled></rule>`, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var rule FirewallFilterRule
			require.NoError(t, xml.Unmarshal([]byte(tt.xml), &rule))
			assert.Equal(t, tt.want, rule.IsPlaceholder())
		})
	}
}

// TestFirewallFilterRule_IsPlaceholder_EveryElementDefeatsIt sets each field in
// turn. The uuid is the one field that does not count, because it is an
// attribute.
func TestFirewallFilterRule_IsPlaceholder_EveryElementDefeatsIt(t *testing.T) {
	t.Parallel()

	typ := reflect.TypeFor[FirewallFilterRule]()
	for i := range typ.NumField() {
		field := typ.Field(i)

		var rule FirewallFilterRule
		require.Truef(t, populateField(reflect.ValueOf(&rule).Elem().Field(i)), "cannot populate %s", field.Name)
		assert.Equalf(t, field.Name == "UUID", rule.IsPlaceholder(), "field %s", field.Name)
	}
}

// TestFirewallFilterRule_MarshalKeepsEmptyElements pins the write side: an
// element that overrides a default with nothing is written back, and one that
// was absent stays absent.
func TestFirewallFilterRule_MarshalKeepsEmptyElements(t *testing.T) {
	t.Parallel()

	const stored = `<rule uuid="u"><enabled></enabled><sequence>7</sequence><source_net>lan,opt1</source_net></rule>`

	var rule FirewallFilterRule
	require.NoError(t, xml.Unmarshal([]byte(stored), &rule))

	out, err := xml.Marshal(struct {
		FirewallFilterRule

		XMLName xml.Name `xml:"rule"`
	}{FirewallFilterRule: rule})
	require.NoError(t, err)
	assert.Equal(t, stored, string(out))
}
