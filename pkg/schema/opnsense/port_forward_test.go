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

const (
	portForwardFixture       = "opnsense-port-forwards.xml"
	legacyPortForwardFixture = "opnsense-legacy-port-forwards.xml"
)

// decodePortForwardFixture decodes a fixture into the document type, the way
// the parser does.
func decodePortForwardFixture(t *testing.T, name string) OpnSenseDocument {
	t.Helper()

	data, err := os.ReadFile(filepath.Join(testdataDir(), name))
	require.NoError(t, err)

	var doc OpnSenseDocument
	require.NoError(t, xml.Unmarshal(data, &doc))

	return doc
}

// TestNat_LegacyPortForwardFixture_DecodesEveryRule pins the binding against a
// config in the shape OPNsense wrote up to 25.7. The schema used to read
// <nat><inbound><rule> and <internalip>, which no release writes, so every
// port forward was dropped without an error.
func TestNat_LegacyPortForwardFixture_DecodesEveryRule(t *testing.T) {
	t.Parallel()

	rules := decodePortForwardFixture(t, legacyPortForwardFixture).Nat.Inbound
	require.Len(t, rules, 3)

	web := rules[0]
	assert.Equal(t, "192.168.10.50", web.Target)
	assert.Equal(t, "8443", web.LocalPort)
	assert.Equal(t, "443", web.Destination.Port)
	assert.Equal(t, "wanip", web.Destination.Network)
	assert.True(t, web.Source.IsAny())
	assert.Equal(t, "nat_68dd1c2a4b5c61.23456789", web.AssociatedRuleID)
	assert.Equal(t, InterfaceList{"wan"}, web.Interface)
	assert.Empty(t, web.UUID)
	assert.False(t, bool(web.Disabled))
	require.NotNil(t, web.Created)
	assert.Equal(t, "root@192.0.2.10", web.Created.Username)

	mail := rules[1]
	assert.Equal(t, "MAIL_HOST", mail.Target)
	assert.Equal(t, "MAIL_PORTS", mail.LocalPort)
	assert.Equal(t, "pass", mail.AssociatedRuleID)
	assert.Equal(t, InterfaceList{"wan", "opt1"}, mail.Interface)
	assert.Equal(t, "TRUSTED_NETS", mail.Source.Address)
	assert.True(t, bool(mail.Source.Not))
	assert.Equal(t, "purenat", mail.NATReflection)
	assert.Equal(t, "Mail", mail.Category)
	assert.True(t, bool(mail.NoSync))
	assert.True(t, bool(mail.Log))

	exempt := rules[2]
	assert.True(t, bool(exempt.NoRDR))
	assert.True(t, bool(exempt.Disabled))
	assert.Empty(t, exempt.Target)
	assert.Empty(t, exempt.LocalPort)
}

// TestNat_PortForwardFixture_DecodesEveryRule is the same check for the shape
// 26.1 and later write: the same path, with a uuid attribute, a <sequence>, the
// association in <pass> and every flag present as 0 or 1.
func TestNat_PortForwardFixture_DecodesEveryRule(t *testing.T) {
	t.Parallel()

	rules := decodePortForwardFixture(t, portForwardFixture).Nat.Inbound
	require.Len(t, rules, 4)

	web := rules[0]
	assert.Equal(t, "b2b2b2b2-0000-4000-8000-000000000001", web.UUID)
	assert.Equal(t, "100", web.Sequence)
	assert.Equal(t, "192.168.10.50", web.Target)
	assert.Equal(t, "8443", web.LocalPort)
	assert.Equal(t, "443", web.Destination.Port)
	assert.Empty(t, web.Pass)
	assert.Empty(t, web.AssociatedRuleID)
	assert.False(t, bool(web.Disabled), "<disabled>0</disabled> is an enabled rule")
	assert.False(t, bool(web.NoRDR))
	assert.False(t, bool(web.Source.Not))
	require.NotNil(t, web.Updated)

	mail := rules[1]
	assert.Equal(t, "300", mail.Sequence)
	assert.Equal(t, "pass", mail.Pass)
	assert.Equal(t, "TRUSTED_NETS", mail.Source.Network)
	assert.Equal(t, "MAIL_HOST", mail.Target)
	assert.Equal(t, InterfaceList{"wan", "opt1"}, mail.Interface)
	assert.Equal(t, "Mail", mail.Category)
	assert.True(t, bool(mail.Log))
	assert.True(t, strings.HasPrefix(mail.Audit, "eyJjcmVhdGVkIjp7"), "audit is base64 JSON from 26.7.4 on")
	assert.Nil(t, mail.Created)

	exempt := rules[2]
	assert.Equal(t, "200", exempt.Sequence)
	assert.True(t, bool(exempt.NoRDR))
	assert.Empty(t, exempt.Target)

	jump := rules[3]
	assert.Equal(t, "rule", jump.Pass)
	assert.True(t, bool(jump.Disabled))
	assert.True(t, bool(jump.Source.Not))
	assert.Equal(t, "ssh", jump.LocalPort)
}

// TestInboundRule_BindsEveryFixtureElement fails when a port forward in either
// fixture carries an element the schema does not bind. encoding/xml drops an
// unbound element without an error, and the model completeness check does not
// look inside an element that repeats, so nothing else would notice.
func TestInboundRule_BindsEveryFixtureElement(t *testing.T) {
	t.Parallel()

	bound := map[string]map[string]bool{
		"rule":        xmlElementNames(reflect.TypeFor[InboundRule]()),
		"source":      xmlElementNames(reflect.TypeFor[Source]()),
		"destination": xmlElementNames(reflect.TypeFor[Destination]()),
		"created":     xmlElementNames(reflect.TypeFor[Created]()),
		"updated":     xmlElementNames(reflect.TypeFor[Updated]()),
	}

	for _, name := range []string{portForwardFixture, legacyPortForwardFixture} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			f, err := os.Open(filepath.Join(testdataDir(), name))
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
					// Only <nat><rule> and below; <nat><outbound><rule> is NATRule.
					if len(path) >= 3 && path[1] == "nat" && path[2] == "rule" {
						parent := path[len(path)-1]
						assert.Truef(t, bound[parent][el.Name.Local],
							"<%s> under <%s> is not bound by the schema", el.Name.Local, strings.Join(path[1:], "><"))

						checked++
					}

					path = append(path, el.Name.Local)
				case xml.EndElement:
					path = path[:len(path)-1]
				}
			}

			assert.Positive(t, checked, "fixture has no port forward elements to check")
		})
	}
}

// xmlElementNames returns the child element names a struct type binds.
func xmlElementNames(typ reflect.Type) map[string]bool {
	names := make(map[string]bool)

	for field := range typ.Fields() {
		tag := field.Tag.Get("xml")
		name, _, _ := strings.Cut(tag, ",")
		if name == "" || strings.Contains(tag, ",attr") || field.Name == xmlNameField {
			continue
		}

		names[name] = true
	}

	return names
}

// TestNat_Marshal_WritesPortForwardsDirectlyUnderNat pins the write side of the
// binding: rules are children of <nat>, next to <outbound>, and the redirect
// address is <target>.
func TestNat_Marshal_WritesPortForwardsDirectlyUnderNat(t *testing.T) {
	t.Parallel()

	doc := NewOpnSenseDocument()
	doc.Nat.Outbound.Mode = "automatic"
	doc.Nat.Inbound = []InboundRule{{
		Interface:   InterfaceList{testWAN},
		Protocol:    testTCP,
		Destination: Destination{Network: "wanip", Port: "443"},
		Target:      "192.168.10.50",
		LocalPort:   "8443",
	}}

	data, err := xml.Marshal(doc)
	require.NoError(t, err)

	out := string(data)
	assert.Contains(t, out, "</outbound><rule>")
	assert.Contains(t, out, "<target>192.168.10.50</target><local-port>8443</local-port>")
	assert.NotContains(t, out, "<inbound>")

	var back OpnSenseDocument
	require.NoError(t, xml.Unmarshal(data, &back))
	require.Len(t, back.Nat.Inbound, 1)
	assert.Equal(t, "192.168.10.50", back.Nat.Inbound[0].Target)
}

// TestInboundRule_IsPlaceholder_DecodedEmptyElement_ReportsPlaceholder is the
// InboundRule counterpart to
// TestStaticRoute_IsPlaceholder_DecodedEmptyElement_ReportsPlaceholder.
func TestInboundRule_IsPlaceholder_DecodedEmptyElement_ReportsPlaceholder(t *testing.T) {
	t.Parallel()

	var nat Nat
	require.NoError(t, xml.Unmarshal(
		[]byte(`<nat><outbound><mode>automatic</mode></outbound><rule/></nat>`), &nat,
	))
	require.Len(t, nat.Inbound, 1)

	assert.Equal(t, "rule", nat.Inbound[0].XMLName.Local,
		"the decoder sets XMLName, which is why the predicate compares fields by name")
	assert.True(t, nat.Inbound[0].IsPlaceholder())
}

// TestInboundRule_IsPlaceholder_RetainsRulesWithData covers the entries whose
// only content decodes through a custom type.
func TestInboundRule_IsPlaceholder_RetainsRulesWithData(t *testing.T) {
	t.Parallel()

	for _, body := range []string{
		`<disabled>1</disabled>`,
		`<nordr/>`,
		`<source><any>1</any></source>`,
		`<destination><port>443</port></destination>`,
		`<interface>wan</interface>`,
		`<descr>placeholder for later</descr>`,
	} {
		var nat Nat
		require.NoError(t, xml.Unmarshal([]byte(`<nat><rule>`+body+`</rule></nat>`), &nat))
		require.Len(t, nat.Inbound, 1)
		assert.Falsef(t, nat.Inbound[0].IsPlaceholder(), "a rule holding only %s must be kept", body)
	}

	var uuidOnly Nat
	require.NoError(
		t,
		xml.Unmarshal([]byte(`<nat><rule uuid="b2b2b2b2-0000-4000-8000-000000000009"/></nat>`), &uuidOnly),
	)
	require.Len(t, uuidOnly.Inbound, 1)
	assert.False(t, uuidOnly.Inbound[0].IsPlaceholder(), "a rule holding only a uuid must be kept")
}

// TestRule_AssociatedRuleID_FixtureRoundTrip pins <associated-rule-id> on a
// filter rule against the fixtures and checks the element is written back.
func TestRule_AssociatedRuleID_FixtureRoundTrip(t *testing.T) {
	t.Parallel()

	for _, name := range []string{portForwardFixture, legacyPortForwardFixture} {
		rules := decodePortForwardFixture(t, name).Filter.Rule
		require.Len(t, rules, 2, name)
		assert.Empty(t, rules[0].AssociatedRuleID, name)
		assert.Equal(t, "nat_68dd1c2a4b5c61.23456789", rules[1].AssociatedRuleID, name)

		data, err := xml.Marshal(rules[1])
		require.NoError(t, err)
		assert.Contains(t, string(data),
			"<associated-rule-id>nat_68dd1c2a4b5c61.23456789</associated-rule-id>", name)
	}
}
