package pfsense

import (
	"encoding/xml"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	// floatingOpenTag has no closing bracket so that it counts a self-closing
	// <floating/> as well.
	floatingOpenTag = "<floating"

	floatingSelfClosing = "<floating/>"
	floatingEmpty       = "<floating></floating>"
	floatingYes         = "<floating>yes</floating>"
)

// vendorFilterRule returns the floating rule of
// testdata/pfsense/config-pfSense.xml with element in place of its <floating>,
// so that an empty element gives the same rule without one.
func vendorFilterRule(element string) string {
	return `<rule>
		<id></id>
		<tracker>1585137356</tracker>
		<type>block</type>
		<interface>wan</interface>
		<ipprotocol>inet46</ipprotocol>
		<tag></tag>
		<tagged>MULLVAD_NO_WAN_EGRESS</tagged>
		<direction>any</direction>
		` + element + `
		<max></max>
		<statetype><![CDATA[keep state]]></statetype>
		<source>
			<any></any>
		</source>
		<destination>
			<any></any>
		</destination>
		<descr><![CDATA[Disable Mullvad WAN Egress]]></descr>
	</rule>`
}

// floatingValues lists the Floating field of each rule, in rule order.
func floatingValues(rules []FilterRule) []*string {
	values := make([]*string, 0, len(rules))
	for i := range rules {
		values = append(values, rules[i].Floating)
	}

	return values
}

// assertFloatingElement checks that data holds want as its only <floating>
// element, or no such element when want is empty.
func assertFloatingElement(t *testing.T, data []byte, want string) {
	t.Helper()

	text := string(data)
	if want == "" {
		assert.NotContains(t, text, floatingOpenTag)
		return
	}

	assert.Equal(t, 1, strings.Count(text, floatingOpenTag), text)
	assert.Contains(t, text, want)
}

// TestFilterRule_Floating_XMLRoundTrip pins the presence semantics of
// <floating> (standards.md "Adding New XML Fields" step 3). pfSense tests the
// element with isset(), so an empty one makes a rule floating and must not read
// as an absent one (GOTCHAS 3.2). pfSense's writer spells an empty element
// <floating></floating>, as it does <any></any> in the fixtures, and marshalling
// a parsed <floating/> gives that form too.
//
// The rule is marshaled by pointer and by value. GOTCHAS 15.1 is about the
// difference between the two, and a *string field must not depend on it.
func TestFilterRule_Floating_XMLRoundTrip(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		element string
		want    *string
		written string
	}{
		{name: "self-closing element", element: floatingSelfClosing, want: new(""), written: floatingEmpty},
		{name: "empty element", element: floatingEmpty, want: new(""), written: floatingEmpty},
		{name: "element holding yes", element: floatingYes, want: new("yes"), written: floatingYes},
		{name: "absent element"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var rule FilterRule
			require.NoError(t, xml.Unmarshal([]byte(vendorFilterRule(tt.element)), &rule))
			assert.Equal(t, tt.want, rule.Floating, "parsed from the vendor shape")

			byPointer, err := xml.Marshal(&rule)
			require.NoError(t, err)

			byValue, err := xml.Marshal(rule)
			require.NoError(t, err)

			for _, data := range [][]byte{byPointer, byValue} {
				assertFloatingElement(t, data, tt.written)

				var got FilterRule
				require.NoError(t, xml.Unmarshal(data, &got))
				assert.Equal(t, tt.want, got.Floating, "after marshal and unmarshal of %s", data)
			}
		})
	}
}

// TestDocument_FilterRuleFloating_XMLRoundTrip pins the same presence on the
// path a config takes, <pfsense><filter><rule>, with one rule of each shape side
// by side so that a shape cannot borrow its presence from a neighbor.
func TestDocument_FilterRuleFloating_XMLRoundTrip(t *testing.T) {
	t.Parallel()

	input := "<pfsense><filter>" +
		vendorFilterRule(floatingSelfClosing) +
		vendorFilterRule(floatingEmpty) +
		vendorFilterRule(floatingYes) +
		vendorFilterRule("") +
		"</filter></pfsense>"
	want := []*string{new(""), new(""), new("yes"), nil}

	var doc Document
	require.NoError(t, xml.Unmarshal([]byte(input), &doc))
	assert.Equal(t, want, floatingValues(doc.Filter.Rule), "parsed from the vendor shape")

	data, err := xml.Marshal(&doc)
	require.NoError(t, err)

	text := string(data)
	assert.Equal(t, 3, strings.Count(text, floatingOpenTag), text)
	assert.Equal(t, 2, strings.Count(text, floatingEmpty), text)
	assert.Equal(t, 1, strings.Count(text, floatingYes), text)

	var got Document
	require.NoError(t, xml.Unmarshal(data, &got))
	assert.Equal(t, want, floatingValues(got.Filter.Rule), "after marshal and unmarshal")
}

// TestDocument_FilterRuleFloating_FixtureRoundTrip runs a config pfSense wrote
// through the same trip. The number of floating rules is read from the raw file
// rather than through the schema, so the two cannot agree by sharing a mistake.
func TestDocument_FilterRuleFloating_FixtureRoundTrip(t *testing.T) {
	t.Parallel()

	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "testdata", "pfsense", "config-pfSense.xml"))
	require.NoError(t, err)

	var doc Document
	require.NoError(t, xml.Unmarshal(raw, &doc))

	values := floatingValues(doc.Filter.Rule)
	require.Greater(t, len(values), 1, "the fixture must hold rules that are not floating as well")

	present := 0
	for _, value := range values {
		if value != nil {
			present++
		}
	}

	wantPresent := strings.Count(string(raw), floatingOpenTag)
	require.Positive(t, wantPresent, "the fixture must hold a floating rule")
	require.Equal(t, wantPresent, present, "rules with a parsed <floating>")

	data, err := xml.Marshal(&doc)
	require.NoError(t, err)
	assert.Equal(t, wantPresent, strings.Count(string(data), floatingYes), "written back as the vendor wrote it")

	var got Document
	require.NoError(t, xml.Unmarshal(data, &got))
	assert.Equal(t, values, floatingValues(got.Filter.Rule), "after marshal and unmarshal")
}
