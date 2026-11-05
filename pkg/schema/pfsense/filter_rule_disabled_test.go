package pfsense

import (
	"encoding/json"
	"encoding/xml"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// assertRuleElementRoundTrip decodes a document whose first rule carries neighbor
// and whose second carries element, and checks what field reads on the second
// rule as parsed, after a marshal of that rule by pointer and by value, and after
// a document round trip, on the path a config takes. The neighbor has the opposite
// shape, so that a shape cannot borrow its presence from it.
func assertRuleElementRoundTrip(
	t *testing.T,
	neighbor, element string,
	want *string,
	field func(*FilterRule) *string,
) {
	t.Helper()

	input := "<pfsense><filter>" + vendorFilterRule(neighbor) + vendorFilterRule(element) +
		"</filter></pfsense>"

	var doc Document
	require.NoError(t, xml.Unmarshal([]byte(input), &doc))
	require.Len(t, doc.Filter.Rule, 2)
	assert.Equal(t, want, field(&doc.Filter.Rule[1]), "parsed from the vendor shape")

	byPointer, err := xml.Marshal(&doc.Filter.Rule[1])
	require.NoError(t, err)

	byValue, err := xml.Marshal(doc.Filter.Rule[1])
	require.NoError(t, err)

	for _, data := range [][]byte{byPointer, byValue} {
		var got FilterRule
		require.NoError(t, xml.Unmarshal(data, &got))
		assert.Equal(t, want, field(&got), "after marshal and unmarshal of %s", data)
	}

	written, err := xml.Marshal(&doc)
	require.NoError(t, err)

	var got Document
	require.NoError(t, xml.Unmarshal(written, &got))
	require.Len(t, got.Filter.Rule, 2)
	assert.Equal(t, field(&doc.Filter.Rule[0]), field(&got.Filter.Rule[0]), "neighbor")
	assert.Equal(t, want, field(&got.Filter.Rule[1]), "after a document round trip")
}

// assertRuleJSONKey checks the JSON key of a retyped field: left out when the
// element is absent, and the element's text when it is present, empty text
// included.
func assertRuleJSONKey(t *testing.T, rule FilterRule, key string, wantPresent bool, wantValue any) {
	t.Helper()

	//nolint:musttag // only one key is read, and XMLName carries no json tag
	data, err := json.Marshal(rule)
	require.NoError(t, err)

	var keys map[string]any
	require.NoError(t, json.Unmarshal(data, &keys))

	value, present := keys[key]
	assert.Equal(t, wantPresent, present, "key in %s", data)
	assert.Equal(t, wantValue, value, "value in %s", data)
}

// TestFilterRule_Disabled_XMLRoundTrip pins <disabled> on a filter rule
// (standards.md "Adding New XML Fields" step 3). pfSense tests the element with
// isset() (filter.inc L3256, L4267), so what it holds has to survive and an empty
// one must not read as an absent one.
func TestFilterRule_Disabled_XMLRoundTrip(t *testing.T) {
	t.Parallel()

	const (
		neighborAbsent = ""
		neighborSet    = "<disabled>1</disabled>"
	)

	tests := []struct {
		name     string
		element  string
		neighbor string
		want     *string
	}{
		{name: "self-closing element", element: "<disabled/>", neighbor: neighborAbsent, want: new("")},
		{name: "empty element", element: "<disabled></disabled>", neighbor: neighborAbsent, want: new("")},
		{name: "element holding 1", element: neighborSet, neighbor: neighborAbsent, want: new("1")},
		{name: "element holding 0", element: "<disabled>0</disabled>", neighbor: neighborAbsent, want: new("0")},
		{name: "element holding no", element: "<disabled>no</disabled>", neighbor: neighborAbsent, want: new("no")},
		{name: "absent element", element: neighborAbsent, neighbor: neighborSet},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			assertRuleElementRoundTrip(t, tt.neighbor, tt.element, tt.want, func(rule *FilterRule) *string {
				return rule.Disabled
			})
		})
	}
}

// TestFilterRule_Disabled_JSON pins the JSON key of the retyped field.
func TestFilterRule_Disabled_JSON(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		rule        FilterRule
		wantPresent bool
		wantValue   any
	}{
		{name: "absent element"},
		{name: "empty element", rule: FilterRule{Disabled: new("")}, wantPresent: true, wantValue: ""},
		{name: "element holding 0", rule: FilterRule{Disabled: new("0")}, wantPresent: true, wantValue: "0"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			assertRuleJSONKey(t, tt.rule, "disabled", tt.wantPresent, tt.wantValue)
		})
	}
}
