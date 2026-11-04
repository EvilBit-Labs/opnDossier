package opnsense

import (
	"encoding/json"
	"encoding/xml"
	"reflect"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// aliasesEqual compares two aliases. AliasURLs is a slice, so == does not
// compile on the type.
func aliasesEqual(a, b Alias) bool {
	return reflect.DeepEqual(a, b)
}

// aliasEnabledStates is every shape <enabled> can take on an alias. The parsed
// value keeps them apart, which a string field could not do for absent and empty
// (GOTCHAS §3.2).
func aliasEnabledStates() []struct {
	name    string
	element string
	want    *string
} {
	stringPtr := func(s string) *string { return &s }

	return []struct {
		name    string
		element string
		want    *string
	}{
		{name: "absent", element: "", want: nil},
		{name: "empty", element: "<enabled></enabled>", want: stringPtr("")},
		{name: "zero", element: "<enabled>0</enabled>", want: stringPtr("0")},
		{name: "one", element: "<enabled>1</enabled>", want: stringPtr("1")},
	}
}

func TestAlias_EnabledKeepsEveryShapeApart(t *testing.T) {
	t.Parallel()

	for _, tt := range aliasEnabledStates() {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var got Alias
			require.NoError(t, xml.Unmarshal([]byte(`<alias>`+tt.element+`<name>A</name></alias>`), &got))
			assert.Equal(t, tt.want, got.Enabled)

			marshaled, err := xml.Marshal(got)
			require.NoError(t, err)

			var roundTripped Alias
			require.NoError(t, xml.Unmarshal(marshaled, &roundTripped))
			assert.Equal(t, tt.want, roundTripped.Enabled, "lost on marshal: %s", marshaled)
		})
	}
}

// TestAlias_ModelShapeRoundTrip decodes an alias in the form the model writes,
// with unset fields as empty elements, and requires each value to survive a
// round trip under its own element.
func TestAlias_ModelShapeRoundTrip(t *testing.T) {
	t.Parallel()

	const input = `<alias uuid="c1c1c1c1-0000-4000-8000-000000000004">
		<enabled>1</enabled>
		<name>FEED</name>
		<type>urljson</type>
		<path_expression>.allowed[].address</path_expression>
		<proto>IPv4,IPv6</proto>
		<interface>lan</interface>
		<content>https://lists.example.org/allowed.json</content>
		<expire>2592000</expire>
		<description>Hosts allowed by a published list</description>
	</alias>`

	var got Alias
	require.NoError(t, xml.Unmarshal([]byte(input), &got))

	enabled := "1"
	want := Alias{
		UUID:             "c1c1c1c1-0000-4000-8000-000000000004",
		Enabled:          &enabled,
		Name:             "FEED",
		Type:             "urljson",
		PathExpression:   ".allowed[].address",
		Proto:            "IPv4,IPv6",
		Interface:        "lan",
		Expire:           "2592000",
		Content:          "https://lists.example.org/allowed.json",
		ModelDescription: "Hosts allowed by a published list",
	}
	assert.Equal(t, want, got)

	marshaled, err := xml.Marshal(got)
	require.NoError(t, err)

	for _, element := range []string{
		"<enabled>1</enabled>",
		"<path_expression>.allowed[].address</path_expression>",
		"<proto>IPv4,IPv6</proto>",
		"<interface>lan</interface>",
		"<expire>2592000</expire>",
		"<description>Hosts allowed by a published list</description>",
	} {
		assert.Contains(t, string(marshaled), element)
	}
	assert.NotContains(t, string(marshaled), "<descr>", "the model does not write <descr>")

	var roundTripped Alias
	require.NoError(t, xml.Unmarshal(marshaled, &roundTripped))
	assert.Equal(t, want, roundTripped)
}

// TestAlias_LegacyShapeRoundTrip covers the elements only the legacy block
// writes. The second <aliasurl> is the one a string field would keep, so a list
// reduced to one entry fails here (GOTCHAS §3.3).
func TestAlias_LegacyShapeRoundTrip(t *testing.T) {
	t.Parallel()

	const input = `<alias>
		<name>LEGACY_URLS</name>
		<type>url</type>
		<url>https://lists.example.org/table.txt</url>
		<aliasurl>https://lists.example.org/first.txt</aliasurl>
		<aliasurl>https://lists.example.org/second.txt</aliasurl>
		<address>10.5.5.4 10.5.5.5</address>
		<proto>IPv4</proto>
		<descr>Legacy URL alias</descr>
	</alias>`

	var got Alias
	require.NoError(t, xml.Unmarshal([]byte(input), &got))

	want := Alias{
		Name: "LEGACY_URLS",
		Type: "url",
		URL:  "https://lists.example.org/table.txt",
		AliasURLs: []string{
			"https://lists.example.org/first.txt",
			"https://lists.example.org/second.txt",
		},
		Address:     "10.5.5.4 10.5.5.5",
		Proto:       "IPv4",
		Description: "Legacy URL alias",
	}
	assert.Equal(t, want, got)

	marshaled, err := xml.Marshal(got)
	require.NoError(t, err)
	assert.Equal(t, 2, strings.Count(string(marshaled), "<aliasurl>"), "%s", marshaled)

	var roundTripped Alias
	require.NoError(t, xml.Unmarshal(marshaled, &roundTripped))
	assert.Equal(t, want, roundTripped)
}

// TestAlias_DescriptionsKeepTheirOwnKeys pins that the two description fields
// have separate JSON and YAML keys. encoding/json drops both fields of a pair
// that shares a key, and yaml.v3 panics on one.
func TestAlias_DescriptionsKeepTheirOwnKeys(t *testing.T) {
	t.Parallel()

	alias := Alias{Name: "A", Description: "legacy text", ModelDescription: "model text"}

	data, err := json.Marshal(alias)
	require.NoError(t, err)

	var fromJSON Alias
	require.NoError(t, json.Unmarshal(data, &fromJSON))
	assert.Equal(t, alias, fromJSON)

	data, err = yaml.Marshal(alias)
	require.NoError(t, err)

	var fromYAML Alias
	require.NoError(t, yaml.Unmarshal(data, &fromYAML))
	assert.Equal(t, alias, fromYAML)
}
