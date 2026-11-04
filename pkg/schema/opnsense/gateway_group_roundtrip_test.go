package opnsense

import (
	"encoding/xml"
	"reflect"
	"slices"
	"strings"
	"testing"
)

// gatewayGroupXML wraps member elements in a <gateway_group> as the OPNsense
// 26.7 GatewayGroups model writes it, with the members between <name> and
// <trigger>. The schema binds neither the uuid attribute nor <poolopts/>; they
// are here so the input has the shape of a real config.
func gatewayGroupXML(members string) string {
	return `<gateway_group uuid="0c4a7b6e-52f3-4a0d-9d3e-2b1f6f8a1c11"><name>WAN_FAILOVER</name>` + members +
		`<trigger>down</trigger><poolopts/><descr>Uplinks</descr></gateway_group>`
}

// assertTierElements checks that marshaled output writes each set tier under
// its vendor element and writes nothing for an empty one. tiers holds <item2>
// to <item5> in order.
func assertTierElements(t *testing.T, out string, tiers [4]string) {
	t.Helper()

	for i, element := range []string{"item2", "item3", "item4", "item5"} {
		if tiers[i] == "" {
			if strings.Contains(out, "<"+element) {
				t.Errorf("empty %s must be omitted: %s", element, out)
			}
			continue
		}
		if want := "<" + element + ">" + tiers[i] + "</" + element + ">"; !strings.Contains(out, want) {
			t.Errorf("marshaled XML missing %s: %s", want, out)
		}
	}
}

// TestGatewayGroup_TierElementsRoundTrip pins the XML round-trip invariant for
// <item2> to <item5> (standards.md "Adding New XML Fields" step 3). Each row
// starts from literal XML and checks the literal elements on the way out,
// because a struct marshaled and read back moves with its own tags and cannot
// see a renamed one. The tiers carry different values so a swapped tag fails too.
func TestGatewayGroup_TierElementsRoundTrip(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		members string
		item    []string
		tiers   [4]string
	}{
		{
			name: "26.7 model with every tier set",
			members: `<item2>WAN_GW2</item2><item3>WAN_GW3,WAN_GW4</item3><item4>WAN_GW5</item4>` +
				`<item5>WAN_GW6</item5><item>WAN_GW,WAN_GW7</item>`,
			item:  []string{"WAN_GW,WAN_GW7"},
			tiers: [4]string{"WAN_GW2", "WAN_GW3,WAN_GW4", "WAN_GW5", "WAN_GW6"},
		},
		{
			name: "legacy repeated item alongside every tier",
			members: `<item2>WAN_GW2</item2><item3>WAN_GW3</item3><item4>WAN_GW4</item4><item5>WAN_GW5</item5>` +
				`<item>WAN_GW|1</item><item>WAN_GW6|2</item><item>WAN_GW7|3</item>`,
			item:  []string{"WAN_GW|1", "WAN_GW6|2", "WAN_GW7|3"},
			tiers: [4]string{"WAN_GW2", "WAN_GW3", "WAN_GW4", "WAN_GW5"},
		},
		{
			// A string field reads <item3/> as it reads an absent element
			// (GOTCHAS 3.2), so the empty tiers the model writes are dropped on
			// the way out.
			name:    "26.7 model with empty tiers",
			members: `<item2/><item3>WAN_GW3</item3><item4/><item5>WAN_GW5</item5><item>WAN_GW</item>`,
			item:    []string{"WAN_GW"},
			tiers:   [4]string{"", "WAN_GW3", "", "WAN_GW5"},
		},
		{
			name:    "legacy group gains no tier element",
			members: `<item>WAN_GW|1</item><item>WAN_GW2|2</item>`,
			item:    []string{"WAN_GW|1", "WAN_GW2|2"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var got GatewayGroup
			if err := xml.Unmarshal([]byte(gatewayGroupXML(tc.members)), &got); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if !slices.Equal(got.Item, tc.item) {
				t.Errorf("Item = %q, want %q", got.Item, tc.item)
			}
			if tiers := [4]string{got.Item2, got.Item3, got.Item4, got.Item5}; tiers != tc.tiers {
				t.Errorf("tiers = %q, want %q", tiers, tc.tiers)
			}

			data, err := xml.Marshal(&got)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			out := string(data)
			assertTierElements(t, out, tc.tiers)
			if n := strings.Count(out, "<item>"); n != len(tc.item) {
				t.Errorf("marshaled %d <item> elements, want %d: %s", n, len(tc.item), out)
			}

			var back GatewayGroup
			if err := xml.Unmarshal(data, &back); err != nil {
				t.Fatalf("unmarshal after marshal: %v", err)
			}
			if !reflect.DeepEqual(back, got) {
				t.Errorf("round trip changed the group:\n got  %+v\n want %+v", back, got)
			}
		})
	}
}

// TestGatewayGroup_EmptyFirstTierOmitted pins the case where a round trip
// changes the decoded group. The model writes <item/> for a group with no tier 1
// gateway, which decodes to one empty entry, and encoding/xml applies omitempty
// to each entry of a slice as well as to the slice, so the entry is dropped as an
// empty <item2> to <item5> is. Item comes back empty rather than holding one
// empty string, and the converter reads both as no tier 1 gateway.
func TestGatewayGroup_EmptyFirstTierOmitted(t *testing.T) {
	t.Parallel()

	members := `<item2>WAN_GW2</item2><item3/><item4/><item5/><item/>`

	var got GatewayGroup
	if err := xml.Unmarshal([]byte(gatewayGroupXML(members)), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !slices.Equal(got.Item, []string{""}) {
		t.Fatalf("Item = %q, want one empty entry", got.Item)
	}

	data, err := xml.Marshal(&got)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(data), "<item>") {
		t.Errorf("empty <item> must be omitted: %s", data)
	}

	var back GatewayGroup
	if err := xml.Unmarshal(data, &back); err != nil {
		t.Fatalf("unmarshal after marshal: %v", err)
	}
	if len(back.Item) != 0 {
		t.Errorf("Item after round trip = %q, want empty", back.Item)
	}
	if back.Item2 != got.Item2 {
		t.Errorf("Item2 after round trip = %q, want %q", back.Item2, got.Item2)
	}
}

// TestGatewayGroup_EmptyTiersOmitted pins omitempty on each tier from a group
// built in Go, where no element was ever read. Each row sets at most one tier,
// so an element written for any other tier breaks the exact match.
func TestGatewayGroup_EmptyTiersOmitted(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		group GatewayGroup
		want  string
	}{
		{name: "no tier set", group: GatewayGroup{}},
		{name: "constructor", group: NewGatewayGroup()},
		{name: "tier 2 only", group: GatewayGroup{Item2: "WAN_GW2"}, want: "<item2>WAN_GW2</item2>"},
		{name: "tier 3 only", group: GatewayGroup{Item3: "WAN_GW3"}, want: "<item3>WAN_GW3</item3>"},
		{name: "tier 4 only", group: GatewayGroup{Item4: "WAN_GW4"}, want: "<item4>WAN_GW4</item4>"},
		{name: "tier 5 only", group: GatewayGroup{Item5: "WAN_GW5"}, want: "<item5>WAN_GW5</item5>"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			data, err := xml.Marshal(&tc.group)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			if want := "<gateway_group>" + tc.want + "</gateway_group>"; string(data) != want {
				t.Errorf("marshaled %s, want %s", data, want)
			}
		})
	}
}

// TestOpnSenseDocument_GatewayGroupTiersRoundTrip runs the tiers through the
// document that internal/cfgparser decodes <gateways> into, with a 26.7 group
// and a legacy group side by side, so neither takes on the other's elements.
func TestOpnSenseDocument_GatewayGroupTiersRoundTrip(t *testing.T) {
	t.Parallel()

	tiers := [4]string{"WAN_GW2", "WAN_GW3", "WAN_GW4", "WAN_GW5"}
	raw := `<opnsense><gateways>` +
		`<gateway_item><interface>wan</interface><gateway>192.0.2.1</gateway><name>WAN_GW</name></gateway_item>` +
		gatewayGroupXML(`<item2>WAN_GW2</item2><item3>WAN_GW3</item3><item4>WAN_GW4</item4>`+
			`<item5>WAN_GW5</item5><item>WAN_GW</item>`) +
		`<gateway_group><name>WAN_LEGACY</name><item>WAN_GW|1</item><item>WAN_GW2|2</item>` +
		`<trigger>down</trigger></gateway_group>` +
		`</gateways></opnsense>`

	var doc OpnSenseDocument
	if err := xml.Unmarshal([]byte(raw), &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(doc.Gateways.Groups) != 2 {
		t.Fatalf("got %d gateway groups, want 2", len(doc.Gateways.Groups))
	}

	data, err := xml.Marshal(&doc)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	out := string(data)
	assertTierElements(t, out, tiers)
	// One document holds both groups, so each tier element must appear only
	// once: a second would be the legacy group gaining an empty element.
	for _, element := range []string{"<item2", "<item3", "<item4", "<item5"} {
		if n := strings.Count(out, element); n != 1 {
			t.Errorf("marshaled %d %s elements, want 1: %s", n, element, out)
		}
	}

	var back OpnSenseDocument
	if err := xml.Unmarshal(data, &back); err != nil {
		t.Fatalf("unmarshal after marshal: %v", err)
	}
	if !reflect.DeepEqual(back.Gateways, doc.Gateways) {
		t.Errorf("round trip changed the gateways:\n got  %+v\n want %+v", back.Gateways, doc.Gateways)
	}
}
