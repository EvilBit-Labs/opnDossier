package pfsense_test

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
	"github.com/EvilBit-Labs/opnDossier/pkg/parser/pfsense"
	schema "github.com/EvilBit-Labs/opnDossier/pkg/schema/pfsense"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// advDHCPConfigTemplate wraps a generated <lan> body. Advanced DHCP *client*
// settings live under <interfaces>, not under <dhcpd>; see
// testdata/sample.config.5.xml, which carries the whole set under <interfaces>.
const advDHCPConfigTemplate = `<?xml version="1.0"?>
<pfsense>
  <system>
    <hostname>fw</hostname>
    <domain>example.com</domain>
  </system>
  <interfaces>
    <lan>
      <if>vtnet0</if>
%s    </lan>
  </interfaces>
</pfsense>`

// advDHCPSentinel returns a value unique to the field, so a builder that reads
// the wrong source field produces a mismatch rather than an accidental pass.
func advDHCPSentinel(field string) string { return "sentinel-" + field }

// advDHCPTickedValue is what pfSense's Form_Checkbox stores for the three
// DHCPv6 checkboxes when they are ticked.
const advDHCPTickedValue = "Selected"

// advDHCPFlagFields reports which fields of the given advanced-DHCP structs are
// checkboxes (bool) rather than value-bearing strings. The XML those two kinds
// require differs, so the generator and the assertions both key off this rather
// than hardcoding a list that would drift.
func advDHCPFlagFields(structs ...any) map[string]bool {
	flags := map[string]bool{}

	for _, v := range structs {
		rt := reflect.TypeOf(v)
		for f := range rt.Fields() {
			if f.Type.Kind() == reflect.Bool {
				flags[f.Name] = true
			}
		}
	}

	return flags
}

// advDHCPFieldNames lists the string fields of a common advanced-DHCP struct.
// The common struct is the source of truth for what must be wired: a field added
// there without a matching builder assignment fails the tests below.
func advDHCPFieldNames(v any) []string {
	rt := reflect.TypeOf(v)
	names := make([]string, 0, rt.NumField())

	for f := range rt.Fields() {
		names = append(names, f.Name)
	}

	return names
}

// advDHCPXMLTags resolves each field name to the XML element the schema declares
// for it, so the fixture is generated from the schema rather than from a
// hand-maintained second copy of the element names. A field the common struct
// carries but the schema interface struct does not is a parser-boundary drop:
// the element never survives unmarshaling, so no converter change can recover it.
func advDHCPXMLTags(t *testing.T, ifaceType reflect.Type, fields []string) map[string]string {
	t.Helper()

	tags := make(map[string]string, len(fields))

	for _, name := range fields {
		sf, ok := ifaceType.FieldByName(name)
		require.Truef(t, ok,
			"schema interface struct declares no %s field, so the element is dropped before conversion", name)

		tag, _, _ := strings.Cut(sf.Tag.Get("xml"), ",")
		require.NotEmptyf(t, tag, "%s has no xml element name", name)

		tags[name] = tag
	}

	return tags
}

// advDHCPAssertFields checks every string field against its own sentinel and
// every checkbox against ticked.
func advDHCPAssertFields(t *testing.T, got reflect.Value, fields []string, ticked bool) {
	t.Helper()

	for _, name := range fields {
		field := got.FieldByName(name)

		if field.Kind() == reflect.Bool {
			assert.Equalf(t, ticked, field.Bool(),
				"%s is a checkbox and is unwired or cross-wired in the interface advanced-DHCP builder", name)

			continue
		}

		assert.Equalf(t, advDHCPSentinel(name), field.String(),
			"%s is unwired or cross-wired in the interface advanced-DHCP builder", name)
	}
}

// TestConverter_InterfaceDHCPAdvanced_AllFieldsWired drives XML through the full
// parse -> convert path, so it covers both halves of the gap: the schema must
// declare the element, and the converter must carry it onto the common model.
// The unticked case keeps every other field set, so a checkbox read from any
// element but its own fails there.
func TestConverter_InterfaceDHCPAdvanced_AllFieldsWired(t *testing.T) {
	t.Parallel()

	v4Fields := advDHCPFieldNames(common.InterfaceDHCPAdvancedV4{})
	v6Fields := advDHCPFieldNames(common.InterfaceDHCPAdvancedV6{})
	tags := advDHCPXMLTags(t, reflect.TypeFor[schema.Interface](), slices.Concat(v4Fields, v6Fields))
	flags := advDHCPFlagFields(common.InterfaceDHCPAdvancedV4{}, common.InterfaceDHCPAdvancedV6{})

	tests := []struct {
		name   string
		ticked bool
	}{
		{name: "checkboxes ticked", ticked: true},
		{name: "checkboxes unticked", ticked: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var body strings.Builder

			for _, name := range slices.Concat(v4Fields, v6Fields) {
				switch {
				case flags[name] && tt.ticked:
					fmt.Fprintf(&body, "      <%s>%s</%s>\n", tags[name], advDHCPTickedValue, tags[name])
				case flags[name]:
					fmt.Fprintf(&body, "      <%s/>\n", tags[name])
				default:
					fmt.Fprintf(&body, "      <%s>%s</%s>\n", tags[name], advDHCPSentinel(name), tags[name])
				}
			}

			xmlBody := fmt.Sprintf(advDHCPConfigTemplate, body.String())

			device, _, err := pfsense.NewParser(nil).Parse(context.Background(), strings.NewReader(xmlBody))
			require.NoError(t, err)
			require.Len(t, device.Interfaces, 1)

			iface := device.Interfaces[0]
			require.NotNil(t, iface.DHCPAdvancedV4,
				"advanced DHCPv4 client settings under <interfaces> must be converted")
			require.NotNil(t, iface.DHCPAdvancedV6,
				"advanced DHCPv6 client settings under <interfaces> must be converted")

			advDHCPAssertFields(t, reflect.ValueOf(*iface.DHCPAdvancedV4), v4Fields, tt.ticked)
			advDHCPAssertFields(t, reflect.ValueOf(*iface.DHCPAdvancedV6), v6Fields, tt.ticked)
		})
	}
}

// TestConverter_InterfaceDHCPAdvanced_NilWhenUnset asserts the pointers stay nil
// for the two shapes real configs actually produce: elements absent entirely, and
// elements present but self-closing. testdata/sample.config.5.xml is the latter,
// checkboxes included, since OPNsense writes an unticked box that way too.
func TestConverter_InterfaceDHCPAdvanced_NilWhenUnset(t *testing.T) {
	t.Parallel()

	v4Fields := advDHCPFieldNames(common.InterfaceDHCPAdvancedV4{})
	v6Fields := advDHCPFieldNames(common.InterfaceDHCPAdvancedV6{})
	tags := advDHCPXMLTags(t, reflect.TypeFor[schema.Interface](), slices.Concat(v4Fields, v6Fields))

	var empties strings.Builder

	for _, name := range slices.Concat(v4Fields, v6Fields) {
		fmt.Fprintf(&empties, "      <%s/>\n", tags[name])
	}

	tests := []struct {
		name string
		body string
	}{
		{name: "elements absent", body: ""},
		{name: "elements present but empty", body: empties.String()},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			xmlBody := fmt.Sprintf(advDHCPConfigTemplate, tt.body)

			device, _, err := pfsense.NewParser(nil).Parse(context.Background(), strings.NewReader(xmlBody))
			require.NoError(t, err)
			require.Len(t, device.Interfaces, 1)

			assert.Nil(t, device.Interfaces[0].DHCPAdvancedV4,
				"an all-empty advanced DHCPv4 set must be omitted, not serialized as an empty object")
			assert.Nil(t, device.Interfaces[0].DHCPAdvancedV6,
				"an all-empty advanced DHCPv6 set must be omitted, not serialized as an empty object")
		})
	}
}

// pfsenseInterfaceChildElements returns the distinct element names that appear
// directly under each <interfaces><iface> block in the given config.
func pfsenseInterfaceChildElements(t *testing.T, path string) []string {
	t.Helper()

	f, err := os.Open(path)
	require.NoError(t, err)
	t.Cleanup(func() { _ = f.Close() })

	var (
		stack []string
		seen  = map[string]struct{}{}
	)

	dec := xml.NewDecoder(f)

	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			break
		}

		require.NoError(t, err)

		switch e := tok.(type) {
		case xml.StartElement:
			stack = append(stack, e.Name.Local)
			// root > interfaces > <iface> > element
			if len(stack) == 4 && stack[1] == "interfaces" {
				seen[e.Name.Local] = struct{}{}
			}
		case xml.EndElement:
			stack = stack[:len(stack)-1]
		}
	}

	names := make([]string, 0, len(seen))
	for name := range seen {
		names = append(names, name)
	}

	slices.Sort(names)

	return names
}

// pfsenseAdvDHCPElementFamilies reports whether an <interfaces> child belongs to
// the advanced DHCP client families this test guards.
func pfsenseAdvDHCPElementFamilies(name string) bool {
	switch name {
	case "alias-address", "alias-subnet", "dhcprejectfrom", "track6-interface", "track6-prefix-id":
		return true
	}

	return strings.HasPrefix(name, "adv_dhcp")
}

// TestSchema_Interface_CoversFixtureAdvancedDHCPElements pins the pfSense schema
// against a real config rather than against itself. The sibling tests above build
// their XML from the pfSense struct's own xml tags, so a misspelled tag stays
// self-consistent and passes; the OPNsense side has this same guard, and without
// a twin the pfSense struct was the only one of the pair not checked against
// XML it did not generate.
//
// The fixture is testdata/sample.config.5.xml, an OPNsense config, and that is
// deliberate. No shipped pfSense fixture carries a single adv_dhcp element under
// <interfaces>, so there is nothing pfSense-authored to read. These element names
// originated in pfSense and OPNsense inherited them unchanged, which is why the
// two schema structs declare an identical set of 41 tags; a file written by a
// real firewall is authoritative for the names in a way a fixture written here
// to match the struct could never be. A pfSense typo fails against it exactly as
// an OPNsense typo would.
func TestSchema_Interface_CoversFixtureAdvancedDHCPElements(t *testing.T) {
	t.Parallel()

	fpath := filepath.Join("..", "..", "..", "testdata", "sample.config.5.xml")

	declared := map[string]struct{}{}
	ifaceType := reflect.TypeFor[schema.Interface]()

	for field := range ifaceType.Fields() {
		tag, _, _ := strings.Cut(field.Tag.Get("xml"), ",")
		if tag != "" {
			declared[tag] = struct{}{}
		}
	}

	var found int

	for _, name := range pfsenseInterfaceChildElements(t, fpath) {
		if !pfsenseAdvDHCPElementFamilies(name) {
			continue
		}

		found++

		_, ok := declared[name]
		assert.Truef(t, ok,
			"<%s> appears under <interfaces> in the fixture but the pfSense interface struct does not declare it, "+
				"so it is dropped during unmarshaling", name)
	}

	require.NotZero(
		t,
		found,
		"fixture no longer carries advanced DHCP elements under <interfaces>; this test is vacuous",
	)
}

// TestConverter_InterfaceDHCPAdvancedV6_CheckboxValues pins how the three
// DHCPv6 checkboxes are read. pfSense stores a ticked box as "Selected", the
// value its Form_Checkbox is given, and removes an unticked one; interfaces.inc
// only checks that the element is non-empty. BoolFlag read "Selected" as unset.
// The self-closing case is how OPNsense writes an unticked box, and the element
// names are shared, so it is pinned here too. "x" is no vendor's value: it pins
// that any other non-empty value also reads as ticked.
func TestConverter_InterfaceDHCPAdvancedV6_CheckboxValues(t *testing.T) {
	t.Parallel()

	fields := slices.Sorted(maps.Keys(advDHCPFlagFields(common.InterfaceDHCPAdvancedV6{})))
	tags := advDHCPXMLTags(t, reflect.TypeFor[schema.Interface](), fields)

	require.Len(t, fields, 3, "the DHCPv6 checkbox set changed; review the cases below")

	tests := []struct {
		name  string
		value string // "" writes the element self-closing
	}{
		{name: "ticked", value: advDHCPTickedValue},
		{name: "ticked other value", value: "x"},
		{name: "unticked", value: ""},
	}

	for _, field := range fields {
		for _, tt := range tests {
			t.Run(field+"/"+tt.name, func(t *testing.T) {
				t.Parallel()

				element := fmt.Sprintf("<%s/>", tags[field])
				if tt.value != "" {
					element = fmt.Sprintf("<%[1]s>%[2]s</%[1]s>", tags[field], tt.value)
				}

				xmlBody := fmt.Sprintf(advDHCPConfigTemplate, "      "+element+"\n")

				device, _, err := pfsense.NewParser(nil).Parse(context.Background(), strings.NewReader(xmlBody))
				require.NoError(t, err)
				require.Len(t, device.Interfaces, 1)

				adv := device.Interfaces[0].DHCPAdvancedV6
				if tt.value == "" {
					assert.Nil(t, adv, "an unticked box is the only advanced-DHCPv6 element, so nothing is configured")

					return
				}

				require.NotNil(t, adv,
					"an interface whose only advanced-DHCPv6 setting is a ticked box must still convert")

				for _, other := range fields {
					assert.Equalf(t, other == field, reflect.ValueOf(*adv).FieldByName(other).Bool(),
						"%s is the only box ticked in the config; %s read wrong", field, other)
				}
			})
		}
	}
}
