package opnsense_test

import (
	"bytes"
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

	"github.com/EvilBit-Labs/opnDossier/internal/cfgparser"
	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
	"github.com/EvilBit-Labs/opnDossier/pkg/parser"
	schema "github.com/EvilBit-Labs/opnDossier/pkg/schema/opnsense"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// advDHCPConfigTemplate wraps a generated <lan> body. Advanced DHCP *client*
// settings live under <interfaces>, not under <dhcpd>; see
// testdata/sample.config.5.xml, which carries the whole set under <interfaces>.
const advDHCPConfigTemplate = `<?xml version="1.0"?>
<opnsense>
  <system>
    <hostname>fw</hostname>
    <domain>example.com</domain>
  </system>
  <interfaces>
    <lan>
      <if>vtnet0</if>
%s    </lan>
  </interfaces>
</opnsense>`

// advDHCPSentinel returns a value unique to the field, so a builder that reads
// the wrong source field produces a mismatch rather than an accidental pass.
func advDHCPSentinel(field string) string { return "sentinel-" + field }

// advDHCPTickedValue is what OPNsense 16.1 and later store for a ticked
// checkbox: the form input has no value attribute, so the browser posts "on".
const advDHCPTickedValue = "on"

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

			device, _, err := parser.NewFactory(cfgparser.NewXMLParser()).CreateDevice(
				context.Background(), strings.NewReader(xmlBody), common.DeviceTypeUnknown, false,
			)
			require.NoError(t, err)
			require.NotNil(t, device)
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
// checkboxes included, since an unticked box is written that way too.
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

			device, _, err := parser.NewFactory(cfgparser.NewXMLParser()).CreateDevice(
				context.Background(), strings.NewReader(xmlBody), common.DeviceTypeUnknown, false,
			)
			require.NoError(t, err)
			require.NotNil(t, device)
			require.Len(t, device.Interfaces, 1)

			assert.Nil(t, device.Interfaces[0].DHCPAdvancedV4,
				"an all-empty advanced DHCPv4 set must be omitted, not serialized as an empty object")
			assert.Nil(t, device.Interfaces[0].DHCPAdvancedV6,
				"an all-empty advanced DHCPv6 set must be omitted, not serialized as an empty object")
		})
	}
}

// advDHCPElementFamilies matches the element names that carry advanced DHCP
// client settings on an interface. The adv_dhcp/adv_dhcp6 prefixes cover most of
// them; the rest are spelled without a shared prefix.
func advDHCPElementFamilies(name string) bool {
	switch name {
	case "alias-address", "alias-subnet", "dhcprejectfrom", "track6-interface", "track6-prefix-id":
		return true
	}

	return strings.HasPrefix(name, "adv_dhcp")
}

// interfaceChildElements returns the distinct element names appearing as direct
// children of an <interfaces><*> entry in the given config file.
func interfaceChildElements(t *testing.T, path string) []string {
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

// TestSchema_Interface_CoversFixtureAdvancedDHCPElements pins the schema against a
// real config rather than against itself. The sibling tests above generate their
// fixture from the schema's own xml tags, so a wrong element name would pass them;
// this one reads the element names OPNsense actually writes.
//
// It is the regression guard for the original gap: before the advanced DHCP client
// fields were added, the interface struct declared 5 of the 41 elements that
// testdata/sample.config.5.xml carries under <interfaces>, and the other 36 were
// discarded during unmarshaling.
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

	for _, name := range interfaceChildElements(t, fpath) {
		if !advDHCPElementFamilies(name) {
			continue
		}

		found++

		_, ok := declared[name]
		assert.Truef(t, ok,
			"<%s> appears under <interfaces> in the fixture but the schema interface struct does not declare it, "+
				"so it is dropped during unmarshaling", name)
	}

	require.NotZero(
		t,
		found,
		"fixture no longer carries advanced DHCP elements under <interfaces>; this test is vacuous",
	)
}

// TestConverter_InterfaceDHCPAdvancedV6_CheckboxValues pins how the three
// DHCPv6 checkboxes are read. OPNsense 16.1 and later store a ticked box as
// "on", 15.x stored "Selected", and releases through 26.7.4 write an unticked
// one as a self-closing element. BoolFlag read "Selected" as unset and the
// self-closing form as set, so every DHCPv6 interface saved from the GUI by
// those releases reported all three boxes ticked. "x" is no vendor's value: it
// pins that any other non-empty value also reads as ticked.
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
		{name: "ticked by 15.x", value: "Selected"},
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

				device, _, err := parser.NewFactory(cfgparser.NewXMLParser()).CreateDevice(
					context.Background(), strings.NewReader(xmlBody), common.DeviceTypeUnknown, false,
				)
				require.NoError(t, err)
				require.NotNil(t, device)
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

// emptyInterfaceChildren returns the elements directly under
// <interfaces><iface> that have no content. encoding/xml reports <a/> and
// <a></a> alike, so this finds empty elements, not self-closing ones as such.
func emptyInterfaceChildren(t *testing.T, raw []byte, iface string) map[string]bool {
	t.Helper()

	var (
		stack []string
		open  string
		empty = map[string]bool{}
	)

	dec := xml.NewDecoder(bytes.NewReader(raw))

	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			break
		}

		require.NoError(t, err)

		switch e := tok.(type) {
		case xml.StartElement:
			stack = append(stack, e.Name.Local)
			open = ""
			// root > interfaces > iface > element
			if len(stack) == 4 && stack[1] == "interfaces" && stack[2] == iface {
				open = e.Name.Local
			}
		case xml.EndElement:
			if open != "" {
				empty[open] = true
			}

			open = ""
			stack = stack[:len(stack)-1]
		default:
			open = ""
		}
	}

	return empty
}

// TestConverter_SampleConfig5_UntickedCheckboxesNotReported reads a config an
// OPNsense firewall wrote rather than XML generated from the schema. Its lan
// interface uses DHCPv6 and carries every advanced-DHCPv6 element self-closing,
// the three checkboxes included, which is how releases through 26.7.4 save the
// page with nothing set. Under BoolFlag this reported all three boxes ticked.
func TestConverter_SampleConfig5_UntickedCheckboxesNotReported(t *testing.T) {
	t.Parallel()

	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "testdata", "sample.config.5.xml"))
	require.NoError(t, err)

	tags := advDHCPXMLTags(t, reflect.TypeFor[schema.Interface](),
		slices.Sorted(maps.Keys(advDHCPFlagFields(common.InterfaceDHCPAdvancedV6{}))))
	empty := emptyInterfaceChildren(t, raw, "lan")

	for _, tag := range tags {
		require.Truef(t, empty[tag], "fixture lan no longer carries an empty <%s>; this test is vacuous", tag)
	}

	device, _, err := parser.NewFactory(cfgparser.NewXMLParser()).CreateDevice(
		context.Background(), bytes.NewReader(raw), common.DeviceTypeUnknown, false,
	)
	require.NoError(t, err)
	require.NotNil(t, device)

	idx := slices.IndexFunc(device.Interfaces, func(i common.Interface) bool { return i.Name == "lan" })
	require.NotEqual(t, -1, idx, "fixture no longer has a lan interface; this test is vacuous")

	assert.Nil(t, device.Interfaces[idx].DHCPAdvancedV6,
		"every advanced-DHCPv6 element on lan is empty, so no box is ticked and nothing is configured")
}
