package opnsense

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
)

// gatewayModelBlock is an <OPNsense><Gateways> block as OPNsense 24.1 migration
// M1_0_0 stores it, in the field order of Routing/Gateways.xml: every field is
// written, and an unset one is self-closed. Gateway binds neither the uuid
// attribute nor the elements it has no field for, so those do not come back.
const gatewayModelBlock = `<Gateways version="1.0.0">
      <gateway_item uuid="7f3c2a1e-5b6d-4e8f-9a0b-1c2d3e4f5a6b">
        <disabled>0</disabled>
        <name>WAN_GW</name>
        <descr>Interface WAN Gateway</descr>
        <interface>wan</interface>
        <ipprotocol>inet</ipprotocol>
        <gateway>192.0.2.1</gateway>
        <defaultgw>1</defaultgw>
        <fargw>0</fargw>
        <monitor_disable>1</monitor_disable>
        <monitor_noroute>0</monitor_noroute>
        <monitor/>
        <force_down>0</force_down>
        <priority>255</priority>
        <weight>1</weight>
        <latencylow/>
        <latencyhigh/>
        <losslow/>
        <losshigh/>
        <interval>1</interval>
        <time_period/>
        <loss_interval/>
        <data_length/>
      </gateway_item>
      <gateway_item uuid="0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d">
        <disabled>1</disabled>
        <name>WAN_GWv6</name>
        <descr>Interface WAN Gateway IPv6</descr>
        <interface>wan</interface>
        <ipprotocol>inet6</ipprotocol>
        <gateway>2001:db8::1</gateway>
        <defaultgw>0</defaultgw>
        <fargw>1</fargw>
        <monitor_disable>0</monitor_disable>
        <monitor_noroute>0</monitor_noroute>
        <monitor>2001:db8::53</monitor>
        <force_down>0</force_down>
        <priority>254</priority>
        <weight>2</weight>
        <latencylow/>
        <latencyhigh/>
        <losslow/>
        <losshigh/>
        <interval>2</interval>
        <time_period/>
        <loss_interval/>
        <data_length/>
      </gateway_item>
    </Gateways>`

// decodeGatewayDocument decodes a config into the document type. Two fixtures
// declare us-ascii, which encoding/xml refuses without a CharsetReader.
func decodeGatewayDocument(t *testing.T, data []byte) OpnSenseDocument {
	t.Helper()

	decoder := xml.NewDecoder(bytes.NewReader(data))
	decoder.CharsetReader = func(_ string, input io.Reader) (io.Reader, error) {
		return input, nil
	}

	var doc OpnSenseDocument
	if err := decoder.Decode(&doc); err != nil {
		t.Fatalf("decode failed: %v", err)
	}

	return doc
}

// remarshalGatewayDocument marshals doc and returns the result decoded again,
// along with the XML it wrote.
//
//nolint:gocritic // unnamedResult retained; project-wide nonamedreturns disables the typical fix.
func remarshalGatewayDocument(t *testing.T, doc *OpnSenseDocument) (OpnSenseDocument, string) {
	t.Helper()

	data, err := xml.Marshal(doc)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	return decodeGatewayDocument(t, data), string(data)
}

// TestStaticRoute_IsPlaceholder_ReportsTrueOnlyWhenEveryFieldIsZero covers the
// empty-<route/> guard. OPNsense writes a self-closing placeholder inside
// <staticroutes> when no route is configured, and the predicate must recognize
// it while retaining any entry that carries data -- including one that is only a
// disabled marker.
func TestStaticRoute_IsPlaceholder_ReportsTrueOnlyWhenEveryFieldIsZero(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		route StaticRoute
		want  bool
	}{
		{name: "zero value is a placeholder", route: StaticRoute{}, want: true},
		{name: "description only is retained", route: StaticRoute{Descr: "to branch office"}, want: false},
		{name: "network only is retained", route: StaticRoute{Network: "10.0.0.0/8"}, want: false},
		{name: "gateway only is retained", route: StaticRoute{Gateway: "WAN_GW"}, want: false},
		{name: "disabled marker alone is retained", route: StaticRoute{Disabled: BoolFlag(true)}, want: false},
		{name: "created timestamp alone is retained", route: StaticRoute{Created: "1700000000"}, want: false},
		{name: "updated timestamp alone is retained", route: StaticRoute{Updated: "1700000000"}, want: false},
		{
			name:  "fully populated is retained",
			route: StaticRoute{Network: "10.0.0.0/8", Gateway: "WAN_GW", Descr: "branch"},
			want:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.route.IsPlaceholder(); got != tt.want {
				t.Errorf("IsPlaceholder() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestGateway_IsPlaceholder_DecodedEmptyElement_ReportsPlaceholder pins, for
// <gateway_item/>, why the predicate compares named fields, and that the
// attribute a model item carries does not make it configured.
func TestGateway_IsPlaceholder_DecodedEmptyElement_ReportsPlaceholder(t *testing.T) {
	t.Parallel()

	for _, element := range []string{`<gateway_item/>`, `<gateway_item uuid="7f3c2a1e"></gateway_item>`} {
		var got Gateway
		if err := xml.Unmarshal([]byte(element), &got); err != nil {
			t.Fatalf("Unmarshal failed: %v", err)
		}

		if got == (Gateway{}) {
			t.Fatal("decoded element equals Gateway{}; the XMLName premise for IsPlaceholder no longer holds")
		}

		if !got.IsPlaceholder() {
			t.Errorf("decoded %s must be reported as a placeholder", element)
		}
	}
}

// TestGateway_MonitorDisable_KeepsAbsentApartFromEmpty pins the distinction the
// field is a pointer for, and the text MonitorDisableValue reads from each.
func TestGateway_MonitorDisable_KeepsAbsentApartFromEmpty(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		element   string
		wantIsNil bool
		wantValue string
	}{
		{name: "absent", element: `<gateway_item><name>GW</name></gateway_item>`, wantIsNil: true},
		{name: "self-closing", element: `<gateway_item><monitor_disable/></gateway_item>`},
		{name: "empty", element: `<gateway_item><monitor_disable></monitor_disable></gateway_item>`},
		{
			name:      "set",
			element:   `<gateway_item><monitor_disable>1</monitor_disable></gateway_item>`,
			wantValue: "1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var got Gateway
			if err := xml.Unmarshal([]byte(tt.element), &got); err != nil {
				t.Fatalf("Unmarshal failed: %v", err)
			}

			if isNil := got.MonitorDisable == nil; isNil != tt.wantIsNil {
				t.Errorf("MonitorDisable == nil is %v, want %v", isNil, tt.wantIsNil)
			}

			if value := got.MonitorDisableValue(); value != tt.wantValue {
				t.Errorf("MonitorDisableValue() = %q, want %q", value, tt.wantValue)
			}
		})
	}
}

// TestGateway_MonitorDisable_XMLRoundTrip pins absent apart from empty through
// marshal and unmarshal in both stores (standards.md "Adding New XML Fields"
// step 3). The model reads an absent element as set and an empty one as unset,
// so a round trip that merged the two would change whether a gateway is
// monitored.
func TestGateway_MonitorDisable_XMLRoundTrip(t *testing.T) {
	t.Parallel()

	const emptyElement = `<monitor_disable></monitor_disable>`

	stores := []struct {
		name     string
		template string
		items    func(doc *OpnSenseDocument) []Gateway
	}{
		{
			name:     "legacy store",
			template: `<opnsense><gateways><gateway_item><name>GW</name>%s</gateway_item></gateways></opnsense>`,
			items:    func(doc *OpnSenseDocument) []Gateway { return doc.Gateways.Gateway },
		},
		{
			name: "model store",
			template: `<opnsense><OPNsense><Gateways version="1.0.0">` +
				`<gateway_item uuid="7f3c2a1e"><name>GW</name>%s</gateway_item>` +
				`</Gateways></OPNsense></opnsense>`,
			items: func(doc *OpnSenseDocument) []Gateway { return doc.OPNsense.Gateways.Items },
		},
	}

	forms := []struct {
		name      string
		element   string
		wantIsNil bool
		wantValue string
		wantXML   string
	}{
		{name: "absent", wantIsNil: true},
		{name: "self-closing", element: `<monitor_disable/>`, wantXML: emptyElement},
		{name: "empty", element: emptyElement, wantXML: emptyElement},
		{
			name:      "zero",
			element:   `<monitor_disable>0</monitor_disable>`,
			wantValue: "0",
			wantXML:   `<monitor_disable>0</monitor_disable>`,
		},
		{
			name:      "set",
			element:   `<monitor_disable>1</monitor_disable>`,
			wantValue: "1",
			wantXML:   `<monitor_disable>1</monitor_disable>`,
		},
	}

	for _, store := range stores {
		for _, form := range forms {
			t.Run(store.name+" "+form.name, func(t *testing.T) {
				t.Parallel()

				doc := decodeGatewayDocument(t, fmt.Appendf(nil, store.template, form.element))
				back, marshaled := remarshalGatewayDocument(t, &doc)

				for _, items := range [][]Gateway{store.items(&doc), store.items(&back)} {
					if len(items) != 1 {
						t.Fatalf("got %d gateways, want 1", len(items))
					}

					if isNil := items[0].MonitorDisable == nil; isNil != form.wantIsNil {
						t.Errorf("MonitorDisable == nil is %v, want %v", isNil, form.wantIsNil)
					}

					if value := items[0].MonitorDisableValue(); value != form.wantValue {
						t.Errorf("MonitorDisableValue() = %q, want %q", value, form.wantValue)
					}
				}

				if present := strings.Contains(marshaled, "<monitor_disable"); present == form.wantIsNil {
					t.Errorf("marshaled element present = %v, want %v: %s", present, !form.wantIsNil, marshaled)
				}

				if !strings.Contains(marshaled, form.wantXML) {
					t.Errorf("marshaled XML lacks %s: %s", form.wantXML, marshaled)
				}
			})
		}
	}
}

// TestOPNsense_GatewayModel_XMLRoundTrip pins the version attribute and the
// gateway_item children of the model block. The block is an anonymous struct,
// so it is marshaled through the document that holds it. Decoding from the
// vendor's XML and comparing with written-out values keeps a renamed tag from
// passing: it would round-trip with itself.
func TestOPNsense_GatewayModel_XMLRoundTrip(t *testing.T) {
	t.Parallel()

	want := []Gateway{
		{
			XMLName:        xml.Name{Local: "gateway_item"},
			Name:           "WAN_GW",
			Descr:          "Interface WAN Gateway",
			Interface:      "wan",
			IPProtocol:     "inet",
			Gateway:        "192.0.2.1",
			DefaultGW:      "1",
			FarGW:          "0",
			MonitorDisable: new("1"),
			Weight:         "1",
			Interval:       "1",
		},
		{
			XMLName:        xml.Name{Local: "gateway_item"},
			Disabled:       true,
			Name:           "WAN_GWv6",
			Descr:          "Interface WAN Gateway IPv6",
			Interface:      "wan",
			IPProtocol:     "inet6",
			Gateway:        "2001:db8::1",
			DefaultGW:      "0",
			FarGW:          "1",
			MonitorDisable: new("0"),
			Monitor:        "2001:db8::53",
			Weight:         "2",
			Interval:       "2",
		},
	}

	doc := decodeGatewayDocument(t, []byte("<opnsense><OPNsense>"+gatewayModelBlock+"</OPNsense></opnsense>"))
	back, marshaled := remarshalGatewayDocument(t, &doc)

	for _, got := range []*OpnSenseDocument{&doc, &back} {
		if version := got.OPNsense.Gateways.Version; version != "1.0.0" {
			t.Errorf("Version = %q, want %q", version, "1.0.0")
		}

		if !reflect.DeepEqual(got.OPNsense.Gateways.Items, want) {
			t.Errorf("Items = %+v, want %+v", got.OPNsense.Gateways.Items, want)
		}

		// The two stores share the element name, not the data.
		if legacy := got.Gateways.Gateway; len(legacy) != 0 {
			t.Errorf("model items reached the legacy store: %+v", legacy)
		}
	}

	for _, element := range []string{
		`<Gateways version="1.0.0">`,
		`<monitor_disable>1</monitor_disable>`,
		`<monitor_disable>0</monitor_disable>`,
		`<disabled></disabled>`,
	} {
		if !strings.Contains(marshaled, element) {
			t.Errorf("marshaled XML lacks %s: %s", element, marshaled)
		}
	}

	if count := strings.Count(marshaled, "<gateway_item"); count != len(want) {
		t.Errorf("marshaled %d <gateway_item> elements, want %d: %s", count, len(want), marshaled)
	}
}

// TestOPNsense_GatewayModel_NoGateways_XMLRoundTrip covers a model that holds no
// gateway. The converter falls back to <gateways> for it, so its version must
// come back, and a placeholder item must still read as one.
func TestOPNsense_GatewayModel_NoGateways_XMLRoundTrip(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		block       string
		wantVersion string
		wantItems   int
	}{
		{name: "no block"},
		{name: "self-closing block", block: `<Gateways version="1.0.0"/>`, wantVersion: "1.0.0"},
		{name: "23.7 block", block: `<Gateways version="0.0.1"/>`, wantVersion: "0.0.1"},
		{
			name:        "placeholder item",
			block:       `<Gateways version="1.0.0"><gateway_item/></Gateways>`,
			wantVersion: "1.0.0",
			wantItems:   1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			doc := decodeGatewayDocument(t, []byte("<opnsense><OPNsense>"+tt.block+"</OPNsense></opnsense>"))
			back, _ := remarshalGatewayDocument(t, &doc)

			model := back.OPNsense.Gateways
			if model.Version != tt.wantVersion {
				t.Errorf("Version = %q, want %q", model.Version, tt.wantVersion)
			}

			if len(model.Items) != tt.wantItems {
				t.Fatalf("got %d items, want %d", len(model.Items), tt.wantItems)
			}

			for _, item := range model.Items {
				if !item.IsPlaceholder() {
					t.Errorf("item must still be a placeholder: %+v", item)
				}
			}
		})
	}
}

// TestGateways_Disabled_XMLRoundTrip pins GOTCHAS 15.1 for the <gateways>
// container. (*BoolFlag).MarshalXML is only reached on an addressable value,
// and a slice element is one even when the container is marshaled by value.
func TestGateways_Disabled_XMLRoundTrip(t *testing.T) {
	t.Parallel()

	const in = `<gateways><gateway_item><name>GW</name><disabled>1</disabled></gateway_item></gateways>`

	var gateways Gateways
	if err := xml.Unmarshal([]byte(in), &gateways); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	tests := []struct {
		name  string
		value any
	}{
		{name: "by pointer", value: &gateways},
		{name: "by value", value: gateways},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			data, err := xml.Marshal(tt.value)
			if err != nil {
				t.Fatalf("Marshal failed: %v", err)
			}

			if !strings.Contains(string(data), `<disabled></disabled>`) {
				t.Errorf("marshaled XML lacks the presence form: %s", data)
			}

			var back Gateways
			if err := xml.Unmarshal(data, &back); err != nil {
				t.Fatalf("Unmarshal failed: %v", err)
			}

			if len(back.Gateway) != 1 || !bool(back.Gateway[0].Disabled) {
				t.Errorf("Disabled did not come back: %+v", back.Gateway)
			}
		})
	}
}

// TestGateways_Fixtures_XMLRoundTrip drives both stores of the shipped configs
// through marshal and unmarshal. The written-out values tie the comparison to
// the vendor's element names.
func TestGateways_Fixtures_XMLRoundTrip(t *testing.T) {
	t.Parallel()

	tests := []struct {
		fixture            string
		wantModelVersion   string
		wantMonitorDisable []string
	}{
		{fixture: "sample.config.2.xml", wantMonitorDisable: []string{"1"}},
		{fixture: "sample.config.4.xml", wantMonitorDisable: []string{"1"}},
		{fixture: "sample.config.5.xml", wantModelVersion: "1.0.0"},
		{fixture: "gateway_groups_test.xml", wantMonitorDisable: []string{"0", "0"}},
	}

	for _, tt := range tests {
		t.Run(tt.fixture, func(t *testing.T) {
			t.Parallel()

			data, err := os.ReadFile(filepath.Join(testdataDir(), tt.fixture))
			if err != nil {
				t.Fatalf("read fixture: %v", err)
			}

			doc := decodeGatewayDocument(t, data)
			back, _ := remarshalGatewayDocument(t, &doc)

			// Not the whole struct: encoding/xml writes a struct field even
			// when it is empty, so a config with no <gateways> gains an empty
			// one, and with it an XMLName.
			if !reflect.DeepEqual(back.Gateways.Gateway, doc.Gateways.Gateway) {
				t.Errorf("gateways changed: got %+v, want %+v", back.Gateways.Gateway, doc.Gateways.Gateway)
			}

			if !reflect.DeepEqual(back.Gateways.Groups, doc.Gateways.Groups) {
				t.Errorf("gateway groups changed: got %+v, want %+v", back.Gateways.Groups, doc.Gateways.Groups)
			}

			if !reflect.DeepEqual(back.OPNsense.Gateways, doc.OPNsense.Gateways) {
				t.Errorf("model changed: got %+v, want %+v", back.OPNsense.Gateways, doc.OPNsense.Gateways)
			}

			if version := back.OPNsense.Gateways.Version; version != tt.wantModelVersion {
				t.Errorf("Version = %q, want %q", version, tt.wantModelVersion)
			}

			texts := make([]string, 0, len(back.Gateways.Gateway))
			for _, gw := range back.Gateways.Gateway {
				texts = append(texts, gw.MonitorDisableValue())
			}

			if !slices.Equal(texts, tt.wantMonitorDisable) {
				t.Errorf("<monitor_disable> texts = %q, want %q", texts, tt.wantMonitorDisable)
			}
		})
	}
}

// TestStaticRoute_IsPlaceholder_DecodedEmptyElement_ReportsPlaceholder pins the
// reason the predicate compares named fields instead of the zero value:
// encoding/xml populates XMLName on unmarshal, so a decoded <route/> is never
// equal to StaticRoute{}.
func TestStaticRoute_IsPlaceholder_DecodedEmptyElement_ReportsPlaceholder(t *testing.T) {
	t.Parallel()

	var got StaticRoute
	if err := xml.Unmarshal([]byte(`<route/>`), &got); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if got == (StaticRoute{}) {
		t.Fatal("decoded <route/> equals StaticRoute{}; the XMLName premise for IsPlaceholder no longer holds")
	}

	if !got.IsPlaceholder() {
		t.Error("decoded <route/> must be reported as a placeholder")
	}
}
