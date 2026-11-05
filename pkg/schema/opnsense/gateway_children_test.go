package opnsense

import (
	"bytes"
	"encoding/xml"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// gatewayContents is the inside of a <gateway_item> paired with whether
// OPNsense counts it as a child element: SimpleXML's count(), which both
// stores test, counts child elements and nothing else.
var gatewayContents = []struct {
	name    string
	content string
	child   bool
}{
	{name: "self-closing"},
	{name: "whitespace", content: "\n        "},
	{name: "text", content: "x"},
	{name: "comment", content: "<!-- <name>GW</name> -->"},
	{name: "processing instruction", content: "<?pi <name/>?>"},
	{name: "CDATA", content: "<![CDATA[<name>GW</name>]]>"},
	{name: "empty name", content: "<name/>", child: true},
	{name: "empty name, open and close", content: "<name></name>", child: true},
	{name: "disabled 0", content: "<disabled>0</disabled>", child: true},
	{name: "unbound element", content: "<priority>255</priority>", child: true},
	{name: "unbound element nesting another", content: "<x><y/></x>", child: true},
	{name: "comment then empty name", content: "<!-- c --><name/>", child: true},
}

// gatewayItemElement writes a <gateway_item> with the given attributes and
// content, self-closed when the content is empty.
func gatewayItemElement(attrs, content string) string {
	if content == "" {
		return "<gateway_item" + attrs + "/>"
	}

	return "<gateway_item" + attrs + ">" + content + "</gateway_item>"
}

// TestGateway_HasChildElement_BothStores decodes each content in both stores,
// between two named gateways, and checks the record, the predicate, the
// neighbours and the marshaled form. The neighbours catch a decoder that reads
// past the item or loses one; the marshaled form, which must not change with
// the record, catches a record that is encoded.
func TestGateway_HasChildElement_BothStores(t *testing.T) {
	t.Parallel()

	for _, tt := range gatewayContents {
		t.Run("legacy/"+tt.name, legacyGatewayContentCase(tt.content, tt.child))
		t.Run("model/"+tt.name, modelGatewayContentCase(tt.content, tt.child))
	}
}

// legacyGatewayContentCase decodes content as the middle of three items under
// <gateways>, beside a gateway group.
func legacyGatewayContentCase(content string, child bool) func(*testing.T) {
	return func(t *testing.T) {
		t.Parallel()

		const (
			first = "<gateway_item><name>FIRST</name></gateway_item>"
			last  = "<gateway_item><name>LAST</name></gateway_item>"
			group = "<gateway_group><name>GROUP</name><item>FIRST|1</item></gateway_group>"
		)

		doc := decodeGatewayDocument(t, []byte("<opnsense><gateways>"+
			first+gatewayItemElement(` a="b"`, content)+last+group+"</gateways></opnsense>"))

		if groups := doc.Gateways.Groups; len(groups) != 1 || groups[0].Name != "GROUP" {
			t.Errorf("groups changed: %+v", groups)
		}

		items := doc.Gateways.Gateway
		assertMiddleGatewayRecord(t, items, child, func(i int) Gateway { return items[i] })
		assertGatewayRecordNotMarshaled(t, &doc, &doc.Gateways.Gateway[1].HasChildElement)
	}
}

// modelGatewayContentCase decodes content as the middle of three model items,
// each with its own uuid.
func modelGatewayContentCase(content string, child bool) func(*testing.T) {
	return func(t *testing.T) {
		t.Parallel()

		const (
			first = `<gateway_item uuid="u1"><name>FIRST</name></gateway_item>`
			last  = `<gateway_item uuid="u3"><name>LAST</name></gateway_item>`
		)

		doc := decodeGatewayDocument(t, []byte(`<opnsense><OPNsense><Gateways version="1.0.0">`+
			first+gatewayItemElement(` uuid="u2"`, content)+last+
			"</Gateways></OPNsense></opnsense>"))

		items := doc.OPNsense.Gateways.Items
		assertMiddleGatewayRecord(t, items, child, func(i int) Gateway { return items[i].Gateway })

		for i, want := range []string{"u1", "u2", "u3"} {
			if items[i].UUID == nil || *items[i].UUID != want {
				t.Errorf("items[%d].UUID = %v, want %q", i, items[i].UUID, want)
			}
		}

		if got := items[1].IsPlaceholder(); got == child {
			t.Errorf("GatewayModelItem.IsPlaceholder() = %v, want %v", got, !child)
		}

		assertGatewayRecordNotMarshaled(t, &doc, &doc.OPNsense.Gateways.Items[1].HasChildElement)
	}
}

// assertMiddleGatewayRecord checks that items holds the named FIRST and LAST
// gateways around one whose record is child, and that the predicate agrees.
func assertMiddleGatewayRecord[T any](t *testing.T, items []T, child bool, gateway func(int) Gateway) {
	t.Helper()

	if len(items) != 3 || gateway(0).Name != "FIRST" || gateway(2).Name != "LAST" {
		t.Fatalf("neighbours changed: %+v", items)
	}

	if !gateway(0).HasChildElement || !gateway(2).HasChildElement {
		t.Error("a named neighbour lost its record")
	}

	if got := gateway(1).HasChildElement; got != child {
		t.Errorf("HasChildElement = %v, want %v", got, child)
	}

	if got := gateway(1).IsPlaceholder(); got == child {
		t.Errorf("IsPlaceholder() = %v, want %v", got, !child)
	}
}

// assertGatewayRecordNotMarshaled marshals doc with the record at flag set and
// cleared, and fails if the two differ.
func assertGatewayRecordNotMarshaled(t *testing.T, doc *OpnSenseDocument, flag *bool) {
	t.Helper()

	saved := *flag
	defer func() { *flag = saved }()

	marshaled := make([][]byte, 0, 2)
	for _, value := range []bool{true, false} {
		*flag = value

		data, err := xml.Marshal(doc)
		if err != nil {
			t.Fatalf("Marshal failed: %v", err)
		}

		marshaled = append(marshaled, data)
	}

	if !bytes.Equal(marshaled[0], marshaled[1]) {
		t.Errorf("HasChildElement reached the XML:\n%s\n%s", marshaled[0], marshaled[1])
	}
}

// Method-less copies of the containers, which decode the way encoding/xml does
// by default.
type (
	defaultGateways  Gateways
	defaultModelItem GatewayModelItem
)

// gatewayStores is every <gateways> and every model <gateway_item> of a
// document, in document order.
type gatewayStores struct {
	legacy []Gateways
	model  []GatewayModelItem
	blocks int
}

// decodeGatewayStores decodes every <gateways> and every <Gateways> block of
// data, wherever it sits, either through the methods or, with plain, through
// the method-less copies.
func decodeGatewayStores(t *testing.T, data []byte, plain bool) gatewayStores {
	t.Helper()

	decoder := xml.NewDecoder(bytes.NewReader(data))
	decoder.CharsetReader = func(_ string, input io.Reader) (io.Reader, error) {
		return input, nil
	}

	var stores gatewayStores

	for {
		tok, err := decoder.Token()
		if errors.Is(err, io.EOF) {
			return stores
		}

		if err != nil {
			t.Fatalf("Token failed: %v", err)
		}

		start, ok := tok.(xml.StartElement)
		if !ok {
			continue
		}

		if start.Name.Local == "gateways" || start.Name.Local == "Gateways" {
			stores.blocks++
		}

		switch {
		case start.Name.Local == "gateways" && plain:
			var g defaultGateways
			decodeGatewayElement(t, decoder, &start, &g)
			stores.legacy = append(stores.legacy, Gateways(g))
		case start.Name.Local == "gateways":
			var g Gateways
			decodeGatewayElement(t, decoder, &start, &g)
			stores.legacy = append(stores.legacy, g)
		case start.Name.Local == "Gateways" && plain:
			var block struct {
				Items []defaultModelItem `xml:"gateway_item"`
			}
			decodeGatewayElement(t, decoder, &start, &block)

			for _, item := range block.Items {
				stores.model = append(stores.model, GatewayModelItem(item))
			}
		case start.Name.Local == "Gateways":
			var block struct {
				Items []GatewayModelItem `xml:"gateway_item"`
			}
			decodeGatewayElement(t, decoder, &start, &block)
			stores.model = append(stores.model, block.Items...)
		}
	}
}

func decodeGatewayElement(t *testing.T, decoder *xml.Decoder, start *xml.StartElement, v any) {
	t.Helper()

	if err := decoder.DecodeElement(v, start); err != nil {
		t.Fatalf("DecodeElement <%s> failed: %v", start.Name.Local, err)
	}
}

// TestGateways_UnmarshalXML_MatchesTheDefaultDecoder decodes the gateways of
// every shipped config that has any, and of three built ones, through the
// methods and through encoding/xml's default decoding, and requires the same
// values apart from the record. It catches a lost container or item XMLName, a
// second <gateways> that replaces the first instead of adding to it, lost
// gateway groups, and a lost uuid or model <disabled>. The pfSense configs
// decode through the same container.
func TestGateways_UnmarshalXML_MatchesTheDefaultDecoder(t *testing.T) {
	t.Parallel()

	inputs := gatewayDecoderInputs(t)

	for name, data := range inputs {
		t.Run(name, gatewayDecodersAgree(data))
	}

	// The cfgparser decodes every <gateways> into the one document field, and
	// encoding/xml appends to a slice it decodes into again, so the second
	// container adds to the first.
	t.Run("two containers into one value", func(t *testing.T) {
		t.Parallel()

		var got struct {
			Gateways Gateways `xml:"gateways"`
		}

		var want struct {
			Gateways defaultGateways `xml:"gateways"`
		}

		for _, v := range []any{&got, &want} {
			if err := xml.Unmarshal(inputs["two containers"], v); err != nil {
				t.Fatalf("Unmarshal failed: %v", err)
			}
		}

		if len(got.Gateways.Gateway) != 3 || len(got.Gateways.Groups) != 2 {
			t.Fatalf("got %d gateways and %d groups, want 3 and 2", len(got.Gateways.Gateway), len(got.Gateways.Groups))
		}

		for i := range got.Gateways.Gateway {
			got.Gateways.Gateway[i].HasChildElement = false
		}

		if !reflect.DeepEqual(got.Gateways, Gateways(want.Gateways)) {
			t.Errorf("Gateways = %+v, want %+v", got.Gateways, want.Gateways)
		}
	})
}

// gatewayDecoderInputs returns three built inputs and every shipped config that
// holds a gateway store, keyed by name.
func gatewayDecoderInputs(t *testing.T) map[string][]byte {
	t.Helper()

	inputs := map[string][]byte{
		"two containers": []byte("<root><gateways>" +
			"<gateway_item><name>A</name></gateway_item><gateway_group><name>G1</name></gateway_group>" +
			"</gateways><gateways>" +
			"<gateway_item><name>B</name></gateway_item><gateway_item/><gateway_group><name>G2</name></gateway_group>" +
			"</gateways></root>"),
		"empty container": []byte("<root><gateways/></root>"),
		"model block":     []byte("<root><OPNsense>" + gatewayModelBlock + "</OPNsense></root>"),
	}

	for _, pattern := range []string{"*.xml", filepath.Join("pfsense", "*.xml")} {
		paths, err := filepath.Glob(filepath.Join(testdataDir(), pattern))
		if err != nil {
			t.Fatalf("glob: %v", err)
		}

		for _, path := range paths {
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read fixture: %v", err)
			}

			if bytes.Contains(data, []byte("<gateways")) || bytes.Contains(data, []byte("<Gateways")) {
				inputs[filepath.Base(filepath.Dir(path))+"/"+filepath.Base(path)] = data
			}
		}
	}

	// The fixtures that must be among the inputs, so that a moved testdata
	// directory cannot leave the test with nothing but the built inputs.
	for _, want := range []string{
		"testdata/sample.config.4.xml",
		"testdata/sample.config.5.xml",
		"pfsense/config-2.7.x.xml",
	} {
		if _, ok := inputs[want]; !ok {
			t.Fatalf("fixture %s not found among %d inputs", want, len(inputs))
		}
	}

	return inputs
}

// gatewayDecodersAgree decodes data through the methods and through the
// default decoder and requires the same values apart from the record.
func gatewayDecodersAgree(data []byte) func(*testing.T) {
	return func(t *testing.T) {
		t.Parallel()

		got := decodeGatewayStores(t, data, false)
		want := decodeGatewayStores(t, data, true)

		if got.blocks == 0 || got.blocks != want.blocks {
			t.Fatalf("decoded %d gateway stores, and %d by default", got.blocks, want.blocks)
		}

		for i := range got.legacy {
			for j := range got.legacy[i].Gateway {
				got.legacy[i].Gateway[j].HasChildElement = false
			}
		}

		for i := range got.model {
			got.model[i].HasChildElement = false
		}

		if !reflect.DeepEqual(got.legacy, want.legacy) {
			t.Errorf("legacy store = %+v, want %+v", got.legacy, want.legacy)
		}

		if !reflect.DeepEqual(got.model, want.model) {
			t.Errorf("model store = %+v, want %+v", got.model, want.model)
		}
	}
}

// TestGateway_HasNoXMLCodec pins that Gateway has neither an UnmarshalXML nor
// a MarshalXML. GatewayModelItem embeds it, so either would be promoted: an
// UnmarshalXML would decode a model item without its uuid and its <disabled>,
// a MarshalXML would write it without them, and decodeGatewayItem, which
// decodes into a *Gateway, would call the UnmarshalXML again.
func TestGateway_HasNoXMLCodec(t *testing.T) {
	t.Parallel()

	for _, typ := range []reflect.Type{reflect.TypeFor[Gateway](), reflect.TypeFor[*Gateway]()} {
		if typ.Implements(reflect.TypeFor[xml.Unmarshaler]()) {
			t.Errorf("%s implements xml.Unmarshaler", typ)
		}

		if typ.Implements(reflect.TypeFor[xml.Marshaler]()) {
			t.Errorf("%s implements xml.Marshaler", typ)
		}
	}
}

// TestGateways_UnmarshalXML_KeepsTheSyntaxError pins that a malformed item
// fails the decode with the error and line of the decoder that read it, which
// the parsers wrap with the element path.
func TestGateways_UnmarshalXML_KeepsTheSyntaxError(t *testing.T) {
	t.Parallel()

	for name, data := range map[string]string{
		"legacy": "<opnsense>\n<gateways>\n<gateway_item>\n<name>GW</nam>\n</gateway_item>\n</gateways>\n</opnsense>",
		"model": "<opnsense>\n<OPNsense>\n<Gateways>\n<gateway_item uuid=\"u1\">\n<name>GW</nam>\n" +
			"</gateway_item>\n</Gateways>\n</OPNsense>\n</opnsense>",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			var doc OpnSenseDocument

			err := xml.NewDecoder(strings.NewReader(data)).Decode(&doc)

			var syntax *xml.SyntaxError
			if !errors.As(err, &syntax) {
				t.Fatalf("err = %v, want an *xml.SyntaxError", err)
			}

			end := strings.Index(data, "</nam>")
			if end < 0 {
				t.Fatal("the input has no </nam>")
			}

			if want := strings.Count(data[:end], "\n") + 1; syntax.Line != want {
				t.Errorf("Line = %d, want %d", syntax.Line, want)
			}
		})
	}
}
