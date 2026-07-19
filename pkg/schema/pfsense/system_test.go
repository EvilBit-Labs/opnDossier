package pfsense

import (
	"encoding/xml"
	"strings"
	"testing"
)

// TestWebGUI_PortRoundTrip pins the XML round-trip invariant for the pfSense
// WebGUI port field (standards.md "Adding New XML Fields" step 3). pfSense
// stores a custom web-configurator port as <system><webgui><port>; a populated
// port must survive marshal -> unmarshal and an absent port must be omitted
// from the marshaled output rather than emitted as an empty element.
func TestWebGUI_PortRoundTrip(t *testing.T) {
	t.Parallel()

	in := WebGUI{Protocol: "https", Port: "8443"}

	data, err := xml.Marshal(in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(data), "<port>8443</port>") {
		t.Errorf("marshaled XML missing <port>8443</port>: %s", data)
	}

	var out WebGUI
	if err := xml.Unmarshal(data, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if out.Port != "8443" {
		t.Errorf("round-tripped Port = %q, want %q", out.Port, "8443")
	}

	emptyData, err := xml.Marshal(WebGUI{Protocol: "https"})
	if err != nil {
		t.Fatalf("marshal empty: %v", err)
	}
	if strings.Contains(string(emptyData), "<port>") {
		t.Errorf("empty Port must be omitted, got: %s", emptyData)
	}
}
