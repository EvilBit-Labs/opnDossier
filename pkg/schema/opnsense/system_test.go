package opnsense

import (
	"encoding/xml"
	"strings"
	"testing"
)

// TestWebGUIConfig_PortRoundTrip pins the XML round-trip invariant for the
// WebGUI port field (standards.md "Adding New XML Fields" step 3): a populated
// <port> survives marshal -> unmarshal, and an absent port is omitted from
// the marshaled output rather than emitted as an empty element.
func TestWebGUIConfig_PortRoundTrip(t *testing.T) {
	t.Parallel()

	in := WebGUIConfig{Protocol: "https", Port: "8443"}

	data, err := xml.Marshal(in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(data), "<port>8443</port>") {
		t.Errorf("marshaled XML missing <port>8443</port>: %s", data)
	}

	var out WebGUIConfig
	if err := xml.Unmarshal(data, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if out.Port != "8443" {
		t.Errorf("round-tripped Port = %q, want %q", out.Port, "8443")
	}

	// An absent port must be omitted from the marshaled output, so existing
	// config.xml files that lack the element are not given one.
	emptyData, err := xml.Marshal(WebGUIConfig{Protocol: "https"})
	if err != nil {
		t.Fatalf("marshal empty: %v", err)
	}
	if strings.Contains(string(emptyData), "<port>") {
		t.Errorf("empty Port must be omitted, got: %s", emptyData)
	}
}
