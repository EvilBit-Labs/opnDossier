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

// TestSystem_IPv6AllowRoundTrip pins the presence semantics of <ipv6allow>
// (standards.md "Adding New XML Fields" step 3): an absent element stays
// absent, and a present one keeps its body, since any body allows IPv6.
func TestSystem_IPv6AllowRoundTrip(t *testing.T) {
	t.Parallel()

	for _, element := range []string{"", "<ipv6allow></ipv6allow>", "<ipv6allow>0</ipv6allow>"} {
		present := element != ""

		var sys System
		if err := xml.Unmarshal([]byte("<system>"+element+"</system>"), &sys); err != nil {
			t.Fatalf("unmarshal %q: %v", element, err)
		}
		if (sys.IPv6Allow != nil) != present {
			t.Errorf("%q: IPv6Allow non-nil = %v, want %v", element, sys.IPv6Allow != nil, present)
		}

		data, err := xml.Marshal(&sys)
		if err != nil {
			t.Fatalf("marshal %q: %v", element, err)
		}
		if strings.Contains(string(data), "<ipv6allow") != present {
			t.Errorf("%q: marshaled element present = %v, want %v: %s", element, !present, present, data)
		}
		if present && !strings.Contains(string(data), element) {
			t.Errorf("%q: body not preserved: %s", element, data)
		}
	}
}
