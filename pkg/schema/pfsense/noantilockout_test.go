package pfsense

import (
	"encoding/xml"
	"testing"
)

// TestWebGUI_NoAntiLockoutPresence pins how <noantilockout> decodes and is
// written back (standards.md "Adding New XML Fields" step 3). The firewall tests
// the element with isset(), so it is a presence field: an empty element turns
// the rule off as the page's value does, and an absent one must not be invented
// on the way out.
func TestWebGUI_NoAntiLockoutPresence(t *testing.T) {
	t.Parallel()

	written := map[string]string{
		"<webgui><protocol>https</protocol></webgui>": "<webgui><protocol>https</protocol></webgui>",
		"<webgui><protocol>https</protocol><noantilockout/></webgui>": "<webgui><protocol>https</protocol>" +
			"<noantilockout></noantilockout></webgui>",
		"<webgui><protocol>https</protocol><noantilockout>1</noantilockout></webgui>": "<webgui><protocol>https</protocol>" +
			"<noantilockout>1</noantilockout></webgui>",
	}

	for in, want := range written {
		var gui WebGUI
		if err := xml.Unmarshal([]byte(in), &gui); err != nil {
			t.Fatalf("%s: %v", in, err)
		}

		if set := gui.NoAntiLockout != nil; set != (in != "<webgui><protocol>https</protocol></webgui>") {
			t.Errorf("%s: NoAntiLockout set = %v", in, set)
		}

		// The type carries no element name of its own; the vendor writes it
		// as <webgui>.
		out, err := xml.Marshal(struct {
			*WebGUI

			XMLName xml.Name `xml:"webgui"`
		}{WebGUI: &gui})
		if err != nil {
			t.Fatalf("%s: %v", in, err)
		}

		if string(out) != want {
			t.Errorf("%s: written back as %s, want %s", in, out, want)
		}
	}
}
