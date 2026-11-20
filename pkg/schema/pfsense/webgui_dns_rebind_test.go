package pfsense

import (
	"encoding/xml"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestWebGUI_NoDNSRebindCheck_RoundTrip pins the presence reading of
// <nodnsrebindcheck>. pfSense writes the element empty and tests it with
// config_path_enabled(), so an empty element is set and an absent one is not.
func TestWebGUI_NoDNSRebindCheck_RoundTrip(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		input   string
		wantSet bool
	}{
		{"empty element", `<webgui><protocol>https</protocol><nodnsrebindcheck></nodnsrebindcheck></webgui>`, true},
		{"absent", `<webgui><protocol>https</protocol></webgui>`, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var first WebGUI
			require.NoError(t, xml.Unmarshal([]byte(tc.input), &first))
			assert.Equal(t, tc.wantSet, first.NoDNSRebindCheck != nil)

			out, err := xml.Marshal(struct {
				WebGUI

				XMLName xml.Name `xml:"webgui"`
			}{WebGUI: first})
			require.NoError(t, err)

			var second WebGUI
			require.NoError(t, xml.Unmarshal(out, &second))
			assert.Equal(t, first.NoDNSRebindCheck, second.NoDNSRebindCheck)
		})
	}
}
