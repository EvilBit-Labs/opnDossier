package opnsense

import (
	"encoding/xml"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestWebGUIConfig_NoDNSRebindCheck_RoundTrip pins the presence reading of
// <nodnsrebindcheck>: OPNsense tests it with isset(), so the element counts
// whatever it holds, and it must survive a marshal exactly as decoded.
func TestWebGUIConfig_NoDNSRebindCheck_RoundTrip(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		input   string
		wantSet bool
	}{
		{"ticked", `<webgui><protocol>https</protocol><nodnsrebindcheck>1</nodnsrebindcheck></webgui>`, true},
		{"empty element", `<webgui><protocol>https</protocol><nodnsrebindcheck></nodnsrebindcheck></webgui>`, true},
		{"absent", `<webgui><protocol>https</protocol></webgui>`, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var first WebGUIConfig
			require.NoError(t, xml.Unmarshal([]byte(tc.input), &first))
			assert.Equal(t, tc.wantSet, first.NoDNSRebindCheck != nil)

			out, err := xml.Marshal(struct {
				WebGUIConfig

				XMLName xml.Name `xml:"webgui"`
			}{WebGUIConfig: first})
			require.NoError(t, err)

			var second WebGUIConfig
			require.NoError(t, xml.Unmarshal(out, &second))
			assert.Equal(t, first.NoDNSRebindCheck, second.NoDNSRebindCheck)
		})
	}
}
