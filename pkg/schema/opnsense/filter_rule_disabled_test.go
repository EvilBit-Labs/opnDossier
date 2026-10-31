package opnsense

import (
	"encoding/xml"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRule_Disabled_XMLRoundTrip pins <disabled> on a legacy filter rule
// (standards.md "Adding New XML Fields" step 3). The field keeps the element's
// text because the firewall tests it with !empty(), so the converter has to tell
// an empty element and a 0, which are live rules, from an absent one and from
// other text. A second rule with the opposite shape sits beside the one under
// test, on the path a config takes, so that a shape cannot borrow from a neighbor.
func TestRule_Disabled_XMLRoundTrip(t *testing.T) {
	t.Parallel()

	const (
		neighborAbsent = ""
		neighborSet    = "<disabled>1</disabled>"
	)

	tests := []struct {
		name     string
		element  string
		neighbor string
		want     *string
	}{
		{name: "self-closing element", element: "<disabled/>", neighbor: neighborAbsent, want: new("")},
		{name: "empty element", element: "<disabled></disabled>", neighbor: neighborAbsent, want: new("")},
		{name: "element holding 1", element: neighborSet, neighbor: neighborAbsent, want: new("1")},
		{name: "element holding 0", element: "<disabled>0</disabled>", neighbor: neighborAbsent, want: new("0")},
		{name: "element holding no", element: "<disabled>no</disabled>", neighbor: neighborAbsent, want: new("no")},
		{name: "absent element", element: neighborAbsent, neighbor: neighborSet},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			input := "<filter><rule><type>pass</type>" + tt.neighbor + "</rule>" +
				"<rule><type>pass</type>" + tt.element + "</rule></filter>"

			var filter Filter
			require.NoError(t, xml.Unmarshal([]byte(input), &filter))
			require.Len(t, filter.Rule, 2)
			assert.Equal(t, tt.want, filter.Rule[1].Disabled, "parsed from the vendor shape")

			byPointer, err := xml.Marshal(&filter.Rule[1])
			require.NoError(t, err)

			byValue, err := xml.Marshal(filter.Rule[1])
			require.NoError(t, err)

			for _, data := range [][]byte{byPointer, byValue} {
				var got Rule
				require.NoError(t, xml.Unmarshal(data, &got))
				assert.Equal(t, tt.want, got.Disabled, "after marshal and unmarshal of %s", data)
			}

			written, err := xml.Marshal(&filter)
			require.NoError(t, err)

			var got Filter
			require.NoError(t, xml.Unmarshal(written, &got))
			require.Len(t, got.Rule, 2)
			assert.Equal(t, filter.Rule[0].Disabled, got.Rule[0].Disabled, "neighbor")
			assert.Equal(t, tt.want, got.Rule[1].Disabled, "after a filter round trip")
		})
	}
}
