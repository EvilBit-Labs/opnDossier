package pfsense_test

import (
	"bytes"
	"context"
	"os"
	"testing"

	"github.com/EvilBit-Labs/opnDossier/pkg/parser/pfsense"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestConverter_IPv6Allow_PresenceToggle pins how pfSense stores "Allow IPv6":
// xmlparse.inc writes true as an empty element, and the readers use isset().
func TestConverter_IPv6Allow_PresenceToggle(t *testing.T) {
	t.Parallel()

	raw, err := os.ReadFile("../../../testdata/pfsense/config-pfSense.xml")
	require.NoError(t, err)

	empty := []byte("<ipv6allow></ipv6allow>")
	require.Equal(t, 1, bytes.Count(raw, empty), "fixture no longer carries an empty <ipv6allow>")

	tests := []struct {
		name    string
		element string
		want    bool
	}{
		{name: "empty element", element: "<ipv6allow></ipv6allow>", want: true},
		{name: "element with a false-looking value", element: "<ipv6allow>0</ipv6allow>", want: true},
		{name: "element absent", element: "", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			device, _, err := pfsense.NewParser(nil).Parse(
				context.Background(), bytes.NewReader(bytes.Replace(raw, empty, []byte(tt.element), 1)))
			require.NoError(t, err)
			assert.Equal(t, tt.want, device.System.IPv6Allow)
		})
	}
}
