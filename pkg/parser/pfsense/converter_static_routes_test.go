package pfsense_test

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/EvilBit-Labs/opnDossier/pkg/parser/pfsense"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestConverter_StaticRoutes_DisabledFromXML drives a route's state through the
// full parser. pfSense shares the OPNsense route type, so the type also binds
// <enabled>, which pfSense does not write and its get_staticroutes (util.inc)
// does not read: only <disabled> sets the state here, however OPNsense reads the
// same route.
func TestConverter_StaticRoutes_DisabledFromXML(t *testing.T) {
	t.Parallel()

	const configTemplate = `<?xml version="1.0"?>
<pfsense>
  <system><hostname>fw</hostname><domain>example.com</domain></system>
  <staticroutes>%s</staticroutes>
</pfsense>`

	tests := []struct {
		name   string
		routes []string
		want   []bool
	}{
		{
			name:   "an empty disabled, self-closed or not, is set",
			routes: []string{``, `<disabled></disabled>`, `<disabled/>`},
			want:   []bool{false, true, true},
		},
		{
			name:   "enabled does not set the state",
			routes: []string{`<enabled>0</enabled>`, `<disabled></disabled><enabled>1</enabled>`},
			want:   []bool{false, true},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var routes strings.Builder
			for i, element := range tt.routes {
				fmt.Fprintf(&routes, `<route><network>10.%d.0.0/16</network><gateway>WAN_GW</gateway>%s</route>`,
					i, element)
			}

			device, _, err := pfsense.NewParser(nil).Parse(
				context.Background(), strings.NewReader(fmt.Sprintf(configTemplate, routes.String())))
			require.NoError(t, err)
			require.NotNil(t, device)

			got := make([]bool, 0, len(device.Routing.StaticRoutes))
			for _, route := range device.Routing.StaticRoutes {
				got = append(got, route.Disabled)
			}
			assert.Equal(t, tt.want, got)
		})
	}
}

// TestConverter_StaticRoutes_EnabledAloneIsRetained pins what <enabled> still does
// here. It sets no route's state, but IsPlaceholder is shared with OPNsense and
// counts it as data, so a hand-written route holding nothing else stays as a blank
// route, and the <route/> beside it is dropped. pfSense writes no such route.
func TestConverter_StaticRoutes_EnabledAloneIsRetained(t *testing.T) {
	t.Parallel()

	const config = `<?xml version="1.0"?>
<pfsense>
  <system><hostname>fw</hostname><domain>example.com</domain></system>
  <staticroutes>
    <route><enabled>1</enabled></route>
    <route/>
    <route><enabled>0</enabled></route>
  </staticroutes>
</pfsense>`

	device, _, err := pfsense.NewParser(nil).Parse(context.Background(), strings.NewReader(config))
	require.NoError(t, err)
	require.NotNil(t, device)

	require.Len(t, device.Routing.StaticRoutes, 2)
	for _, route := range device.Routing.StaticRoutes {
		assert.Empty(t, route.Network)
		assert.False(t, route.Disabled)
	}
}
