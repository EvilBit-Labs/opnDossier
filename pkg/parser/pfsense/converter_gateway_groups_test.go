package pfsense_test

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/cfgparser"
	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
	"github.com/EvilBit-Labs/opnDossier/pkg/parser"
	_ "github.com/EvilBit-Labs/opnDossier/pkg/parser/pfsense"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestConverter_GatewayGroups_ItemsAsWritten pins that pfSense exports <item> as
// written. pfsense.Document reuses opnsense.GatewayGroup, so the OPNsense 26.7
// tier fields decode here too, but only the OPNsense converter reads them or
// rewrites entries, and pfSense never writes those elements. The entries are out
// of tier order to show pfSense does not sort them.
func TestConverter_GatewayGroups_ItemsAsWritten(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		members string
		want    []string
	}{
		{
			name:    "name|tier|vip entries out of tier order",
			members: `<item>WAN_GW2|2|address</item><item>WAN_GW|1|address</item>`,
			want:    []string{"WAN_GW2|2|address", "WAN_GW|1|address"},
		},
		{
			name: "tier elements are not read",
			members: `<item2>WAN_GW2</item2><item3>WAN_GW4</item3><item4>WAN_GW5</item4>` +
				`<item5>WAN_GW6</item5><item>WAN_GW,WAN_GW3</item>`,
			want: []string{"WAN_GW,WAN_GW3"},
		},
		{
			name:    "tier elements alone add no members",
			members: `<item2>WAN_GW2</item2><item3>WAN_GW4</item3><item4>WAN_GW5</item4><item5>WAN_GW6</item5>`,
			want:    nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			config := fmt.Sprintf(`<?xml version="1.0"?>
<pfsense>
  <system><hostname>fw</hostname><domain>example.com</domain></system>
  <interfaces><wan><if>em0</if></wan></interfaces>
  <gateways>
    <gateway_group><name>WAN_FAILOVER</name>%s<trigger>down</trigger></gateway_group>
  </gateways>
</pfsense>`, tc.members)

			factory := parser.NewFactory(cfgparser.NewXMLParser())
			device, _, err := factory.CreateDevice(
				context.Background(), strings.NewReader(config), common.DeviceTypeUnknown, false)
			require.NoError(t, err)
			require.Len(t, device.Routing.GatewayGroups, 1)

			assert.Equal(t, tc.want, device.Routing.GatewayGroups[0].Items)
		})
	}
}
