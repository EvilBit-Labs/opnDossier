package pfsense_test

import (
	"context"
	"os"
	"strings"
	"testing"

	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
	"github.com/EvilBit-Labs/opnDossier/pkg/parser/pfsense"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestConverter_SNMP_EnableGatesTheAgent drives both pfSense fixtures through
// the parser as shipped, with community "public" and no <enable>, and again
// with <enable> added in the two shapes isset() accepts. pfSense starts
// bsnmpd only when config_path_enabled('snmpd') holds, so only the second
// pass reports an agent.
func TestConverter_SNMP_EnableGatesTheAgent(t *testing.T) {
	t.Parallel()

	fixtures := map[string]common.SNMPConfig{
		"../../../testdata/pfsense/config-pfSense.xml": {Enabled: true, ROCommunity: "public"},
		"../../../testdata/pfsense/config-2.7.x.xml": {
			Enabled:     true,
			ROCommunity: "public",
			SysLocation: "Server Room",
			SysContact:  "admin@edge.local",
		},
	}

	for path, enabled := range fixtures {
		raw, err := os.ReadFile(path)
		require.NoError(t, err)
		require.Equal(t, 1, strings.Count(string(raw), "<snmpd>"), path)
		require.NotContains(t, string(raw), "<enable/></snmpd>", path)

		cases := []struct {
			name   string
			enable string
			want   common.SNMPConfig
		}{
			{name: "as shipped", want: common.SNMPConfig{}},
			{name: "empty enable", enable: "<enable/>", want: enabled},
			{name: "enable with body", enable: "<enable>yes</enable>", want: enabled},
		}

		for _, tc := range cases {
			t.Run(path+"/"+tc.name, func(t *testing.T) {
				t.Parallel()

				config := strings.Replace(string(raw), "<snmpd>", "<snmpd>"+tc.enable, 1)
				device, _, err := pfsense.NewParser(nil).Parse(context.Background(), strings.NewReader(config))
				require.NoError(t, err)
				assert.Equal(t, tc.want, device.SNMP)
				assert.Equal(t, tc.want.Enabled, device.SNMP.IsEnabled())
			})
		}
	}
}
