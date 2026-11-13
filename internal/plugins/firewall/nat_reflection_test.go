package firewall_test

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/analysis"
	"github.com/EvilBit-Labs/opnDossier/internal/cfgparser"
	"github.com/EvilBit-Labs/opnDossier/internal/plugins/firewall"
	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
	"github.com/EvilBit-Labs/opnDossier/pkg/parser"
	_ "github.com/EvilBit-Labs/opnDossier/pkg/parser/opnsense"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// natReflectionConfig is the factory default system setting with one 26.1
// DNat model port forward whose <natreflection> is %s.
const natReflectionConfig = `<?xml version="1.0"?>
<opnsense>
  <system>
    <hostname>fw</hostname>
    <domain>example.com</domain>
    %s
  </system>
  <interfaces>
    <wan><enable>1</enable><if>vtnet0</if><ipaddr>198.51.100.2</ipaddr><subnet>24</subnet></wan>
    <lan><enable>1</enable><if>vtnet1</if><ipaddr>192.168.1.1</ipaddr><subnet>24</subnet></lan>
  </interfaces>
  <nat>
    <outbound><mode>automatic</mode></outbound>
    <rule uuid="d4d4d4d4-0000-4000-8000-000000000001">
      <sequence>100</sequence>
      <disabled>0</disabled>
      <nordr>0</nordr>
      <interface>wan</interface>
      <ipprotocol>inet</ipprotocol>
      <protocol>tcp</protocol>
      <source><network/><port/><not>0</not></source>
      <destination><network>wanip</network><port>443</port><not>0</not></destination>
      <target>192.168.1.50</target>
      <local-port>443</local-port>
      <descr>HTTPS to web server</descr>
      <natreflection>%s</natreflection>
      <pass/>
    </rule>
  </nat>
</opnsense>`

// TestFirewallPlugin_NATReflection_ReadsEachPortForward drives FIREWALL-056
// and the security features from parsed XML. A forward set to Enable is
// reflected on a firewall whose global setting is off, and the control
// passed on it because only the global setting was read.
func TestFirewallPlugin_NATReflection_ReadsEachPortForward(t *testing.T) {
	t.Parallel()

	const globalOff = `<disablenatreflection>yes</disablenatreflection>`

	tests := []struct {
		name          string
		systemElement string
		natreflection string
		wantFinding   bool
	}{
		{"global off, forward on Enable", globalOff, "purenat", true},
		{"global off, forward on the default", globalOff, "", false},
		{"global on, forward on Disable", "", "disable", false},
		{"global on, forward on the default", "", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			config := strings.Replace(natReflectionConfig, "%s", tt.systemElement, 1)
			config = strings.Replace(config, "%s", tt.natreflection, 1)

			factory := parser.NewFactory(cfgparser.NewXMLParser())
			device, _, err := factory.CreateDevice(
				context.Background(),
				strings.NewReader(config),
				common.DeviceTypeUnknown,
				false,
			)
			require.NoError(t, err)

			findings, _, err := firewall.NewPlugin().RunChecks(device)
			require.NoError(t, err)

			found := false
			for _, f := range findings {
				if f.Reference == "FIREWALL-056" {
					found = true
				}
			}
			assert.Equal(t, tt.wantFinding, found, "FIREWALL-056 finding")

			stats := analysis.ComputeStatistics(device)
			assert.Equal(t, !tt.wantFinding,
				slices.Contains(stats.SecurityFeatures, "NAT Reflection Disabled"),
				"securityFeatures %v", stats.SecurityFeatures)
		})
	}
}
