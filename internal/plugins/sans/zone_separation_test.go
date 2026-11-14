package sans_test

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/cfgparser"
	"github.com/EvilBit-Labs/opnDossier/internal/compliance"
	"github.com/EvilBit-Labs/opnDossier/internal/plugins/sans"
	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
	"github.com/EvilBit-Labs/opnDossier/pkg/parser"
	_ "github.com/EvilBit-Labs/opnDossier/pkg/parser/opnsense" // registers the OPNsense parser
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSANSPlugin_ZoneSeparation_PseudoInterfacesAreNotZones drives a config
// OPNsense wrote through parse and SANS-FW-003. testdata/sample.config.5.xml
// has wan, lan and the lo0 entry OPNsense writes on every save. Disabling lan
// leaves one network, which used to pass because lo0 counted as a second
// zone. The pseudo-interfaces OPNsense adds for an interface group, OpenVPN
// and IPsec are written the way plugins_interfaces writes them.
func TestSANSPlugin_ZoneSeparation_PseudoInterfacesAreNotZones(t *testing.T) {
	t.Parallel()

	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "testdata", "sample.config.5.xml"))
	require.NoError(t, err)

	lanEnable := []byte("<if>vtnet0</if>\n      <descr/>\n      <enable>1</enable>")
	endLo0 := []byte("</lo0>")
	ifgroups := []byte(`<ifgroups version="1.0.0"/>`)
	for _, anchor := range [][]byte{lanEnable, endLo0, ifgroups} {
		require.Equalf(t, 1, bytes.Count(raw, anchor), "fixture no longer carries %s", anchor)
	}

	lanDisabled := bytes.Replace(raw, lanEnable, []byte("<if>vtnet0</if>\n      <descr/>"), 1)

	withInterfaces := func(cfg []byte, entries string) []byte {
		return bytes.Replace(cfg, endLo0, []byte("</lo0>\n"+entries), 1)
	}

	group := `<mgmt>
      <internal_dynamic>1</internal_dynamic>
      <enable>1</enable>
      <networks/>
      <if>mgmt</if>
      <descr>mgmt</descr>
      <virtual>1</virtual>
      <type>group</type>
    </mgmt>`
	groupEntry := []byte(`<ifgroups version="1.0.0">
    <ifgroupentry uuid="5e0a8c58-6f8f-4b8e-9d3a-0c1f2e3d4b5a">
      <ifname>mgmt</ifname>
      <members>wan</members>
      <nogroup>0</nogroup>
      <sequence>0</sequence>
      <descr/>
    </ifgroupentry>
  </ifgroups>`)
	vpn := `<openvpn>
      <internal_dynamic>1</internal_dynamic>
      <enable>1</enable>
      <if>openvpn</if>
      <descr>OpenVPN (Group)</descr>
      <type>group</type>
      <virtual>1</virtual>
      <networks/>
    </openvpn>
    <enc0>
      <internal_dynamic>1</internal_dynamic>
      <enable>1</enable>
      <if>enc0</if>
      <descr>IPsec encapsulation</descr>
      <type>none</type>
      <virtual>1</virtual>
    </enc0>`
	vti := `<ipsec1>
      <internal_dynamic>1</internal_dynamic>
      <enable>1</enable>
      <descr>branch</descr>
      <if>ipsec1</if>
      <type>none</type>
    </ipsec1>`

	// assigned is an interface the operator assigned to device, as
	// interfaces_assign.php writes it.
	assigned := func(device string) string {
		return "<opt1>\n      <if>" + device + "</if>\n      <descr>extra</descr>\n" +
			"      <enable>1</enable>\n      <ipaddr>10.9.9.1</ipaddr>\n      <subnet>24</subnet>\n    </opt1>"
	}

	tests := []struct {
		name   string
		cfg    []byte
		failed bool
	}{
		{name: "wan and lan", cfg: raw},
		{name: "wan only, with lo0", cfg: lanDisabled, failed: true},
		{
			name:   "wan only, with an interface group",
			cfg:    bytes.Replace(withInterfaces(lanDisabled, group), ifgroups, groupEntry, 1),
			failed: true,
		},
		{name: "wan only, with VPN pseudo-interfaces", cfg: withInterfaces(lanDisabled, vpn), failed: true},
		// An IPsec VTI is a routed interface to a remote network and is not
		// marked virtual, so it counts.
		{name: "wan and an IPsec VTI", cfg: withInterfaces(lanDisabled, vti)},
		// A loopback device the operator created and assigned carries no
		// virtual flag, but reaches no network beyond the firewall.
		{name: "wan and an assigned loopback", cfg: withInterfaces(lanDisabled, assigned("lo1")), failed: true},
	}

	// Devices assigned as an interface carry a network of their own.
	for _, dev := range []string{"vtnet0_vlan10", "bridge0", "lagg0", "ovpns1", "wg0"} {
		tests = append(tests, struct {
			name   string
			cfg    []byte
			failed bool
		}{name: "wan and an assigned " + dev, cfg: withInterfaces(lanDisabled, assigned(dev))})
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			device, _, err := parser.NewFactory(cfgparser.NewXMLParser()).CreateDevice(
				context.Background(), bytes.NewReader(tt.cfg), common.DeviceTypeUnknown, false,
			)
			require.NoError(t, err)
			require.NotNil(t, device)

			findings, evaluated, err := sans.NewPlugin().RunChecks(device)
			require.NoError(t, err)

			require.Contains(t, evaluated, "SANS-FW-003")
			assert.Equal(t, tt.failed, slices.ContainsFunc(findings, func(f compliance.Finding) bool {
				return slices.Contains(f.References, "SANS-FW-003")
			}))
		})
	}
}
