package opnsense_test

import (
	"context"
	"strings"
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/cfgparser"
	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
	"github.com/EvilBit-Labs/opnDossier/pkg/parser"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// reflectionForward returns a port forward in the body the 26.1 DNat model
// writes, with the given <disabled>, <nordr> and <natreflection> values. id is
// one hex digit that keeps the uuids of a config apart.
func reflectionForward(id, disabled, nordr, natreflection string) string {
	return `<rule uuid="c3c3c3c3-0000-4000-8000-00000000000` + id + `">
      <sequence>100</sequence>
      <disabled>` + disabled + `</disabled>
      <nordr>` + nordr + `</nordr>
      <interface>wan</interface>
      <ipprotocol>inet</ipprotocol>
      <protocol>tcp</protocol>
      <source><network/><port/><not>0</not></source>
      <destination><network>wanip</network><port>443</port><not>0</not></destination>
      <target>192.168.1.50</target>
      <local-port>443</local-port>
      <poolopts/>
      <log>0</log>
      <category/>
      <descr>HTTPS to web server</descr>
      <tag/>
      <tagged/>
      <nosync>0</nosync>
      <natreflection>` + natreflection + `</natreflection>
      <pass/>
      <associated-rule-id/>
    </rule>`
}

// legacyReflectionForward is a port forward in the body the legacy page wrote
// up to 25.7, which leaves out the elements it does not set.
const legacyReflectionForward = `<rule>
      <protocol>tcp</protocol>
      <interface>wan</interface>
      <ipprotocol>inet</ipprotocol>
      <descr>HTTPS to web server</descr>
      <target>192.168.1.50</target>
      <local-port>443</local-port>
      <source><any>1</any></source>
      <destination><network>wanip</network><port>443</port></destination>
      %s
    </rule>`

// parseReflectionConfig parses a config with the given <system> reflection
// element and port forwards, the way the factory default 26.7.9 config holds
// them.
func parseReflectionConfig(t *testing.T, systemElement string, forwards ...string) *common.CommonDevice {
	t.Helper()

	config := `<?xml version="1.0"?>
<opnsense>
  <system>
    <hostname>fw</hostname>
    <domain>example.com</domain>
    ` + systemElement + `
  </system>
  <interfaces>
    <wan><enable>1</enable><if>vtnet0</if><ipaddr>198.51.100.2</ipaddr><subnet>24</subnet></wan>
    <lan><enable>1</enable><if>vtnet1</if><ipaddr>192.168.1.1</ipaddr><subnet>24</subnet></lan>
  </interfaces>
  <nat>
    <outbound><mode>automatic</mode></outbound>
    ` + strings.Join(forwards, "\n    ") + `
  </nat>
</opnsense>`

	factory := parser.NewFactory(cfgparser.NewXMLParser())
	device, _, err := factory.CreateDevice(
		context.Background(),
		strings.NewReader(config),
		common.DeviceTypeUnknown,
		false,
	)
	require.NoError(t, err)
	require.NotNil(t, device)

	return device
}

// reflectionCase is one config of TestConverter_NATReflection_PerForwardOverride.
type reflectionCase struct {
	name          string
	systemElement string
	forwards      []string
	wantDisabled  bool
}

// reflectionCases returns the cases of TestConverter_NATReflection_PerForwardOverride.
func reflectionCases() []reflectionCase {
	const globalOff = `<disablenatreflection>yes</disablenatreflection>`

	return []reflectionCase{
		{
			name:          "forward set to Enable reflects while the global setting is off",
			systemElement: globalOff,
			forwards: []string{
				reflectionForward("1", "0", "0", ""),
				reflectionForward("2", "0", "0", "purenat"),
			},
			wantDisabled: false,
		},
		{
			name:          "forward set to enable reflects while the global setting is off",
			systemElement: globalOff,
			forwards:      []string{reflectionForward("3", "0", "0", "enable")},
			wantDisabled:  false,
		},
		{
			name:          "forward on the system default follows a global off",
			systemElement: globalOff,
			forwards:      []string{reflectionForward("4", "0", "0", "")},
			wantDisabled:  true,
		},
		{
			name:          "disabled forward set to Enable is not loaded",
			systemElement: globalOff,
			forwards: []string{
				reflectionForward("5", "0", "0", ""),
				reflectionForward("6", "1", "0", "purenat"),
			},
			wantDisabled: true,
		},
		{
			name:          "no-RDR forward set to Enable redirects nothing",
			systemElement: globalOff,
			forwards: []string{
				reflectionForward("7", "0", "0", ""),
				reflectionForward("8", "0", "1", "purenat"),
			},
			wantDisabled: true,
		},
		{
			name:          "a global on is not disabled when every forward is set to Disable",
			systemElement: "",
			forwards: []string{
				reflectionForward("9", "0", "0", "disable"),
				reflectionForward("a", "0", "0", "disable"),
			},
			wantDisabled: false,
		},
		{
			// From 26.1 the firewall gives "0" the global default, as it gives
			// an empty value.
			name:          "forward with 0 follows a global off",
			systemElement: globalOff,
			forwards: []string{
				reflectionForward("e", "0", "0", ""),
				reflectionForward("f", "0", "0", "0"),
			},
			wantDisabled: true,
		},
		{
			name:          "forward with 0 under a global on",
			systemElement: "",
			forwards:      []string{reflectionForward("e", "0", "0", "0")},
			wantDisabled:  false,
		},
		{
			name:          "forward on the system default follows a global on",
			systemElement: "",
			forwards: []string{
				reflectionForward("b", "0", "0", "disable"),
				reflectionForward("c", "0", "0", ""),
			},
			wantDisabled: false,
		},
		{
			name:          "only disabled forwards leave the global on in force",
			systemElement: "",
			forwards:      []string{reflectionForward("d", "1", "0", "disable")},
			wantDisabled:  false,
		},
		{
			name:          "no forward leaves the global on in force",
			systemElement: "",
			wantDisabled:  false,
		},
		{
			name:          "no forward leaves the global off in force",
			systemElement: globalOff,
			wantDisabled:  true,
		},
		{
			name:          "legacy forward set to Enable reflects while the global setting is off",
			systemElement: globalOff,
			forwards: []string{
				strings.Replace(legacyReflectionForward, "%s", "", 1),
				strings.Replace(legacyReflectionForward, "%s", "<natreflection>purenat</natreflection>", 1),
			},
			wantDisabled: false,
		},
		{
			name:          "legacy forward with no element follows a global off",
			systemElement: globalOff,
			forwards:      []string{strings.Replace(legacyReflectionForward, "%s", "", 1)},
			wantDisabled:  true,
		},
	}
}

// TestConverter_NATReflection_PerForwardOverride covers the reflection
// setting each port forward carries. OPNsense gives a forward with an empty
// <natreflection> the global default and reflects one that ends up with
// purenat or enable (Plugin.php, ForwardRule.php), so a forward can turn
// reflection on while the global setting is off. ReflectionDisabled was read
// from the global setting alone. It now holds only when reflection is off
// globally and no forward turns it back on; a global on is never disabled,
// since the next forward added would reflect.
func TestConverter_NATReflection_PerForwardOverride(t *testing.T) {
	t.Parallel()

	tests := reflectionCases()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			device := parseReflectionConfig(t, tt.systemElement, tt.forwards...)
			require.Len(t, device.NAT.InboundRules, len(tt.forwards))

			assert.Equal(t, tt.wantDisabled, device.NAT.ReflectionDisabled)
			assert.Equal(t, tt.wantDisabled, device.NATSummary().ReflectionDisabled)
			// The System field keeps the global setting as written.
			assert.Equal(t, tt.systemElement != "", device.System.DisableNATReflection)
		})
	}
}
