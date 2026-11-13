package pfsense_test

import (
	"context"
	"strings"
	"testing"

	"github.com/EvilBit-Labs/opnDossier/pkg/parser/pfsense"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// pfSenseReflectionForward returns a port forward in the body the pfSense GUI
// writes, with extra elements such as <natreflection>, <disabled> or <nordr>.
func pfSenseReflectionForward(extra string) string {
	return `<rule>
			<source><any></any></source>
			<destination><network>wanip</network><port>443</port></destination>
			<protocol>tcp</protocol>
			<target>10.0.2.2</target>
			<local-port>443</local-port>
			<interface>wan</interface>
			<descr><![CDATA[HTTPS to webserver]]></descr>
			` + extra + `
		</rule>`
}

// TestConverter_NATReflection_PerForwardOverride covers the reflection
// setting each pfSense port forward carries. filter.inc reflects a forward set
// to enable (NAT + proxy) or purenat whatever the global mode, never one set
// to disable, and gives any other value, default included, the global mode.
// ReflectionDisabled was read from the global setting alone.
func TestConverter_NATReflection_PerForwardOverride(t *testing.T) {
	t.Parallel()

	const globalOff = `<disablenatreflection>yes</disablenatreflection>`

	tests := []struct {
		name          string
		systemElement string
		forwards      []string
		wantDisabled  bool
	}{
		{
			name:          "forward set to Pure NAT reflects while the global mode is off",
			systemElement: globalOff,
			forwards: []string{
				pfSenseReflectionForward(""),
				pfSenseReflectionForward("<natreflection>purenat</natreflection>"),
			},
			wantDisabled: false,
		},
		{
			name:          "forward set to NAT + Proxy reflects while the global mode is off",
			systemElement: globalOff,
			forwards: []string{
				pfSenseReflectionForward("<natreflection>default</natreflection>"),
				pfSenseReflectionForward("<natreflection>enable</natreflection>"),
			},
			wantDisabled: false,
		},
		{
			name:          "forwards on the system default follow a global off",
			systemElement: globalOff,
			forwards: []string{
				pfSenseReflectionForward(""),
				pfSenseReflectionForward("<natreflection>default</natreflection>"),
			},
			wantDisabled: true,
		},
		{
			name:          "disabled forward set to Pure NAT is skipped",
			systemElement: globalOff,
			forwards: []string{
				pfSenseReflectionForward(""),
				pfSenseReflectionForward("<natreflection>purenat</natreflection><disabled></disabled>"),
			},
			wantDisabled: true,
		},
		{
			name:          "no-RDR forward set to Pure NAT redirects nothing",
			systemElement: globalOff,
			forwards: []string{
				pfSenseReflectionForward(""),
				pfSenseReflectionForward("<natreflection>purenat</natreflection><nordr></nordr>"),
			},
			wantDisabled: true,
		},
		{
			name:          "every forward set to Disable overrides a global on",
			systemElement: "",
			forwards: []string{
				pfSenseReflectionForward("<natreflection>disable</natreflection>"),
				pfSenseReflectionForward("<natreflection>disable</natreflection>"),
			},
			wantDisabled: true,
		},
		{
			name:          "forward on the system default follows a global on",
			systemElement: "",
			forwards: []string{
				pfSenseReflectionForward("<natreflection>disable</natreflection>"),
				pfSenseReflectionForward("<natreflection>default</natreflection>"),
			},
			wantDisabled: false,
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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			config := `<?xml version="1.0"?>
<pfsense>
	<system>
		<hostname>fw</hostname>
		<domain>example.com</domain>
		` + tt.systemElement + `
	</system>
	<nat>
		<outbound><mode>automatic</mode></outbound>
		` + strings.Join(tt.forwards, "\n\t\t") + `
	</nat>
</pfsense>`

			device, _, err := pfsense.NewParser(nil).Parse(context.Background(), strings.NewReader(config))
			require.NoError(t, err)
			require.NotNil(t, device)
			require.Len(t, device.NAT.InboundRules, len(tt.forwards))

			assert.Equal(t, tt.wantDisabled, device.NAT.ReflectionDisabled)
			assert.Equal(t, tt.wantDisabled, device.NATSummary().ReflectionDisabled)
			// The System field keeps the global setting as written.
			assert.Equal(t, tt.systemElement != "", device.System.DisableNATReflection)
		})
	}
}
