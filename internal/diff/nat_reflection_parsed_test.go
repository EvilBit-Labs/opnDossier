package diff

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// reflectionDoc is an OPNsense config with the given <system> reflection
// element and 26.1 model port forwards, one per <natreflection> value given.
func reflectionDoc(systemElement string, natreflections ...string) string {
	var forwards strings.Builder
	for i, value := range natreflections {
		forwards.WriteString(`<rule uuid="e5e5e5e5-0000-4000-8000-00000000000` + string(rune('1'+i)) + `">
      <sequence>` + string(rune('1'+i)) + `00</sequence>
      <disabled>0</disabled>
      <nordr>0</nordr>
      <interface>wan</interface>
      <ipprotocol>inet</ipprotocol>
      <protocol>tcp</protocol>
      <source><network/><port/><not>0</not></source>
      <destination><network>wanip</network><port>44` + string(rune('3'+i)) + `</port><not>0</not></destination>
      <target>192.168.1.50</target>
      <local-port>443</local-port>
      <descr>Forward ` + string(rune('1'+i)) + `</descr>
      <natreflection>` + value + `</natreflection>
      <pass/>
    </rule>
    `)
	}

	return `<?xml version="1.0"?>
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
    ` + forwards.String() + `
  </nat>
</opnsense>`
}

// TestCompare_NATReflection_GlobalAndPerForward covers the diff entry for
// nat.reflectionDisabled once it is decided from the port forwards as well as
// the global flag. The diff never compared System.DisableNATReflection, so
// this entry is the only one that reports a global toggle: it must move with
// the global flag whatever the forwards say, move when a forward turns
// reflection on, and stay quiet when forwards are only removed.
func TestCompare_NATReflection_GlobalAndPerForward(t *testing.T) {
	t.Parallel()

	const globalOff = `<disablenatreflection>yes</disablenatreflection>`

	tests := []struct {
		name      string
		oldDoc    string
		newDoc    string
		wantEntry bool
		wantOld   string
		wantNew   string
	}{
		{
			name:      "global flag toggled with every forward set to Disable",
			oldDoc:    reflectionDoc(globalOff, "disable", "disable"),
			newDoc:    reflectionDoc("", "disable", "disable"),
			wantEntry: true, wantOld: "true", wantNew: "false",
		},
		{
			name:      "forward set to Enable added under a global off",
			oldDoc:    reflectionDoc(globalOff, ""),
			newDoc:    reflectionDoc(globalOff, "", "purenat"),
			wantEntry: true, wantOld: "true", wantNew: "false",
		},
		{
			name:   "forwards set to Disable removed under a global on",
			oldDoc: reflectionDoc("", "disable", "disable"),
			newDoc: reflectionDoc(""),
		},
		{
			name:   "forwards on the default removed under a global off",
			oldDoc: reflectionDoc(globalOff, "", "disable"),
			newDoc: reflectionDoc(globalOff),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var entries []Change
			for _, c := range diffAliasDocs(t, tt.oldDoc, tt.newDoc, Options{}) {
				if c.Path == "nat.reflectionDisabled" {
					entries = append(entries, c)
				}
			}

			if !tt.wantEntry {
				assert.Empty(t, entries)

				return
			}
			require.Len(t, entries, 1)
			assert.Equal(t, tt.wantOld, entries[0].OldValue)
			assert.Equal(t, tt.wantNew, entries[0].NewValue)
			assert.Equal(
				t,
				"NAT reflection changed (global setting or a port forward override)",
				entries[0].Description,
			)
		})
	}
}
