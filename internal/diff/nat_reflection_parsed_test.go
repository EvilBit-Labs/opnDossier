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

// pfSenseReflectionDoc is a pfSense config with the given <system>
// reflection element and one port forward per <natreflection> value given.
func pfSenseReflectionDoc(systemElement string, natreflections ...string) string {
	var forwards strings.Builder
	for i, value := range natreflections {
		forwards.WriteString(`<rule>
			<source><any></any></source>
			<destination><network>wanip</network><port>44` + string(rune('3'+i)) + `</port></destination>
			<protocol>tcp</protocol>
			<target>10.0.2.2</target>
			<local-port>443</local-port>
			<interface>wan</interface>
			<descr>Forward ` + string(rune('1'+i)) + `</descr>
			<natreflection>` + value + `</natreflection>
		</rule>
		`)
	}

	return `<?xml version="1.0"?>
<pfsense>
	<system>
		<hostname>fw</hostname>
		<domain>example.com</domain>
		` + systemElement + `
	</system>
	<nat>
		<outbound><mode>automatic</mode></outbound>
		` + forwards.String() + `
	</nat>
</pfsense>`
}

// reflectionEntry is the old and new value of one diff entry, keyed by path.
type reflectionEntry struct{ old, new string }

// TestCompare_NATReflection_GlobalAndPerForward covers the two diff entries
// for NAT reflection. nat.reflectionDisabled combines the global flag with the
// port forwards, so it does not move when the global flag is toggled while a
// forward sets purenat or enable; system.disableNatReflection reports the
// global flag itself, which CompareSystem does not compare. Removing forwards
// set to disable or to the default leaves both unchanged.
func TestCompare_NATReflection_GlobalAndPerForward(t *testing.T) {
	t.Parallel()

	const globalOff = `<disablenatreflection>yes</disablenatreflection>`
	const (
		combined = "nat.reflectionDisabled"
		global   = "system.disableNatReflection"
	)

	tests := []struct {
		name   string
		oldDoc string
		newDoc string
		want   map[string]reflectionEntry
	}{
		{
			name:   "global flag toggled with every forward set to Disable",
			oldDoc: reflectionDoc(globalOff, "disable", "disable"),
			newDoc: reflectionDoc("", "disable", "disable"),
			want:   map[string]reflectionEntry{combined: {"true", "false"}, global: {"true", "false"}},
		},
		{
			name:   "global flag toggled with a forward set to Enable",
			oldDoc: reflectionDoc(globalOff, "", "purenat"),
			newDoc: reflectionDoc("", "", "purenat"),
			want:   map[string]reflectionEntry{global: {"true", "false"}},
		},
		{
			name:   "global flag toggled back with a forward set to Enable",
			oldDoc: reflectionDoc("", "", "purenat"),
			newDoc: reflectionDoc(globalOff, "", "purenat"),
			want:   map[string]reflectionEntry{global: {"false", "true"}},
		},
		{
			name:   "pfSense global flag toggled with a forward set to NAT + Proxy",
			oldDoc: pfSenseReflectionDoc(globalOff, "", "enable"),
			newDoc: pfSenseReflectionDoc("", "", "enable"),
			want:   map[string]reflectionEntry{global: {"true", "false"}},
		},
		{
			name:   "pfSense global flag toggled with every forward set to Disable",
			oldDoc: pfSenseReflectionDoc(globalOff, "disable"),
			newDoc: pfSenseReflectionDoc("", "disable"),
			want:   map[string]reflectionEntry{combined: {"true", "false"}, global: {"true", "false"}},
		},
		{
			name:   "forward set to Enable added under a global off",
			oldDoc: reflectionDoc(globalOff, ""),
			newDoc: reflectionDoc(globalOff, "", "purenat"),
			want:   map[string]reflectionEntry{combined: {"true", "false"}},
		},
		{
			// The removed forward was reflected, so the combined value moves.
			name:   "forward set to Enable removed under a global off",
			oldDoc: reflectionDoc(globalOff, "", "purenat"),
			newDoc: reflectionDoc(globalOff, ""),
			want:   map[string]reflectionEntry{combined: {"false", "true"}},
		},
		{
			name:   "forwards set to Disable removed under a global on",
			oldDoc: reflectionDoc("", "disable", "disable"),
			newDoc: reflectionDoc(""),
		},
		{
			name:   "forwards on the default or Disable removed under a global off",
			oldDoc: reflectionDoc(globalOff, "", "disable"),
			newDoc: reflectionDoc(globalOff),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := map[string]reflectionEntry{}
			for _, c := range diffAliasDocs(t, tt.oldDoc, tt.newDoc, Options{}) {
				if c.Path != combined && c.Path != global {
					continue
				}
				require.NotContains(t, got, c.Path, "duplicate entry")
				got[c.Path] = reflectionEntry{c.OldValue, c.NewValue}
				assert.Equal(t, SectionNAT, c.Section)
				if c.Path == combined {
					assert.Equal(
						t,
						"NAT reflection changed (global setting or a port forward override)",
						c.Description,
					)
				}
			}

			want := tt.want
			if want == nil {
				want = map[string]reflectionEntry{}
			}
			assert.Equal(t, want, got)
		})
	}
}
