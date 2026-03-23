// Package pfsense defines the data structures for pfSense configurations.
package pfsense

import (
	"encoding/xml"
	"strings"
	"testing"

	opnsense "github.com/EvilBit-Labs/opnDossier/pkg/schema/opnsense"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestInterfaceMarshalXML_EnableProducesPresenceElement verifies that an enabled
// Interface marshals Enable as a self-closing <enable/> element (pfSense presence-based
// flag semantics), not as a textual boolean like <enable>true</enable>.
func TestInterfaceMarshalXML_EnableProducesPresenceElement(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		iface      Interface
		wantEnable bool // whether <enable> element should appear
	}{
		{
			name: "enabled interface produces enable element",
			iface: Interface{
				Enable: opnsense.BoolFlag(true),
				If:     "em0",
				Descr:  "WAN",
			},
			wantEnable: true,
		},
		{
			name: "disabled interface omits enable element",
			iface: Interface{
				Enable: opnsense.BoolFlag(false),
				If:     "em1",
				Descr:  "LAN",
			},
			wantEnable: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			out, err := xml.Marshal(tt.iface)
			require.NoError(t, err)

			xmlStr := string(out)

			if tt.wantEnable {
				// Must contain <enable></enable> (empty element, XML canonical form)
				// or <enable/> — both are valid. encoding/xml produces <enable></enable>.
				assert.Contains(t, xmlStr, "<enable>", "enabled interface must produce <enable> element")
				assert.NotContains(t, xmlStr, "true", "enable element must not contain textual boolean")
			} else {
				assert.NotContains(t, xmlStr, "<enable", "disabled interface must omit enable element")
			}
		})
	}
}

// TestInterfacesMarshalXML_EnableProducesPresenceElement verifies that marshaling
// through the Interfaces map container also produces correct <enable/> elements.
func TestInterfacesMarshalXML_EnableProducesPresenceElement(t *testing.T) {
	t.Parallel()

	ifaces := Interfaces{
		Items: map[string]Interface{
			"wan": {
				Enable: opnsense.BoolFlag(true),
				If:     "em0",
				Descr:  "WAN",
			},
			"lan": {
				Enable: opnsense.BoolFlag(false),
				If:     "em1",
				Descr:  "LAN",
			},
		},
	}

	out, err := xml.MarshalIndent(&ifaces, "", "  ")
	require.NoError(t, err)

	xmlStr := string(out)

	// lan sorts before wan alphabetically, so lan appears first in output
	lanIdx := strings.Index(xmlStr, "<lan>")
	wanIdx := strings.Index(xmlStr, "<wan>")
	require.Greater(t, lanIdx, -1, "lan element must exist")
	require.Greater(t, wanIdx, -1, "wan element must exist")

	// LAN (disabled) section should not have enable element
	lanSection := xmlStr[lanIdx:wanIdx]
	assert.NotContains(t, lanSection, "<enable", "LAN must not have <enable> element")

	// WAN (enabled) should have <enable></enable> (presence element)
	wanSection := xmlStr[wanIdx:]
	assert.Contains(t, wanSection, "<enable>", "WAN must have <enable> element")
	assert.NotContains(t, wanSection, "true", "WAN enable must not contain textual boolean")
}

// TestInterfaceXMLRoundTrip verifies that Interface values round-trip through
// XML marshal/unmarshal preserving the Enable BoolFlag semantics.
func TestInterfaceXMLRoundTrip(t *testing.T) {
	t.Parallel()

	original := Interfaces{
		Items: map[string]Interface{
			"wan": {
				Enable: opnsense.BoolFlag(true),
				If:     "em0",
				Descr:  "WAN",
				IPAddr: "192.168.1.1",
				Subnet: "24",
			},
			"lan": {
				Enable: opnsense.BoolFlag(false),
				If:     "em1",
				Descr:  "LAN",
			},
		},
	}

	out, err := xml.Marshal(&original)
	require.NoError(t, err)

	var decoded Interfaces
	err = xml.Unmarshal(out, &decoded)
	require.NoError(t, err)

	wanIface, ok := decoded.Get("wan")
	require.True(t, ok, "wan must exist after round-trip")
	assert.True(t, wanIface.Enable.Bool(), "WAN Enable must be true after round-trip")
	assert.Equal(t, "em0", wanIface.If)

	lanIface, ok := decoded.Get("lan")
	require.True(t, ok, "lan must exist after round-trip")
	assert.False(t, lanIface.Enable.Bool(), "LAN Enable must be false after round-trip")
	assert.Equal(t, "em1", lanIface.If)
}

// TestDocumentXMLRoundTrip_InterfaceEnable verifies that marshaling a full
// pfsense.Document with enabled/disabled interfaces emits presence-based
// <enable/> elements and that unmarshaling preserves the enabled/disabled state.
func TestDocumentXMLRoundTrip_InterfaceEnable(t *testing.T) {
	t.Parallel()

	doc := NewDocument()
	doc.Interfaces.Items["wan"] = Interface{
		Enable: opnsense.BoolFlag(true),
		If:     "em0",
		Descr:  "WAN",
		IPAddr: "dhcp",
	}
	doc.Interfaces.Items["lan"] = Interface{
		Enable: opnsense.BoolFlag(false),
		If:     "em1",
		Descr:  "LAN",
		IPAddr: "192.168.1.1",
		Subnet: "24",
	}

	out, err := xml.MarshalIndent(doc, "", "  ")
	require.NoError(t, err)

	xmlStr := string(out)

	// Verify the marshaled XML contains a presence-based <enable> for WAN
	wanIdx := strings.Index(xmlStr, "<wan>")
	lanIdx := strings.Index(xmlStr, "<lan>")
	require.Greater(t, wanIdx, -1, "wan element must exist in document XML")
	require.Greater(t, lanIdx, -1, "lan element must exist in document XML")

	// lan sorts before wan alphabetically
	lanSection := xmlStr[lanIdx:wanIdx]
	wanSection := xmlStr[wanIdx:]

	assert.NotContains(t, lanSection, "<enable", "disabled LAN must omit <enable> element")
	assert.Contains(t, wanSection, "<enable>", "enabled WAN must have <enable> element")
	assert.NotContains(t, wanSection, "true", "WAN enable must not contain textual boolean")

	// Unmarshal back and verify state is preserved
	var decoded Document
	err = xml.Unmarshal(out, &decoded)
	require.NoError(t, err)

	wanIface, ok := decoded.Interfaces.Get("wan")
	require.True(t, ok, "wan must exist after document round-trip")
	assert.True(t, wanIface.Enable.Bool(), "WAN Enable must be true after document round-trip")
	assert.Equal(t, "em0", wanIface.If)
	assert.Equal(t, "WAN", wanIface.Descr)
	assert.Equal(t, "dhcp", wanIface.IPAddr)

	lanIface, ok := decoded.Interfaces.Get("lan")
	require.True(t, ok, "lan must exist after document round-trip")
	assert.False(t, lanIface.Enable.Bool(), "LAN Enable must be false after document round-trip")
	assert.Equal(t, "em1", lanIface.If)
	assert.Equal(t, "LAN", lanIface.Descr)
	assert.Equal(t, "192.168.1.1", lanIface.IPAddr)
}
