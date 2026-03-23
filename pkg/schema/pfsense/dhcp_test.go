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

// TestDhcpdInterfaceEnable_UnmarshalXML verifies that BoolFlag Enable on DhcpdInterface
// correctly unmarshals from self-closing, value-based, and absent XML elements.
func TestDhcpdInterfaceEnable_UnmarshalXML(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		xml        string
		wantEnable bool
	}{
		{
			name:       "enable self-closing",
			xml:        `<scope><enable/></scope>`,
			wantEnable: true,
		},
		{
			name:       "enable with content",
			xml:        `<scope><enable>1</enable></scope>`,
			wantEnable: true,
		},
		{
			name:       "enable absent",
			xml:        `<scope><gateway>192.168.1.1</gateway></scope>`,
			wantEnable: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var result DhcpdInterface
			err := xml.Unmarshal([]byte(tt.xml), &result)
			require.NoError(t, err)

			assert.Equal(t, tt.wantEnable, result.Enable.Bool(),
				"Enable.Bool() mismatch for case %q", tt.name)
		})
	}
}

// TestDhcpdInterfaceMarshalXML_EnableProducesPresenceElement verifies that an enabled
// DhcpdInterface marshals Enable as a self-closing <enable/> element (pfSense presence-based
// flag semantics), not as a textual boolean like <enable>true</enable>.
func TestDhcpdInterfaceMarshalXML_EnableProducesPresenceElement(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		scope      DhcpdInterface
		wantEnable bool // whether <enable> element should appear
	}{
		{
			name: "enabled scope produces enable element",
			scope: DhcpdInterface{
				Enable:  opnsense.BoolFlag(true),
				Gateway: "192.168.1.1",
			},
			wantEnable: true,
		},
		{
			name: "disabled scope omits enable element",
			scope: DhcpdInterface{
				Enable:  opnsense.BoolFlag(false),
				Gateway: "192.168.1.1",
			},
			wantEnable: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			out, err := xml.Marshal(tt.scope)
			require.NoError(t, err)

			xmlStr := string(out)

			if tt.wantEnable {
				assert.Contains(t, xmlStr, "<enable>", "enabled scope must produce <enable> element")
				assert.NotContains(t, xmlStr, "true", "enable element must not contain textual boolean")
			} else {
				assert.NotContains(t, xmlStr, "<enable", "disabled scope must omit enable element")
			}
		})
	}
}

// TestDhcpdMarshalXML_EnableProducesPresenceElement verifies that marshaling
// through the Dhcpd map container also produces correct <enable/> elements.
func TestDhcpdMarshalXML_EnableProducesPresenceElement(t *testing.T) {
	t.Parallel()

	dhcpd := Dhcpd{
		Items: map[string]DhcpdInterface{
			"lan": {
				Enable:  opnsense.BoolFlag(true),
				Gateway: "192.168.1.1",
			},
			"wan": {
				Enable:  opnsense.BoolFlag(false),
				Gateway: "10.0.0.1",
			},
		},
	}

	out, err := xml.MarshalIndent(&dhcpd, "", "  ")
	require.NoError(t, err)

	xmlStr := string(out)

	// lan sorts before wan alphabetically, so lan appears first in output
	lanIdx := strings.Index(xmlStr, "<lan>")
	wanIdx := strings.Index(xmlStr, "<wan>")
	require.Greater(t, lanIdx, -1, "lan element must exist")
	require.Greater(t, wanIdx, -1, "wan element must exist")

	// LAN (enabled) section should have enable element
	lanSection := xmlStr[lanIdx:wanIdx]
	assert.Contains(t, lanSection, "<enable>", "LAN must have <enable> element")
	assert.NotContains(t, lanSection, "true", "LAN enable must not contain textual boolean")

	// WAN (disabled) section should not have enable element
	wanSection := xmlStr[wanIdx:]
	assert.NotContains(t, wanSection, "<enable", "WAN must not have <enable> element")
}

// TestDhcpdXMLRoundTrip verifies that Dhcpd values round-trip through
// XML marshal/unmarshal preserving the Enable BoolFlag semantics.
func TestDhcpdXMLRoundTrip(t *testing.T) {
	t.Parallel()

	original := Dhcpd{
		Items: map[string]DhcpdInterface{
			"lan": {
				Enable:  opnsense.BoolFlag(true),
				Gateway: "192.168.1.1",
				Range: opnsense.Range{
					From: "192.168.1.100",
					To:   "192.168.1.200",
				},
			},
			"wan": {
				Enable:  opnsense.BoolFlag(false),
				Gateway: "10.0.0.1",
			},
		},
	}

	out, err := xml.Marshal(&original)
	require.NoError(t, err)

	var decoded Dhcpd
	err = xml.Unmarshal(out, &decoded)
	require.NoError(t, err)

	lanScope, ok := decoded.Get("lan")
	require.True(t, ok, "lan must exist after round-trip")
	assert.True(t, lanScope.Enable.Bool(), "LAN Enable must be true after round-trip")
	assert.Equal(t, "192.168.1.1", lanScope.Gateway)
	assert.Equal(t, "192.168.1.100", lanScope.Range.From)

	wanScope, ok := decoded.Get("wan")
	require.True(t, ok, "wan must exist after round-trip")
	assert.False(t, wanScope.Enable.Bool(), "WAN Enable must be false after round-trip")
	assert.Equal(t, "10.0.0.1", wanScope.Gateway)
}

// TestDocumentXMLRoundTrip_DhcpdEnable verifies that marshaling a full
// pfsense.Document with enabled/disabled DHCP scopes round-trips through
// XML marshal/unmarshal preserving the enable state as a string value.
// Document uses pfsense.Dhcpd with BoolFlag Enable.
func TestDocumentXMLRoundTrip_DhcpdEnable(t *testing.T) {
	t.Parallel()

	doc := NewDocument()
	doc.Dhcpd.Items["lan"] = DhcpdInterface{
		Enable:  opnsense.BoolFlag(true),
		Gateway: "192.168.1.1",
		Range: opnsense.Range{
			From: "192.168.1.100",
			To:   "192.168.1.200",
		},
	}
	doc.Dhcpd.Items["wan"] = DhcpdInterface{
		Gateway: "10.0.0.1",
	}

	out, err := xml.MarshalIndent(doc, "", "  ")
	require.NoError(t, err)

	// Unmarshal back and verify state is preserved
	var decoded Document
	err = xml.Unmarshal(out, &decoded)
	require.NoError(t, err)

	lanScope, ok := decoded.Dhcpd.Get("lan")
	require.True(t, ok, "lan must exist after document round-trip")
	assert.True(t, lanScope.Enable.Bool(), "LAN Enable must be true after document round-trip")
	assert.Equal(t, "192.168.1.1", lanScope.Gateway)
	assert.Equal(t, "192.168.1.100", lanScope.Range.From)

	wanScope, ok := decoded.Dhcpd.Get("wan")
	require.True(t, ok, "wan must exist after document round-trip")
	assert.False(t, wanScope.Enable.Bool(), "WAN Enable must be false after document round-trip")
	assert.Equal(t, "10.0.0.1", wanScope.Gateway)
}
