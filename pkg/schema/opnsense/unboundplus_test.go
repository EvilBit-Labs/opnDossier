package opnsense

import (
	"encoding/xml"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUnboundPlus_UnmarshalXML(t *testing.T) {
	t.Parallel()

	input := `<unboundplus version="1.0.0">
		<general>
			<enabled>1</enabled>
			<port>53</port>
			<dnssec>1</dnssec>
			<dns64>0</dns64>
			<local_zone_type>transparent</local_zone_type>
		</general>
		<advanced>
			<hideidentity>1</hideidentity>
			<hideversion>1</hideversion>
			<prefetch>1</prefetch>
			<logqueries>0</logqueries>
			<logreplies>0</logreplies>
			<privateaddress>10.0.0.0/8,192.168.0.0/16</privateaddress>
			<privatedomain>corp.example.com</privatedomain>
		</advanced>
		<acls>
			<default_action>allow</default_action>
		</acls>
		<dnsbl>
			<enabled>0</enabled>
			<type>ads</type>
		</dnsbl>
		<forwarding>
			<enabled>0</enabled>
		</forwarding>
		<dots></dots>
		<hosts></hosts>
		<aliases></aliases>
		<domains></domains>
	</unboundplus>`

	var got UnboundPlus
	require.NoError(t, xml.Unmarshal([]byte(input), &got))

	assert.Equal(t, "1.0.0", got.Version)
	assert.Equal(t, "1", got.General.Enabled)
	assert.Equal(t, "53", got.General.Port)
	assert.Equal(t, "1", got.General.Dnssec)
	assert.Equal(t, "transparent", got.General.LocalZoneType)
	assert.Equal(t, "1", got.Advanced.Hideidentity)
	assert.Equal(t, "1", got.Advanced.Hideversion)
	assert.Equal(t, "1", got.Advanced.Prefetch)
	assert.Equal(t, "0", got.Advanced.Logqueries)
	assert.Equal(t, "10.0.0.0/8,192.168.0.0/16", got.Advanced.Privateaddress)
	assert.Equal(t, "corp.example.com", got.Advanced.Privatedomain)
	assert.Equal(t, "allow", got.Acls.DefaultAction)
	assert.Equal(t, "ads", got.Dnsbl.Type)
	assert.Equal(t, "0", got.Forwarding.Enabled)
}

func TestUnboundPlus_EmptyElement(t *testing.T) {
	t.Parallel()

	var got UnboundPlus
	require.NoError(t, xml.Unmarshal([]byte(`<unboundplus/>`), &got))

	assert.Empty(t, got.Version)
	assert.Empty(t, got.General.Enabled)
	assert.Empty(t, got.Advanced.Privateaddress)
	assert.Empty(t, got.Acls.DefaultAction)
}

func TestUnboundPlus_RoundTrip(t *testing.T) {
	t.Parallel()

	// Populate every sub-struct so the round-trip exercises every field path.
	// A future field whose type-promotion or tag silently breaks marshaling
	// will fail the deep-equality check below.
	original := UnboundPlus{
		Version: "1.0.0",
		General: UnboundPlusGeneral{
			Enabled:            "1",
			Port:               "53",
			Stats:              "1",
			ActiveInterface:    "lan",
			Dnssec:             "1",
			DNS64:              "0",
			RegisterDHCP:       "1",
			RegisterDHCPDomain: "1",
			LocalZoneType:      "transparent",
		},
		Advanced: UnboundPlusAdvanced{
			Hideidentity:   "1",
			Hideversion:    "1",
			Prefetch:       "1",
			Logqueries:     "0",
			Logreplies:     "0",
			Privatedomain:  "corp.example.com",
			Privateaddress: "192.168.0.0/16,10.0.0.0/8",
			Dnssecstripped: "0",
		},
		Acls:       UnboundPlusAcls{DefaultAction: "allow"},
		Dnsbl:      UnboundPlusDnsbl{Enabled: "1", Type: "ads", Nxdomain: "0"},
		Forwarding: UnboundPlusForwarding{Enabled: "0"},
		Dots:       "dot1",
		Hosts:      "host1",
		Aliases:    "alias1",
		Domains:    "domain1",
	}

	out, err := xml.Marshal(&original)
	require.NoError(t, err)

	var round UnboundPlus
	require.NoError(t, xml.Unmarshal(out, &round))
	// Full-struct deep equality locks in the round-trip contract so any
	// future field added without a proper tag is caught immediately.
	assert.Equal(t, original, round)
}

func TestUnboundPlus_UnmarshalsWithinOPNsenseDocument(t *testing.T) {
	t.Parallel()

	input := `<opnsense>
		<OPNsense>
			<unboundplus version="1.0.0">
				<advanced>
					<privateaddress>10.0.0.0/8</privateaddress>
					<hideidentity>1</hideidentity>
				</advanced>
			</unboundplus>
		</OPNsense>
	</opnsense>`

	var doc OpnSenseDocument
	require.NoError(t, xml.Unmarshal([]byte(input), &doc))

	assert.Equal(t, "1.0.0", doc.OPNsense.UnboundPlus.Version)
	assert.Equal(t, "10.0.0.0/8", doc.OPNsense.UnboundPlus.Advanced.Privateaddress)
	assert.Equal(t, "1", doc.OPNsense.UnboundPlus.Advanced.Hideidentity)
	assert.True(t, strings.HasPrefix(doc.XMLName.Local, "opnsense"))
}
