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
	require.NotNil(t, got.Advanced.Privateaddress)
	assert.Equal(t, "10.0.0.0/8,192.168.0.0/16", *got.Advanced.Privateaddress)
	assert.Equal(t, "corp.example.com", got.Advanced.Privatedomain)
	assert.Equal(t, "allow", got.Acls.DefaultAction)
	assert.Equal(t, "ads", got.Dnsbl.Type)
	assert.Equal(t, "0", got.Forwarding.Enabled)

	// Present-but-empty container elements must deserialize to non-nil
	// pointers pointing to empty strings — this is the contract the *string
	// promotion exists to protect (GOTCHAS 3.2). The NotNil checks confirm
	// the XML elements were present and unmarshaled into populated pointers.
	// If these fields regressed to plain `string`, NotNil could still pass
	// because a string stored in an interface{} is non-nil; the real guard
	// is the dereference below, which requires the fields to remain *string
	// or the test will fail to compile.
	require.NotNil(t, got.Dots)
	require.NotNil(t, got.Hosts)
	require.NotNil(t, got.Aliases)
	require.NotNil(t, got.Domains)
	assert.Empty(t, *got.Dots)
	assert.Empty(t, *got.Hosts)
	assert.Empty(t, *got.Aliases)
	assert.Empty(t, *got.Domains)
}

func TestUnboundPlus_EmptyElement(t *testing.T) {
	t.Parallel()

	var got UnboundPlus
	require.NoError(t, xml.Unmarshal([]byte(`<unboundplus/>`), &got))

	assert.Empty(t, got.Version)
	assert.Empty(t, got.General.Enabled)
	assert.Nil(t, got.Advanced.Privateaddress)
	assert.Empty(t, got.Acls.DefaultAction)
	// Absent container elements must deserialize to nil pointers so callers
	// can distinguish "never configured" from "present but empty".
	assert.Nil(t, got.Dots)
	assert.Nil(t, got.Hosts)
	assert.Nil(t, got.Aliases)
	assert.Nil(t, got.Domains)
}

func TestUnboundPlus_RoundTrip(t *testing.T) {
	t.Parallel()

	// Populate every sub-struct so the round-trip exercises every field path.
	// A future field whose type-promotion or tag silently breaks marshaling
	// will fail the deep-equality check below. Declaring the *string values as
	// locals (rather than a one-line helper) avoids the modernize analyzer's
	// false-positive `new()` suggestion for value-to-pointer conversions.
	dots, hosts, aliases, domains := "dot1", "host1", "alias1", "domain1"
	privAddr := "192.168.0.0/16,10.0.0.0/8"
	original := UnboundPlus{
		XMLName: xml.Name{Local: "unboundplus"},
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
			Privateaddress: &privAddr,
			Dnssecstripped: "0",
		},
		Acls:       UnboundPlusAcls{DefaultAction: "allow"},
		Dnsbl:      UnboundPlusDnsbl{Enabled: "1", Type: "ads", Nxdomain: "0"},
		Forwarding: UnboundPlusForwarding{Enabled: "0"},
		Dots:       &dots,
		Hosts:      &hosts,
		Aliases:    &aliases,
		Domains:    &domains,
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
	require.NotNil(t, doc.OPNsense.UnboundPlus.Advanced.Privateaddress)
	assert.Equal(t, "10.0.0.0/8", *doc.OPNsense.UnboundPlus.Advanced.Privateaddress)
	assert.Equal(t, "1", doc.OPNsense.UnboundPlus.Advanced.Hideidentity)
	assert.True(t, strings.HasPrefix(doc.XMLName.Local, "opnsense"))
}
