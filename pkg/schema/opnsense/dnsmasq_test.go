package opnsense

import (
	"encoding/xml"
	"reflect"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// dnsmasqModelElement is a <dnsmasq> element in the shape the 26.7.9 model
// writes, one entry of each repeated item.
const dnsmasqModelElement = `<dnsmasq version="1.0.9">
  <enable>1</enable>
  <dnssec>1</dnssec>
  <interface>lan,opt1</interface>
  <port>53</port>
  <dhcp><no_interface>opt2</no_interface></dhcp>
  <hosts uuid="00000000-0000-4000-8000-000000000001">
    <host>nas</host><domain>internal</domain><ip>192.168.1.10</ip>
    <client_id>01:02:f3</client_id><hwaddr>aa:bb:cc:dd:ee:01</hwaddr><lease_time>3600</lease_time><ignore>0</ignore>
    <descr>NAS</descr><aliases>files.internal,backup.internal</aliases>
  </hosts>
  <domainoverrides uuid="00000000-0000-4000-8000-000000000002">
    <domain>corp.example</domain><srcip>192.168.1.1</srcip><port>5353</port><ip>10.9.0.53</ip><descr>Corp</descr>
  </domainoverrides>
  <dhcp_ranges uuid="00000000-0000-4000-8000-000000000003">
    <interface>lan</interface><set_tag>t1</set_tag><start_addr>::1000</start_addr><end_addr>::2000</end_addr>
    <subnet_mask>255.255.255.0</subnet_mask><constructor>lan</constructor><mode>static</mode><prefix_len>64</prefix_len>
    <lease_time>86400</lease_time><domain_type>range</domain_type><domain>lan.example</domain>
    <ra_mode>slaac</ra_mode><description>LAN v6</description>
  </dhcp_ranges>
  <dhcp_options uuid="00000000-0000-4000-8000-000000000004">
    <type>set</type><option>6</option><option6>23</option6><interface>lan</interface><tag>t1</tag><set_tag>t2</set_tag>
    <value>9.9.9.9</value><force>1</force><description>DNS</description>
  </dhcp_options>
</dnsmasq>`

// TestDNSMasq_DecodesModelShape pins the element names the Dnsmasq model
// writes. The schema bound hosts>host and domainoverrides>domainoverride,
// which no release writes.
func TestDNSMasq_DecodesModelShape(t *testing.T) {
	t.Parallel()

	var dm DNSMasq
	require.NoError(t, xml.Unmarshal([]byte(dnsmasqModelElement), &dm))

	assert.Equal(t, "1.0.9", dm.Version)
	require.NotNil(t, dm.Dnssec)
	assert.Equal(t, "1", *dm.Dnssec)
	assert.Equal(t, "53", dm.Port)
	assert.Equal(t, "lan,opt1", dm.Interface)
	require.NotNil(t, dm.DHCP)
	assert.Equal(t, "opt2", dm.DHCP.NoInterface)

	require.Len(t, dm.Hosts, 1)
	h := dm.Hosts[0]
	assert.Equal(t, "nas", h.Host)
	assert.Equal(t, "aa:bb:cc:dd:ee:01", h.HWAddr)
	assert.Equal(t, "01:02:f3", h.ClientID)
	assert.Equal(t, DNSMasqHostAliases{"files.internal", "backup.internal"}, h.Aliases)

	require.Len(t, dm.DomainOverrides, 1)
	assert.Equal(t, "5353", dm.DomainOverrides[0].Port)
	assert.Equal(t, "192.168.1.1", dm.DomainOverrides[0].SrcIP)

	require.Len(t, dm.DHCPRanges, 1)
	assert.Equal(t, DNSMasqDHCPRange{
		UUID: "00000000-0000-4000-8000-000000000003", Interface: "lan", SetTag: "t1",
		StartAddr: "::1000", EndAddr: "::2000", SubnetMask: "255.255.255.0", Constructor: "lan",
		Mode: "static", PrefixLen: "64", LeaseTime: "86400", DomainType: "range", Domain: "lan.example",
		RAMode: "slaac", Description: "LAN v6",
	}, dm.DHCPRanges[0])

	require.Len(t, dm.DHCPOptions, 1)
	assert.Equal(t, DNSMasqDHCPOption{
		UUID: "00000000-0000-4000-8000-000000000004", Type: "set", Option: "6", Option6: "23",
		Interface: "lan", Tag: "t1", SetTag: "t2", Value: "9.9.9.9", Force: "1", Description: "DNS",
	}, dm.DHCPOptions[0])
}

// TestDNSMasq_RoundTrip encodes a decoded element and decodes it again.
func TestDNSMasq_RoundTrip(t *testing.T) {
	t.Parallel()

	var first DNSMasq
	require.NoError(t, xml.Unmarshal([]byte(dnsmasqModelElement), &first))

	out, err := xml.Marshal(&first)
	require.NoError(t, err)
	assert.Contains(t, string(out), `<aliases>files.internal,backup.internal</aliases>`)
	assert.Contains(t, string(out), `<dnsmasq version="1.0.9">`)

	var second DNSMasq
	require.NoError(t, xml.Unmarshal(out, &second))
	assert.Equal(t, first, second)
}

// TestDNSMasqHostAliases_LegacyItems decodes the legacy <item> shape the way
// the model flattens it, and writes it back in the model's form.
func TestDNSMasqHostAliases_LegacyItems(t *testing.T) {
	t.Parallel()

	const legacy = `<hosts><host>nas</host><aliases>
  <item><description>Files</description><domain>internal</domain><host>files</host></item>
  <item><description/><domain/><host>orphan</host></item>
  <item><description/><domain>backup.internal</domain><host/></item>
</aliases></hosts>`

	var h DNSMasqHost
	require.NoError(t, xml.Unmarshal([]byte(legacy), &h))
	assert.Equal(t, DNSMasqHostAliases{"files.internal", "backup.internal"}, h.Aliases)

	// Encoded by value, as a slice element is, the host still writes the
	// model form rather than one element per alias.
	out, err := xml.Marshal(h)
	require.NoError(t, err)
	assert.Equal(t, 1, strings.Count(string(out), "<aliases>"))
	assert.Contains(t, string(out), `<aliases>files.internal,backup.internal</aliases>`)

	var again DNSMasqHost
	require.NoError(t, xml.Unmarshal(out, &again))
	assert.Equal(t, h.Aliases, again.Aliases)
}

// TestDNSMasqHostAliases_Empty writes nothing for a host without aliases and
// reads an empty element as none.
func TestDNSMasqHostAliases_Empty(t *testing.T) {
	t.Parallel()

	var h DNSMasqHost
	require.NoError(t, xml.Unmarshal([]byte(`<hosts><host>a</host><aliases/></hosts>`), &h))
	assert.Empty(t, h.Aliases)

	out, err := xml.Marshal(h)
	require.NoError(t, err)
	assert.NotContains(t, string(out), "aliases")
}

// dnsmasqPlaceholderTypes lists the dnsmasq item types with an IsPlaceholder
// guard. Each carries a uuid attribute, which does not make an item real, so
// they have their own every-field test rather than the shared one.
var dnsmasqPlaceholderTypes = []struct {
	name string
	zero placeholderReporter
}{
	{name: "DNSMasqHost", zero: DNSMasqHost{}},
	{name: "DomainOverride", zero: DomainOverride{}},
	{name: "DNSMasqDHCPRange", zero: DNSMasqDHCPRange{}},
	{name: "DNSMasqDHCPOption", zero: DNSMasqDHCPOption{}},
}

// TestDNSMasq_IsPlaceholder_EveryFieldDefeatsIt sets each field but XMLName
// and UUID alone and requires the item to survive, so a field left out of a
// predicate fails here instead of dropping real config.
func TestDNSMasq_IsPlaceholder_EveryFieldDefeatsIt(t *testing.T) {
	t.Parallel()

	for _, tt := range dnsmasqPlaceholderTypes {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			typ := reflect.TypeOf(tt.zero)
			require.True(t, tt.zero.IsPlaceholder(), "zero value is a placeholder")

			withUUID := reflect.New(typ).Elem()
			withUUID.FieldByName("UUID").SetString("00000000-0000-4000-8000-000000000001")
			reporter, ok := withUUID.Interface().(placeholderReporter)
			require.True(t, ok)
			assert.True(t, reporter.IsPlaceholder(), "a uuid alone does not make an item real")

			for i := range typ.NumField() {
				field := typ.Field(i)
				if field.Name == xmlNameField || field.Name == "UUID" {
					continue
				}
				populated := reflect.New(typ).Elem()
				require.True(t, populateField(populated.Field(i)), "cannot populate %s.%s", tt.name, field.Name)
				reporter, ok := populated.Interface().(placeholderReporter)
				require.True(t, ok)
				assert.False(t, reporter.IsPlaceholder(),
					"%s with only %s set must not be a placeholder", tt.name, field.Name)
			}
		})
	}
}

// TestDNSMasq_IsPlaceholder_DecodedEmptyElement decodes the self-closing
// elements the legacy pages leave behind.
func TestDNSMasq_IsPlaceholder_DecodedEmptyElement(t *testing.T) {
	t.Parallel()

	var dm DNSMasq
	require.NoError(t, xml.Unmarshal([]byte(`<dnsmasq><hosts/><domainoverrides/>`+
		`<dhcp_ranges uuid="u1"/><dhcp_options uuid="u2"/></dnsmasq>`), &dm))
	require.Len(t, dm.Hosts, 1)
	require.Len(t, dm.DomainOverrides, 1)
	require.Len(t, dm.DHCPRanges, 1)
	require.Len(t, dm.DHCPOptions, 1)
	assert.True(t, dm.Hosts[0].IsPlaceholder())
	assert.True(t, dm.DomainOverrides[0].IsPlaceholder())
	assert.True(t, dm.DHCPRanges[0].IsPlaceholder())
	assert.True(t, dm.DHCPOptions[0].IsPlaceholder())
}
