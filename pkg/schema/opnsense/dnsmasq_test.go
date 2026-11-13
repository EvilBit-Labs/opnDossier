package opnsense

import (
	"encoding/xml"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// dnsmasqModelElement is a <dnsmasq> element in the shape the 26.7.9 model
// writes, one entry of each repeated item this schema binds.
const dnsmasqModelElement = `<dnsmasq version="1.0.9">
  <enable>1</enable>
  <dnssec>1</dnssec>
  <hosts uuid="00000000-0000-4000-8000-000000000001">
    <host>nas</host><domain>internal</domain><ip>192.168.1.10</ip>
    <descr>NAS</descr><aliases>files.internal,backup.internal</aliases>
  </hosts>
  <domainoverrides uuid="00000000-0000-4000-8000-000000000002">
    <domain>corp.example</domain><srcip>192.168.1.1</srcip><port>5353</port><ip>10.9.0.53</ip><descr>Corp</descr>
  </domainoverrides>
</dnsmasq>`

// TestDNSMasq_DecodesModelShape pins the element names the Dnsmasq model
// writes. The schema bound hosts>host and domainoverrides>domainoverride,
// which no release writes.
func TestDNSMasq_DecodesModelShape(t *testing.T) {
	t.Parallel()

	var dm DNSMasq
	require.NoError(t, xml.Unmarshal([]byte(dnsmasqModelElement), &dm))

	assert.Equal(t, "1.0.9", dm.Version)

	require.Len(t, dm.Hosts, 1)
	h := dm.Hosts[0]
	assert.Equal(t, "nas", h.Host)
	assert.Equal(t, DNSMasqHostAliases{"files.internal", "backup.internal"}, h.Aliases)

	require.Len(t, dm.DomainOverrides, 1)
	assert.Equal(t, "5353", dm.DomainOverrides[0].Port)
	assert.Equal(t, "192.168.1.1", dm.DomainOverrides[0].SrcIP)
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
