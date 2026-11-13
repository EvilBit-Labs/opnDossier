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

// dnsmasqInterfaces carries the factory LAN of 26.7.9 plus two more networks.
const dnsmasqInterfaces = `<interfaces>
    <wan><enable>1</enable><if>vtnet0</if><ipaddr>dhcp</ipaddr></wan>
    <lan><enable>1</enable><if>vtnet1</if><ipaddr>192.168.1.1</ipaddr><subnet>24</subnet></lan>
    <opt1><enable>1</enable><if>vtnet2</if><ipaddr>10.0.1.1</ipaddr><subnet>24</subnet></opt1>
    <opt2><enable>1</enable><if>vtnet3</if><ipaddr>10.0.2.1</ipaddr><subnet>24</subnet></opt2>
  </interfaces>`

// parseDnsmasqConfig runs a config holding the given <dnsmasq> element
// through parse and convert.
func parseDnsmasqConfig(t *testing.T, dnsmasq string) (*common.CommonDevice, []common.ConversionWarning) {
	t.Helper()

	config := `<?xml version="1.0"?>
<opnsense>
  <system><hostname>fw</hostname><domain>example.com</domain></system>
  ` + dnsmasqInterfaces + `
  ` + dnsmasq + `
</opnsense>`

	factory := parser.NewFactory(cfgparser.NewXMLParser())
	device, warnings, err := factory.CreateDevice(
		context.Background(), strings.NewReader(config), common.DeviceTypeUnknown, false)
	require.NoError(t, err)
	require.NotNil(t, device)

	return device, warnings
}

// dnsmasqWarnings keeps the warnings the dnsmasq conversion raised.
func dnsmasqWarnings(warnings []common.ConversionWarning) []common.ConversionWarning {
	var result []common.ConversionWarning
	for _, w := range warnings {
		if strings.HasPrefix(w.Field, "dnsmasq") || strings.HasPrefix(w.Field, "DNS.DNSMasq") {
			result = append(result, w)
		}
	}

	return result
}

// TestConverter_Dnsmasq_HostOverrides decodes the <hosts> entries of both
// generations. Each used to decode as an empty entry.
func TestConverter_Dnsmasq_HostOverrides(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		dnsmasq string
	}{
		{
			name: "model",
			dnsmasq: `<dnsmasq version="1.0.9"><enable>1</enable>
    <hosts uuid="00000000-0000-4000-8000-000000000201"><host>printer</host><domain>internal</domain><ip>192.168.1.50</ip><descr/></hosts>
    <hosts uuid="00000000-0000-4000-8000-000000000202"><host>nas</host><domain>internal</domain><ip>192.168.1.10,fd00::10</ip><descr>NAS box</descr><aliases>files.internal,backup.internal</aliases></hosts>
  </dnsmasq>`,
		},
		{
			name: "legacy page",
			dnsmasq: `<dnsmasq><enable>1</enable>
    <hosts><host>printer</host><domain>internal</domain><ip>192.168.1.50</ip><descr/><aliases/></hosts>
    <hosts><host>nas</host><domain>internal</domain><ip>192.168.1.10,fd00::10</ip><descr>NAS box</descr>
      <aliases>
        <item><description>Files</description><domain>internal</domain><host>files</host></item>
        <item><description/><domain/><host>orphan</host></item>
        <item><description/><domain>backup.internal</domain><host/></item>
      </aliases>
    </hosts>
  </dnsmasq>`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			device, warnings := parseDnsmasqConfig(t, tt.dnsmasq)
			assert.Empty(t, dnsmasqWarnings(warnings))
			assert.Equal(t, []common.DNSMasqHost{
				{Host: "printer", Domain: "internal", IP: "192.168.1.50"},
				{
					Host: "nas", Domain: "internal", IP: "192.168.1.10,fd00::10", Description: "NAS box",
					Aliases: []string{"files.internal", "backup.internal"},
				},
			}, device.DNS.DNSMasq.Hosts)
		})
	}
}

// TestConverter_Dnsmasq_DomainOverrides reads the per-domain DNS servers,
// which were never read on any release.
func TestConverter_Dnsmasq_DomainOverrides(t *testing.T) {
	t.Parallel()

	device, _ := parseDnsmasqConfig(t, `<dnsmasq version="1.0.9"><enable>1</enable>
    <domainoverrides uuid="00000000-0000-4000-8000-000000000301"><sequence>1</sequence><domain>lab.example</domain><ipset/><srcip/><port/><ip>10.0.0.53</ip><descr>Lab</descr></domainoverrides>
    <domainoverrides uuid="00000000-0000-4000-8000-000000000302"><sequence>2</sequence><domain>corp.example</domain><ipset/><srcip>192.168.1.1</srcip><port>5353</port><ip>10.9.0.53</ip><descr>Corp DNS</descr></domainoverrides>
  </dnsmasq>`)

	assert.Equal(t, []common.DomainOverride{
		{Domain: "lab.example", IP: "10.0.0.53", Description: "Lab"},
		{Domain: "corp.example", IP: "10.9.0.53", Description: "Corp DNS", Port: "5353", SourceIP: "192.168.1.1"},
	}, device.DNS.DNSMasq.DomainOverrides)

	legacy, _ := parseDnsmasqConfig(t, `<dnsmasq><enable>1</enable>
    <domainoverrides><domain>lab.example</domain><ip>10.0.0.53</ip><descr>Lab</descr></domainoverrides>
    <domainoverrides><domain>corp.example</domain><ip>10.9.0.53#5353@192.168.1.1</ip><descr>Corp DNS</descr></domainoverrides>
  </dnsmasq>`)

	assert.Equal(t, []common.DomainOverride{
		{Domain: "lab.example", IP: "10.0.0.53", Description: "Lab"},
		{Domain: "corp.example", IP: "10.9.0.53#5353@192.168.1.1", Description: "Corp DNS"},
	}, legacy.DNS.DNSMasq.DomainOverrides)
}

// TestConverter_Dnsmasq_ModelVersionPinned warns on a model version the
// schema was not checked against, and on no other.
func TestConverter_Dnsmasq_ModelVersionPinned(t *testing.T) {
	t.Parallel()

	for _, version := range []string{"1.0.0", "1.0.5", "1.0.6", "1.0.7", "1.0.8", "1.0.9"} {
		device, warnings := parseDnsmasqConfig(t, `<dnsmasq version="`+version+`"><enable>1</enable></dnsmasq>`)
		require.NotNil(t, device)
		assert.Empty(t, dnsmasqWarnings(warnings), version)
	}

	_, warnings := parseDnsmasqConfig(t, `<dnsmasq version="2.0.0"><enable>1</enable></dnsmasq>`)
	got := dnsmasqWarnings(warnings)
	require.Len(t, got, 1)
	assert.Equal(t, "DNS.DNSMasq.Version", got[0].Field)
	assert.Equal(t, "2.0.0", got[0].Value)
	assert.Equal(t, common.SeverityMedium, got[0].Severity)
}
