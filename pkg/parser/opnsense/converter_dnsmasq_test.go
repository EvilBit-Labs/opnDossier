package opnsense_test

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/analysis"
	"github.com/EvilBit-Labs/opnDossier/internal/cfgparser"
	"github.com/EvilBit-Labs/opnDossier/internal/compliance"
	"github.com/EvilBit-Labs/opnDossier/internal/diff"
	"github.com/EvilBit-Labs/opnDossier/internal/plugins/firewall"
	"github.com/EvilBit-Labs/opnDossier/internal/plugins/stig"
	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
	"github.com/EvilBit-Labs/opnDossier/pkg/parser"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// dnsmasqInterfaces carries the factory LAN of 26.7.9 plus two more networks,
// so that a reservation can be placed by its address.
const dnsmasqInterfaces = `<interfaces>
    <wan><enable>1</enable><if>vtnet0</if><ipaddr>dhcp</ipaddr></wan>
    <lan><enable>1</enable><if>vtnet1</if><ipaddr>192.168.1.1</ipaddr><subnet>24</subnet></lan>
    <opt1><enable>1</enable><if>vtnet2</if><ipaddr>10.0.1.1</ipaddr><subnet>24</subnet></opt1>
    <opt2><enable>1</enable><if>vtnet3</if><ipaddr>10.0.2.1</ipaddr><subnet>24</subnet></opt2>
  </interfaces>`

// dnsmasqFactoryDefault is the <dnsmasq> element of the 26.7.9
// config.xml.sample as shipped, which has no version attribute until the
// model is first saved.
const dnsmasqFactoryDefault = `<dnsmasq>
    <enable>1</enable>
    <port>53053</port>
    <interface>lan</interface>
    <dhcp>
      <enable_ra>1</enable_ra>
    </dhcp>
    <dhcp_ranges>
      <interface>lan</interface>
      <start_addr>192.168.1.100</start_addr>
      <end_addr>192.168.1.199</end_addr>
    </dhcp_ranges>
    <dhcp_ranges>
      <interface>lan</interface>
      <start_addr>::1000</start_addr>
      <end_addr>::2000</end_addr>
      <constructor>lan</constructor>
      <ra_mode>slaac</ra_mode>
    </dhcp_ranges>
  </dnsmasq>`

// threeRanges serves IPv4 on lan, opt1 and opt2, as a box with a guest and an
// IoT network does.
const threeRanges = `<dnsmasq version="1.0.9">
    <enable>1</enable>
    <port>53053</port>
    <dhcp_ranges uuid="00000000-0000-4000-8000-000000000001">
      <interface>lan</interface>
      <start_addr>192.168.1.100</start_addr>
      <end_addr>192.168.1.199</end_addr>
    </dhcp_ranges>
    <dhcp_ranges uuid="00000000-0000-4000-8000-000000000002">
      <interface>opt1</interface>
      <start_addr>10.0.1.100</start_addr>
      <end_addr>10.0.1.199</end_addr>
    </dhcp_ranges>
    <dhcp_ranges uuid="00000000-0000-4000-8000-000000000003">
      <interface>opt2</interface>
      <start_addr>10.0.2.100</start_addr>
      <end_addr>10.0.2.199</end_addr>
    </dhcp_ranges>
  </dnsmasq>`

// parseDnsmasqConfig runs a config holding the given <dnsmasq> element, and
// whatever else extra holds, through parse and convert.
func parseDnsmasqConfig(t *testing.T, dnsmasq, extra string) (*common.CommonDevice, []common.ConversionWarning) {
	t.Helper()

	config := `<?xml version="1.0"?>
<opnsense>
  <system><hostname>fw</hostname><domain>example.com</domain></system>
  ` + dnsmasqInterfaces + `
  ` + dnsmasq + `
  ` + extra + `
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

// hasReference reports whether a finding cites the control.
func hasReference(findings []compliance.Finding, control string) bool {
	return slices.ContainsFunc(findings, func(f compliance.Finding) bool {
		return slices.Contains(f.References, control)
	})
}

// TestConverter_Dnsmasq_FactoryDefaultServesLANDHCP pins the 26.7.9 factory
// default: dnsmasq serves DHCP on LAN, and before the fix the config
// converted to no DHCP at all.
func TestConverter_Dnsmasq_FactoryDefaultServesLANDHCP(t *testing.T) {
	t.Parallel()

	device, warnings := parseDnsmasqConfig(t, dnsmasqFactoryDefault, "")
	assert.Empty(t, dnsmasqWarnings(warnings))

	require.Len(t, device.DHCP, 1)
	scope := device.DHCP[0]
	assert.Equal(t, "lan", scope.Interface)
	assert.Equal(t, common.DHCPSourceDnsmasq, scope.Source)
	assert.True(t, scope.Enabled)
	assert.Equal(t, common.DHCPRange{From: "192.168.1.100", To: "192.168.1.199"}, scope.Range)
	require.NotNil(t, scope.RangeV6)
	assert.Equal(t, common.DHCPRange{From: "::1000", To: "::2000"}, *scope.RangeV6)

	assert.True(t, device.DNS.DNSMasq.Enabled)
	assert.Equal(t, "53053", device.DNS.DNSMasq.Port)
	assert.False(t, device.DNS.DNSMasq.DNSSEC)

	findings, _, err := firewall.NewPlugin().RunChecks(device)
	require.NoError(t, err)
	assert.True(t, hasReference(findings, "FIREWALL-062"), "the DHCP inventory must list the LAN scope")
	for _, f := range findings {
		if slices.Contains(f.References, "FIREWALL-062") {
			assert.Contains(t, f.Description, "1 dnsmasq DHCP scope(s) on: lan")
		}
	}
}

// TestConverter_Dnsmasq_ScopesReachTheChecks drives three IPv4 ranges through
// the checks that count DHCP scopes. The same three scopes under ISC or Kea
// fail V-206690; under dnsmasq they passed, and opt1 and opt2 read as unused.
func TestConverter_Dnsmasq_ScopesReachTheChecks(t *testing.T) {
	t.Parallel()

	device, warnings := parseDnsmasqConfig(t, threeRanges, "")
	assert.Empty(t, dnsmasqWarnings(warnings))

	require.Len(t, device.DHCP, 3)
	assert.Equal(t, "opt1", device.DHCP[1].Interface)
	assert.Equal(t, common.DHCPRange{From: "10.0.1.100", To: "10.0.1.199"}, device.DHCP[1].Range)
	assert.Nil(t, device.DHCP[1].RangeV6)

	stigFindings, _, err := stig.NewPlugin().RunChecks(device)
	require.NoError(t, err)
	assert.True(t, hasReference(stigFindings, "V-206690"))

	// The factory default's one scope stays under the limit, so the finding
	// above comes from the ranges and not from something else in the config.
	oneScope, _ := parseDnsmasqConfig(t, dnsmasqFactoryDefault, "")
	stigFindings, _, err = stig.NewPlugin().RunChecks(oneScope)
	require.NoError(t, err)
	assert.False(t, hasReference(stigFindings, "V-206690"))

	for _, unused := range analysis.DetectUnusedInterfaces(device) {
		assert.NotContains(t, []string{"opt1", "opt2"}, unused.InterfaceName,
			"an interface dnsmasq serves DHCP on is in use")
	}
}

// TestConverter_Dnsmasq_ScopeEnabled checks that a scope is enabled only
// where dnsmasq runs and serves DHCP.
func TestConverter_Dnsmasq_ScopeEnabled(t *testing.T) {
	t.Parallel()

	ranges := `<dhcp_ranges><interface>lan</interface><start_addr>192.168.1.100</start_addr>` +
		`<end_addr>192.168.1.199</end_addr></dhcp_ranges>` +
		`<dhcp_ranges><interface>opt1</interface><start_addr>10.0.1.100</start_addr>` +
		`<end_addr>10.0.1.199</end_addr></dhcp_ranges>`

	tests := []struct {
		name     string
		settings string
		wantLAN  bool
		wantOpt1 bool
	}{
		{name: "enabled on every interface", settings: `<enable>1</enable>`, wantLAN: true, wantOpt1: true},
		{name: "service disabled", settings: `<enable>0</enable>`, wantLAN: false, wantOpt1: false},
		{
			name:     "DHCP turned off on one interface",
			settings: `<enable>1</enable><dhcp><no_interface>opt1</no_interface></dhcp>`,
			wantLAN:  true,
			wantOpt1: false,
		},
		{
			name:     "listening on another interface only",
			settings: `<enable>1</enable><interface>lan,wan</interface>`,
			wantLAN:  true,
			wantOpt1: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			device, _ := parseDnsmasqConfig(t, `<dnsmasq version="1.0.9">`+tt.settings+ranges+`</dnsmasq>`, "")
			require.Len(t, device.DHCP, 2)
			assert.Equal(t, tt.wantLAN, device.DHCP[0].Enabled, "lan")
			assert.Equal(t, tt.wantOpt1, device.DHCP[1].Enabled, "opt1")
		})
	}
}

// TestConverter_Dnsmasq_RangeWithoutInterface keeps a range that serves any
// interface, and folds a second range of one family into a warning.
func TestConverter_Dnsmasq_RangeWithoutInterface(t *testing.T) {
	t.Parallel()

	device, warnings := parseDnsmasqConfig(t, `<dnsmasq version="1.0.9"><enable>1</enable>
    <dhcp_ranges><start_addr>192.168.1.100</start_addr><end_addr>192.168.1.149</end_addr></dhcp_ranges>
    <dhcp_ranges><start_addr>192.168.1.150</start_addr><end_addr>192.168.1.199</end_addr></dhcp_ranges>
    <dhcp_ranges><interface>lan</interface><start_addr></start_addr></dhcp_ranges>
  </dnsmasq>`, "")

	require.Len(t, device.DHCP, 1)
	assert.Empty(t, device.DHCP[0].Interface)
	assert.True(t, device.DHCP[0].Enabled)
	assert.Equal(t, "192.168.1.100", device.DHCP[0].Range.From)

	got := dnsmasqWarnings(warnings)
	require.Len(t, got, 2)
	assert.Equal(t, "dnsmasq.dhcp_ranges", got[0].Field)
	assert.Equal(t, "192.168.1.150 - 192.168.1.199", got[0].Value)
	assert.Equal(t, "dnsmasq.dhcp_ranges.start_addr", got[1].Field)
}

// TestConverter_Dnsmasq_DHCPOptions maps the options dnsmasq sends into the
// scopes. An interface-bound option overrides one that names no interface.
func TestConverter_Dnsmasq_DHCPOptions(t *testing.T) {
	t.Parallel()

	device, warnings := parseDnsmasqConfig(t, `<dnsmasq version="1.0.9"><enable>1</enable>
    <dhcp_ranges><interface>lan</interface><start_addr>192.168.1.100</start_addr><end_addr>192.168.1.199</end_addr></dhcp_ranges>
    <dhcp_ranges><interface>opt2</interface><start_addr>10.0.2.100</start_addr><end_addr>10.0.2.199</end_addr></dhcp_ranges>
    <dhcp_options><type>set</type><option>6</option><value>192.168.1.53</value></dhcp_options>
    <dhcp_options><type>set</type><option>6</option><interface>opt2</interface><value>9.9.9.9,149.112.112.112</value></dhcp_options>
    <dhcp_options><type>set</type><option>3</option><interface>opt2</interface><value>10.0.2.254</value></dhcp_options>
    <dhcp_options><type>set</type><option>42</option><value>192.168.1.123</value></dhcp_options>
    <dhcp_options><type>set</type><option>66</option><interface>opt2</interface><value>tftp.example.com</value></dhcp_options>
    <dhcp_options uuid="00000000-0000-4000-8000-0000000000aa"><type>set</type><option>6</option><tag>11111111-1111-4111-8111-111111111111</tag><value>1.1.1.1</value></dhcp_options>
    <dhcp_options uuid="00000000-0000-4000-8000-0000000000bb"><type>set</type><option6>23</option6><value>[2001:db8::53]</value></dhcp_options>
  </dnsmasq>`, "")

	require.Len(t, device.DHCP, 2)
	lan, opt2 := device.DHCP[0], device.DHCP[1]

	assert.Equal(t, []string{"192.168.1.53"}, lan.DNSServers)
	assert.Empty(t, lan.Gateway)
	assert.Equal(t, "192.168.1.123", lan.NTPServer)
	assert.Empty(t, lan.NumberOptions)

	assert.Equal(t, []string{"9.9.9.9", "149.112.112.112"}, opt2.DNSServers)
	assert.Equal(t, "10.0.2.254", opt2.Gateway)
	assert.Equal(t, "192.168.1.123", opt2.NTPServer)
	assert.Equal(t, []common.DHCPNumberOption{{Number: "66", Value: "tftp.example.com"}}, opt2.NumberOptions)

	got := dnsmasqWarnings(warnings)
	require.Len(t, got, 2, "one warning per option the scope cannot hold")
	assert.Equal(t, "00000000-0000-4000-8000-0000000000aa", got[0].Value)
	assert.Equal(t, "00000000-0000-4000-8000-0000000000bb", got[1].Value)
}

// TestConverter_Dnsmasq_Reservations turns <hosts> entries with a hardware
// address or client id into static leases on the scope whose network holds
// their address. Entries that are only host overrides stay out.
func TestConverter_Dnsmasq_Reservations(t *testing.T) {
	t.Parallel()

	device, warnings := parseDnsmasqConfig(t, `<dnsmasq version="1.0.9"><enable>1</enable>
    <hosts uuid="00000000-0000-4000-8000-000000000101">
      <host>nas</host><domain>internal</domain><ip>192.168.1.60</ip><descr>NAS</descr>
    </hosts>
    <hosts uuid="00000000-0000-4000-8000-000000000102">
      <host>printer</host><ip>10.0.1.50</ip><hwaddr>aa:bb:cc:dd:ee:01</hwaddr><descr>Printer</descr>
    </hosts>
    <hosts uuid="00000000-0000-4000-8000-000000000103">
      <host>phone</host><ip>192.168.1.70</ip><client_id>01:02:f3</client_id>
    </hosts>
    <hosts uuid="00000000-0000-4000-8000-000000000104">
      <host>blocked</host><hwaddr>aa:bb:cc:dd:ee:02</hwaddr><ignore>1</ignore>
    </hosts>
    <hosts uuid="00000000-0000-4000-8000-000000000105">
      <host>stray</host><ip>172.16.0.9</ip><hwaddr>aa:bb:cc:dd:ee:03</hwaddr>
    </hosts>
    <hosts uuid="00000000-0000-4000-8000-000000000106">
      <host>nomac</host><ip>192.168.1.80</ip><hwaddr>aabbccddee04</hwaddr>
    </hosts>
    <dhcp_ranges><interface>lan</interface><start_addr>192.168.1.100</start_addr><end_addr>192.168.1.199</end_addr></dhcp_ranges>
    <dhcp_ranges><interface>opt1</interface><start_addr>10.0.1.100</start_addr><end_addr>10.0.1.199</end_addr></dhcp_ranges>
  </dnsmasq>`, "")

	require.Len(t, device.DHCP, 2)
	assert.Equal(t, []common.DHCPStaticLease{
		{CID: "01:02:f3", IPAddress: "192.168.1.70", Hostname: "phone"},
	}, device.DHCP[0].StaticLeases)
	assert.Equal(t, []common.DHCPStaticLease{
		{MAC: "aa:bb:cc:dd:ee:01", IPAddress: "10.0.1.50", Hostname: "printer", Description: "Printer"},
	}, device.DHCP[1].StaticLeases)

	got := dnsmasqWarnings(warnings)
	require.Len(t, got, 2)
	assert.Equal(t, "dnsmasq.hosts.ignore", got[0].Field)
	assert.Equal(t, "blocked", got[0].Value)
	assert.Equal(t, "dnsmasq.hosts", got[1].Field)
	assert.Equal(t, "stray", got[1].Value)

	assert.Len(t, device.DNS.DNSMasq.Hosts, 6, "every entry is a host override as well")
}

// TestConverter_Dnsmasq_ReservationFallsBackToOnlyScope attaches a reservation
// with no IPv4 address to the only scope that serves IPv4.
func TestConverter_Dnsmasq_ReservationFallsBackToOnlyScope(t *testing.T) {
	t.Parallel()

	device, warnings := parseDnsmasqConfig(t, dnsmasqFactoryDefault[:len(dnsmasqFactoryDefault)-len("</dnsmasq>")]+
		`<hosts><host>laptop</host><hwaddr>aa:bb:cc:dd:ee:05</hwaddr></hosts></dnsmasq>`, "")

	assert.Empty(t, dnsmasqWarnings(warnings))
	require.Len(t, device.DHCP, 1)
	assert.Equal(t, []common.DHCPStaticLease{{MAC: "aa:bb:cc:dd:ee:05", Hostname: "laptop"}},
		device.DHCP[0].StaticLeases)
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

			device, warnings := parseDnsmasqConfig(t, tt.dnsmasq, "")
			assert.Empty(t, dnsmasqWarnings(warnings))
			assert.Equal(t, []common.DNSMasqHost{
				{Host: "printer", Domain: "internal", IP: "192.168.1.50"},
				{
					Host: "nas", Domain: "internal", IP: "192.168.1.10,fd00::10", Description: "NAS box",
					Aliases: []string{"files.internal", "backup.internal"},
				},
			}, device.DNS.DNSMasq.Hosts)
			assert.Empty(t, device.DHCP, "a host override alone is not a DHCP scope")
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
  </dnsmasq>`, "")

	assert.Equal(t, []common.DomainOverride{
		{Domain: "lab.example", IP: "10.0.0.53", Description: "Lab"},
		{Domain: "corp.example", IP: "10.9.0.53", Description: "Corp DNS", Port: "5353", SourceIP: "192.168.1.1"},
	}, device.DNS.DNSMasq.DomainOverrides)

	legacy, _ := parseDnsmasqConfig(t, `<dnsmasq><enable>1</enable>
    <domainoverrides><domain>lab.example</domain><ip>10.0.0.53</ip><descr>Lab</descr></domainoverrides>
    <domainoverrides><domain>corp.example</domain><ip>10.9.0.53#5353@192.168.1.1</ip><descr>Corp DNS</descr></domainoverrides>
  </dnsmasq>`, "")

	assert.Equal(t, []common.DomainOverride{
		{Domain: "lab.example", IP: "10.0.0.53", Description: "Lab"},
		{Domain: "corp.example", IP: "10.9.0.53#5353@192.168.1.1", Description: "Corp DNS"},
	}, legacy.DNS.DNSMasq.DomainOverrides)
}

// TestConverter_Dnsmasq_DNSSEC reads <dnssec> the way each generation does:
// the model compares the value with "1", the legacy page tested presence.
func TestConverter_Dnsmasq_DNSSEC(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		dnsmasq string
		want    bool
	}{
		{name: "model off", dnsmasq: `<dnsmasq version="1.0.9"><dnssec>0</dnssec></dnsmasq>`, want: false},
		{name: "model on", dnsmasq: `<dnsmasq version="1.0.9"><dnssec>1</dnssec></dnsmasq>`, want: true},
		{name: "model empty", dnsmasq: `<dnsmasq version="1.0.9"><dnssec/></dnsmasq>`, want: false},
		{name: "model absent", dnsmasq: `<dnsmasq version="1.0.9"><enable>1</enable></dnsmasq>`, want: false},
		{name: "legacy on", dnsmasq: `<dnsmasq><dnssec>1</dnssec></dnsmasq>`, want: true},
		{name: "legacy empty element", dnsmasq: `<dnsmasq><dnssec/></dnsmasq>`, want: true},
		{name: "legacy absent", dnsmasq: `<dnsmasq><enable>1</enable></dnsmasq>`, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			device, _ := parseDnsmasqConfig(t, tt.dnsmasq, "")
			assert.Equal(t, tt.want, device.DNS.DNSMasq.DNSSEC)
		})
	}
}

// TestConverter_Dnsmasq_FIREWALL058 decides FIREWALL-058 on a box whose
// resolver is dnsmasq. It failed whenever Unbound was off.
func TestConverter_Dnsmasq_FIREWALL058(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		settings string
		extra    string
		wantPass bool
	}{
		{name: "dnsmasq on the default port with DNSSEC", settings: `<dnssec>1</dnssec>`, wantPass: true},
		{name: "dnsmasq on port 53 with DNSSEC", settings: `<port>53</port><dnssec>1</dnssec>`, wantPass: true},
		{name: "dnsmasq without DNSSEC", settings: `<dnssec>0</dnssec>`, wantPass: false},
		{name: "dnsmasq on another port", settings: `<port>53053</port><dnssec>1</dnssec>`, wantPass: false},
		{name: "dnsmasq DNS turned off", settings: `<port>0</port><dnssec>1</dnssec>`, wantPass: false},
		{
			name:     "Unbound decides when it is enabled",
			settings: `<dnssec>1</dnssec>`,
			extra:    `<unbound><enable>1</enable></unbound>`,
			wantPass: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			device, _ := parseDnsmasqConfig(t,
				`<dnsmasq version="1.0.9"><enable>1</enable>`+tt.settings+`</dnsmasq>`, tt.extra)
			findings, evaluated, err := firewall.NewPlugin().RunChecks(device)
			require.NoError(t, err)

			assert.Contains(t, evaluated, "FIREWALL-058")
			assert.Equal(t, !tt.wantPass, hasReference(findings, "FIREWALL-058"))
		})
	}
}

// TestConverter_Dnsmasq_ModelVersionPinned warns on a model version the
// schema was not checked against, and on no other.
func TestConverter_Dnsmasq_ModelVersionPinned(t *testing.T) {
	t.Parallel()

	for _, version := range []string{"1.0.0", "1.0.5", "1.0.6", "1.0.7", "1.0.8", "1.0.9"} {
		device, warnings := parseDnsmasqConfig(t, `<dnsmasq version="`+version+`"><enable>1</enable></dnsmasq>`, "")
		require.NotNil(t, device)
		assert.Empty(t, dnsmasqWarnings(warnings), version)
	}

	_, warnings := parseDnsmasqConfig(t, `<dnsmasq version="2.0.0"><enable>1</enable></dnsmasq>`, "")
	got := dnsmasqWarnings(warnings)
	require.Len(t, got, 1)
	assert.Equal(t, "DNS.DNSMasq.Version", got[0].Field)
	assert.Equal(t, "2.0.0", got[0].Value)
	assert.Equal(t, common.SeverityMedium, got[0].Severity)
}

// TestConverter_Dnsmasq_Placeholders drops the empty <hosts/> and
// <domainoverrides/> the legacy pages leave once the last entry is deleted,
// and the same empty model items, without a warning.
func TestConverter_Dnsmasq_Placeholders(t *testing.T) {
	t.Parallel()

	device, warnings := parseDnsmasqConfig(t, `<dnsmasq><enable>1</enable>
    <hosts/>
    <domainoverrides/>
    <dhcp_ranges uuid="00000000-0000-4000-8000-000000000001"/>
    <dhcp_options uuid="00000000-0000-4000-8000-000000000002"/>
  </dnsmasq>`, "")

	assert.Empty(t, dnsmasqWarnings(warnings))
	assert.Nil(t, device.DNS.DNSMasq.Hosts)
	assert.Nil(t, device.DNS.DNSMasq.DomainOverrides)
	assert.Empty(t, device.DHCP)

	// A placeholder beside a real entry leaves only the real one.
	device, _ = parseDnsmasqConfig(t, `<dnsmasq><enable>1</enable>
    <hosts/>
    <hosts><host>nas</host><ip>192.168.1.10</ip></hosts>
  </dnsmasq>`, "")
	assert.Equal(t, []common.DNSMasqHost{{Host: "nas", IP: "192.168.1.10"}}, device.DNS.DNSMasq.Hosts)
}

// TestConverter_Dnsmasq_RangesThatServeNoPool keeps router-advertisement-only
// entries out of the DHCP scopes, keeps a stateless DHCPv6 entry as a scope
// with no pool, and leaves a static range's pool empty.
func TestConverter_Dnsmasq_RangesThatServeNoPool(t *testing.T) {
	t.Parallel()

	device, warnings := parseDnsmasqConfig(t, `<dnsmasq version="1.0.9"><enable>1</enable>
    <dhcp><enable_ra>1</enable_ra></dhcp>
    <dhcp_ranges><interface>lan</interface><start_addr>192.168.1.100</start_addr><end_addr>192.168.1.199</end_addr></dhcp_ranges>
    <dhcp_ranges><interface>opt1</interface><start_addr>::</start_addr><constructor>opt1</constructor><ra_mode>ra-only</ra_mode></dhcp_ranges>
    <dhcp_ranges><interface>opt2</interface><start_addr>::</start_addr><constructor>opt2</constructor><ra_mode>ra-stateless</ra_mode></dhcp_ranges>
    <dhcp_ranges><interface>lan</interface><start_addr>::</start_addr><constructor>lan</constructor><ra_mode>slaac</ra_mode></dhcp_ranges>
    <dhcp_ranges><interface>opt3</interface><start_addr>::</start_addr><constructor>opt3</constructor></dhcp_ranges>
  </dnsmasq>`, "")

	assert.Empty(t, dnsmasqWarnings(warnings))
	require.Len(t, device.DHCP, 2, "ra-only and mode-less entries are router advertisements alone")
	assert.Equal(t, "lan", device.DHCP[0].Interface)
	assert.Nil(t, device.DHCP[0].RangeV6)
	opt2 := device.DHCP[1]
	assert.Equal(t, "opt2", opt2.Interface, "ra-stateless answers stateless DHCPv6")
	assert.True(t, opt2.Enabled)
	assert.Nil(t, opt2.RangeV6, "a stateless DHCPv6 service hands out no addresses")
	assert.Equal(t, common.DHCPRange{}, opt2.Range)

	stigFindings, _, err := stig.NewPlugin().RunChecks(device)
	require.NoError(t, err)
	assert.False(t, hasReference(stigFindings, "V-206690"))

	device, warnings = parseDnsmasqConfig(t, `<dnsmasq version="1.0.9"><enable>1</enable>
    <dhcp_ranges><interface>lan</interface><start_addr>192.168.1.100</start_addr><end_addr>192.168.1.199</end_addr></dhcp_ranges>
    <dhcp_ranges><interface>opt1</interface><start_addr>10.0.1.0</start_addr><mode>static</mode></dhcp_ranges>
    <hosts><host>cam</host><ip>10.0.1.40</ip><hwaddr>aa:bb:cc:dd:ee:10</hwaddr></hosts>
  </dnsmasq>`, "")

	assert.Empty(t, dnsmasqWarnings(warnings))
	require.Len(t, device.DHCP, 2)
	opt1 := device.DHCP[1]
	assert.Equal(t, "opt1", opt1.Interface)
	assert.True(t, opt1.Enabled, "a static range still serves its reservations")
	assert.Equal(t, common.DHCPRange{}, opt1.Range, "a static range hands out no pool")
	assert.Equal(t, []common.DHCPStaticLease{{MAC: "aa:bb:cc:dd:ee:10", IPAddress: "10.0.1.40", Hostname: "cam"}},
		opt1.StaticLeases)
}

// TestConverter_Dnsmasq_ReservationPlacement checks the rules that place a
// lease by its address.
func TestConverter_Dnsmasq_ReservationPlacement(t *testing.T) {
	t.Parallel()

	lanRange := `<dhcp_ranges><interface>lan</interface><start_addr>192.168.1.100</start_addr>` +
		`<end_addr>192.168.1.199</end_addr></dhcp_ranges>`

	// IPv6 listed first: the IPv4 address still places the lease.
	device, warnings := parseDnsmasqConfig(t, `<dnsmasq version="1.0.9"><enable>1</enable>`+lanRange+
		`<dhcp_ranges><interface>opt1</interface><start_addr>10.0.1.100</start_addr><end_addr>10.0.1.199</end_addr></dhcp_ranges>`+
		`<hosts><host>dual</host><ip>fd00::5,10.0.1.5</ip><hwaddr>aa:bb:cc:dd:ee:20</hwaddr></hosts></dnsmasq>`, "")
	assert.Empty(t, dnsmasqWarnings(warnings))
	require.Len(t, device.DHCP, 2)
	assert.Empty(t, device.DHCP[0].StaticLeases)
	require.Len(t, device.DHCP[1].StaticLeases, 1)
	assert.Equal(t, "dual", device.DHCP[1].StaticLeases[0].Hostname)

	// An IPv4 address outside every network is reported, not attached to the
	// only scope.
	device, warnings = parseDnsmasqConfig(t, `<dnsmasq version="1.0.9"><enable>1</enable>`+lanRange+
		`<hosts><host>far</host><ip>10.20.30.40</ip><hwaddr>aa:bb:cc:dd:ee:21</hwaddr></hosts></dnsmasq>`, "")
	require.Len(t, device.DHCP, 1)
	assert.Empty(t, device.DHCP[0].StaticLeases)
	got := dnsmasqWarnings(warnings)
	require.Len(t, got, 1)
	assert.Equal(t, "far", got[0].Value)

	// A range for any interface takes a lease whose address is on one of the
	// firewall's networks.
	device, warnings = parseDnsmasqConfig(t, `<dnsmasq version="1.0.9"><enable>1</enable>`+
		`<dhcp_ranges><start_addr>10.0.2.100</start_addr><end_addr>10.0.2.199</end_addr></dhcp_ranges>`+
		`<hosts><host>iot</host><ip>10.0.2.50</ip><hwaddr>aa:bb:cc:dd:ee:22</hwaddr></hosts></dnsmasq>`, "")
	assert.Empty(t, dnsmasqWarnings(warnings))
	require.Len(t, device.DHCP, 1)
	require.Len(t, device.DHCP[0].StaticLeases, 1)
	assert.Equal(t, "iot", device.DHCP[0].StaticLeases[0].Hostname)
}

// TestConverter_Dnsmasq_AnyRangeWithListenList keeps a range that names no
// interface enabled when dnsmasq listens on named interfaces only.
func TestConverter_Dnsmasq_AnyRangeWithListenList(t *testing.T) {
	t.Parallel()

	device, _ := parseDnsmasqConfig(t, `<dnsmasq version="1.0.9"><enable>1</enable><interface>lan</interface>
    <dhcp_ranges><start_addr>192.168.1.100</start_addr><end_addr>192.168.1.199</end_addr></dhcp_ranges>
  </dnsmasq>`, "")
	require.Len(t, device.DHCP, 1)
	assert.True(t, device.DHCP[0].Enabled)
}

// TestConverter_Dnsmasq_LegacyDomainOnlyHost reads a legacy entry that names
// only a domain as migration M1_0_0 does: the domain is the host name.
func TestConverter_Dnsmasq_LegacyDomainOnlyHost(t *testing.T) {
	t.Parallel()

	device, _ := parseDnsmasqConfig(t, `<dnsmasq><enable>1</enable>
    <hosts><host/><domain>wpad.example.com</domain><ip>192.168.1.5</ip><descr/></hosts>
  </dnsmasq>`, "")
	assert.Equal(t, []common.DNSMasqHost{{Host: "wpad.example.com", IP: "192.168.1.5"}}, device.DNS.DNSMasq.Hosts)
}

// TestConverter_Dnsmasq_DisabledScopesDoNotCount fails V-206690 on enabled
// scopes only. A disabled dnsmasq beside two Kea subnets used to tip it.
func TestConverter_Dnsmasq_DisabledScopesDoNotCount(t *testing.T) {
	t.Parallel()

	kea := `<OPNsense><Kea><dhcp4 version="1.0.4">
      <general><enabled>1</enabled><interfaces>lan,opt1</interfaces></general>
      <subnets>
        <subnet4 uuid="10000000-0000-4000-8000-000000000001"><subnet>192.168.1.0/24</subnet><pools>192.168.1.100-192.168.1.199</pools></subnet4>
        <subnet4 uuid="10000000-0000-4000-8000-000000000002"><subnet>10.0.1.0/24</subnet><pools>10.0.1.100-10.0.1.199</pools></subnet4>
      </subnets>
    </dhcp4></Kea></OPNsense>`
	lanRange := `<dhcp_ranges><interface>lan</interface><start_addr>192.168.1.100</start_addr>` +
		`<end_addr>192.168.1.199</end_addr></dhcp_ranges>`

	for _, tt := range []struct {
		enable string
		want   bool
	}{{enable: "0", want: false}, {enable: "1", want: true}} {
		device, _ := parseDnsmasqConfig(
			t,
			`<dnsmasq version="1.0.9"><enable>`+tt.enable+`</enable>`+lanRange+`</dnsmasq>`,
			kea,
		)
		require.Len(t, device.DHCP, 3)
		findings, _, err := stig.NewPlugin().RunChecks(device)
		require.NoError(t, err)
		assert.Equal(t, tt.want, hasReference(findings, "V-206690"), "dnsmasq enable %s", tt.enable)
	}
}

// mixedISC is an ISC scope on lan beside the dnsmasq one, as a box upgraded
// to dnsmasq keeps it; the wizard only unsets <enable>.
func mixedISC(enable, leaseIP string) string {
	return `<dhcpd><lan>` + enable + `<range><from>192.168.1.10</from><to>192.168.1.50</to></range>` +
		`<staticmap><mac>aa:bb:cc:00:00:01</mac><ipaddr>` + leaseIP + `</ipaddr><hostname>old</hostname></staticmap>` +
		`</lan></dhcpd>`
}

// mixedDnsmasq is the dnsmasq side of the mixed configs.
func mixedDnsmasq(enable string) string {
	return `<dnsmasq version="1.0.9"><enable>` + enable + `</enable>` +
		`<dhcp_ranges><interface>lan</interface><start_addr>192.168.1.100</start_addr>` +
		`<end_addr>192.168.1.199</end_addr></dhcp_ranges></dnsmasq>`
}

// TestConverter_Dnsmasq_DiffBesideISC diffs configs holding an ISC and a
// dnsmasq scope on one interface. The diff keyed scopes by interface alone,
// so the dnsmasq scope hid the ISC one.
func TestConverter_Dnsmasq_DiffBesideISC(t *testing.T) {
	t.Parallel()

	oldDevice, _ := parseDnsmasqConfig(t, mixedDnsmasq("1"), mixedISC("", "192.168.1.20"))

	stats := analysis.ComputeStatistics(oldDevice)
	found := false
	for _, iface := range stats.InterfaceDetails {
		if iface.Name == "lan" {
			found = true
			assert.True(t, iface.HasDHCP, "the enabled dnsmasq scope describes lan")
		}
	}
	assert.True(t, found)

	leaseMoved, _ := parseDnsmasqConfig(t, mixedDnsmasq("1"), mixedISC("", "192.168.1.21"))
	changes := diff.NewAnalyzer().CompareDHCP(oldDevice.DHCP, leaseMoved.DHCP)
	require.Len(t, changes, 1)
	assert.Equal(t, "dhcpd.lan.staticmap[aa:bb:cc:00:00:01].ipaddr", changes[0].Path)

	swapped, _ := parseDnsmasqConfig(t, mixedDnsmasq("0"), mixedISC("<enable>1</enable>", "192.168.1.20"))
	changes = diff.NewAnalyzer().CompareDHCP(oldDevice.DHCP, swapped.DHCP)
	got := make([]string, 0, len(changes))
	for _, c := range changes {
		got = append(got, c.Path+" "+c.OldValue+" -> "+c.NewValue)
	}
	assert.ElementsMatch(t, []string{
		"dhcpd.lan.enabled false -> true",
		"dhcpd.dnsmasq.lan.enabled true -> false",
	}, got)
}

// TestConverter_Dnsmasq_DiffClientIDReservation reports a change to a
// reservation that has a client id and no MAC address.
func TestConverter_Dnsmasq_DiffClientIDReservation(t *testing.T) {
	t.Parallel()

	config := func(ip string) string {
		return `<dnsmasq version="1.0.9"><enable>1</enable>` +
			`<hosts><host>a</host><ip>` + ip + `</ip><client_id>01:02:03</client_id></hosts>` +
			`<hosts><host>b</host><ip>192.168.1.51</ip><client_id>01:02:04</client_id></hosts>` +
			`<dhcp_ranges><interface>lan</interface><start_addr>192.168.1.100</start_addr>` +
			`<end_addr>192.168.1.199</end_addr></dhcp_ranges></dnsmasq>`
	}
	oldDevice, _ := parseDnsmasqConfig(t, config("192.168.1.50"), "")
	newDevice, _ := parseDnsmasqConfig(t, config("192.168.1.60"), "")

	changes := diff.NewAnalyzer().CompareDHCP(oldDevice.DHCP, newDevice.DHCP)
	require.Len(t, changes, 1)
	assert.Equal(t, "dhcpd.dnsmasq.lan.staticmap[id:01:02:03].ipaddr", changes[0].Path)
	assert.Equal(t, "192.168.1.50", changes[0].OldValue)
	assert.Equal(t, "192.168.1.60", changes[0].NewValue)
}

// TestConverter_Dnsmasq_ISCScopesStillCount keeps counting every ISC scope
// toward V-206690, including one the factory default wrote as <enable/> up to
// 25.1, while a disabled dnsmasq scope beside it does not count.
func TestConverter_Dnsmasq_ISCScopesStillCount(t *testing.T) {
	t.Parallel()

	isc := `<dhcpd>
    <lan><enable/><range><from>192.168.1.100</from><to>192.168.1.199</to></range></lan>
    <opt1><enable>1</enable><range><from>10.0.1.100</from><to>10.0.1.199</to></range></opt1>
    <opt2><enable>1</enable><range><from>10.0.2.100</from><to>10.0.2.199</to></range></opt2>
  </dhcpd>`
	device, _ := parseDnsmasqConfig(t, `<dnsmasq><enable>0</enable></dnsmasq>`, isc)
	require.Len(t, device.DHCP, 3)
	findings, _, err := stig.NewPlugin().RunChecks(device)
	require.NoError(t, err)
	assert.True(t, hasReference(findings, "V-206690"), "three ISC scopes exceed the limit")

	// Two ISC scopes and a disabled dnsmasq scope stay under it.
	twoISC := `<dhcpd>
    <lan><enable/><range><from>192.168.1.100</from><to>192.168.1.199</to></range></lan>
    <opt1><enable>1</enable><range><from>10.0.1.100</from><to>10.0.1.199</to></range></opt1>
  </dhcpd>`
	device, _ = parseDnsmasqConfig(t, `<dnsmasq version="1.0.9"><enable>0</enable>`+
		`<dhcp_ranges><interface>opt2</interface><start_addr>10.0.2.100</start_addr>`+
		`<end_addr>10.0.2.199</end_addr></dhcp_ranges></dnsmasq>`, twoISC)
	require.Len(t, device.DHCP, 3)
	findings, _, err = stig.NewPlugin().RunChecks(device)
	require.NoError(t, err)
	assert.False(t, hasReference(findings, "V-206690"))
}

// TestConverter_Dnsmasq_StaticIPv6RangeWithoutEnd keeps an IPv6 static range,
// which has no end address, as a scope that serves reservations only.
func TestConverter_Dnsmasq_StaticIPv6RangeWithoutEnd(t *testing.T) {
	t.Parallel()

	device, warnings := parseDnsmasqConfig(t, `<dnsmasq version="1.0.9"><enable>1</enable>
    <dhcp_ranges><interface>opt1</interface><start_addr>::</start_addr><constructor>opt1</constructor><mode>static</mode></dhcp_ranges>
  </dnsmasq>`, "")

	assert.Empty(t, dnsmasqWarnings(warnings))
	require.Len(t, device.DHCP, 1)
	assert.Equal(t, "opt1", device.DHCP[0].Interface)
	assert.True(t, device.DHCP[0].Enabled)
	assert.Nil(t, device.DHCP[0].RangeV6)
}

// TestConverter_Dnsmasq_AnyScopeRejectsForeignAddress keeps a reservation
// outside every network of the firewall out of a range that names no
// interface.
func TestConverter_Dnsmasq_AnyScopeRejectsForeignAddress(t *testing.T) {
	t.Parallel()

	device, warnings := parseDnsmasqConfig(t, `<dnsmasq version="1.0.9"><enable>1</enable>`+
		`<dhcp_ranges><start_addr>10.0.2.100</start_addr><end_addr>10.0.2.199</end_addr></dhcp_ranges>`+
		`<hosts><host>far</host><ip>172.31.9.9</ip><hwaddr>aa:bb:cc:dd:ee:30</hwaddr></hosts></dnsmasq>`, "")

	require.Len(t, device.DHCP, 1)
	assert.Empty(t, device.DHCP[0].StaticLeases)
	got := dnsmasqWarnings(warnings)
	require.Len(t, got, 1)
	assert.Equal(t, "far", got[0].Value)
}

// TestConverter_Dnsmasq_DiffLeaseWithMACAndClientID keys a reservation that
// has both a MAC address and a client id by its MAC.
func TestConverter_Dnsmasq_DiffLeaseWithMACAndClientID(t *testing.T) {
	t.Parallel()

	config := func(ip string) string {
		return `<dnsmasq version="1.0.9"><enable>1</enable>` +
			`<hosts><host>a</host><ip>` + ip + `</ip><hwaddr>aa:bb:cc:dd:ee:40</hwaddr><client_id>01:02:05</client_id></hosts>` +
			`<dhcp_ranges><interface>lan</interface><start_addr>192.168.1.100</start_addr>` +
			`<end_addr>192.168.1.199</end_addr></dhcp_ranges></dnsmasq>`
	}
	oldDevice, _ := parseDnsmasqConfig(t, config("192.168.1.50"), "")
	newDevice, _ := parseDnsmasqConfig(t, config("192.168.1.60"), "")

	changes := diff.NewAnalyzer().CompareDHCP(oldDevice.DHCP, newDevice.DHCP)
	require.Len(t, changes, 1)
	assert.Equal(t, "dhcpd.dnsmasq.lan.staticmap[aa:bb:cc:dd:ee:40].ipaddr", changes[0].Path)
}
