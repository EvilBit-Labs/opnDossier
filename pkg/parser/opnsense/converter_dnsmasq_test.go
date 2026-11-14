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
// so that a reservation can be placed by its address, and three interfaces
// without a static network the config shows: opt3 with no address (a
// virtual IP can carry one), opt4 tracking a delegated IPv6 prefix, opt5
// with an IPv6 /48 and opt6 with an IPv6 /80.
const dnsmasqInterfaces = `<interfaces>
    <wan><enable>1</enable><if>vtnet0</if><ipaddr>dhcp</ipaddr></wan>
    <lan><enable>1</enable><if>vtnet1</if><ipaddr>192.168.1.1</ipaddr><subnet>24</subnet></lan>
    <opt1><enable>1</enable><if>vtnet2</if><ipaddr>10.0.1.1</ipaddr><subnet>24</subnet></opt1>
    <opt2><enable>1</enable><if>vtnet3</if><ipaddr>10.0.2.1</ipaddr><subnet>24</subnet><ipaddrv6>fd00:2::1</ipaddrv6><subnetv6>64</subnetv6></opt2>
    <opt3><enable>1</enable><if>vtnet4</if></opt3>
    <opt4><enable>1</enable><if>vtnet5</if><ipaddrv6>track6</ipaddrv6></opt4>
    <opt5><enable>1</enable><if>vtnet6</if><ipaddrv6>fd00:5::1</ipaddrv6><subnetv6>48</subnetv6></opt5>
    <opt6><enable>1</enable><if>vtnet7</if><ipaddrv6>fd00:6::1</ipaddrv6><subnetv6>80</subnetv6></opt6>
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

// TestConverter_Dnsmasq_RangeWithoutInterface gives a range that names no
// interface the scope of the interface whose network holds it, and folds a
// second range of one family into a warning.
func TestConverter_Dnsmasq_RangeWithoutInterface(t *testing.T) {
	t.Parallel()

	device, warnings := parseDnsmasqConfig(t, `<dnsmasq version="1.0.9"><enable>1</enable>
    <dhcp_ranges><start_addr>192.168.1.100</start_addr><end_addr>192.168.1.149</end_addr></dhcp_ranges>
    <dhcp_ranges><start_addr>192.168.1.150</start_addr><end_addr>192.168.1.199</end_addr></dhcp_ranges>
    <dhcp_ranges><interface>lan</interface><start_addr></start_addr></dhcp_ranges>
  </dnsmasq>`, "")

	require.Len(t, device.DHCP, 1)
	assert.Equal(t, "lan", device.DHCP[0].Interface)
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
		enable   string
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
			name:     "dnsmasq disabled",
			enable:   "0",
			settings: `<dnssec>1</dnssec>`,
			wantPass: false,
		},
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

			enable := tt.enable
			if enable == "" {
				enable = "1"
			}
			device, _ := parseDnsmasqConfig(t,
				`<dnsmasq version="1.0.9"><enable>`+enable+`</enable>`+tt.settings+`</dnsmasq>`, tt.extra)
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

// TestConverter_Dnsmasq_AnyRangesResolveToTheirInterface gives each range
// that names no interface the scope of the interface whose network holds it,
// so the scopes reach the checks per interface. Ranges no interface holds keep
// a scope each.
func TestConverter_Dnsmasq_AnyRangesResolveToTheirInterface(t *testing.T) {
	t.Parallel()

	device, warnings := parseDnsmasqConfig(t, `<dnsmasq version="1.0.9"><enable>1</enable>
    <dhcp_ranges><start_addr>192.168.1.100</start_addr><end_addr>192.168.1.199</end_addr></dhcp_ranges>
    <dhcp_ranges><start_addr>10.0.1.100</start_addr><end_addr>10.0.1.199</end_addr></dhcp_ranges>
    <dhcp_ranges><start_addr>10.0.2.100</start_addr><end_addr>10.0.2.199</end_addr></dhcp_ranges>
  </dnsmasq>`, "")

	assert.Empty(t, dnsmasqWarnings(warnings))
	require.Len(t, device.DHCP, 3)
	for i, want := range []string{"lan", "opt1", "opt2"} {
		assert.Equal(t, want, device.DHCP[i].Interface)
		assert.True(t, device.DHCP[i].Enabled, want)
	}
	assert.Equal(t, common.DHCPRange{From: "10.0.2.100", To: "10.0.2.199"}, device.DHCP[2].Range)
	for _, unused := range analysis.DetectUnusedInterfaces(device) {
		assert.NotContains(t, []string{"opt1", "opt2"}, unused.InterfaceName)
	}
	stigFindings, _, err := stig.NewPlugin().RunChecks(device)
	require.NoError(t, err)
	assert.True(t, hasReference(stigFindings, "V-206690"), "three interfaces get DHCP")

	device, warnings = parseDnsmasqConfig(t, `<dnsmasq version="1.0.9"><enable>1</enable>
    <dhcp_ranges><start_addr>172.16.0.100</start_addr><end_addr>172.16.0.199</end_addr></dhcp_ranges>
    <dhcp_ranges><start_addr>172.17.0.100</start_addr><end_addr>172.17.0.199</end_addr></dhcp_ranges>
  </dnsmasq>`, "")

	assert.Empty(t, dnsmasqWarnings(warnings), "distinct ranges are not folded together")
	require.Len(t, device.DHCP, 2)
	assert.Empty(t, device.DHCP[0].Interface)
	assert.Equal(t, "172.16.0.100", device.DHCP[0].Range.From)
	assert.Empty(t, device.DHCP[1].Interface)
	assert.Equal(t, "172.17.0.100", device.DHCP[1].Range.From)
}

// TestConverter_Dnsmasq_RAModeWithEndAddress classifies an IPv6 range with an
// end address by what dnsmasq does with it: ra-stateless allocates no address
// and ra-only, which only adds router advertisements, still serves the range.
func TestConverter_Dnsmasq_RAModeWithEndAddress(t *testing.T) {
	t.Parallel()

	device, warnings := parseDnsmasqConfig(t, `<dnsmasq version="1.0.9"><enable>1</enable>
    <dhcp_ranges><interface>opt1</interface><start_addr>::1000</start_addr><end_addr>::2000</end_addr><constructor>opt1</constructor><ra_mode>ra-only</ra_mode></dhcp_ranges>
    <dhcp_ranges><interface>opt2</interface><start_addr>::1000</start_addr><end_addr>::2000</end_addr><constructor>opt2</constructor><ra_mode>ra-stateless</ra_mode></dhcp_ranges>
  </dnsmasq>`, "")

	assert.Empty(t, dnsmasqWarnings(warnings))
	require.Len(t, device.DHCP, 2)
	assert.Equal(t, "opt1", device.DHCP[0].Interface)
	assert.Equal(t, &common.DHCPRange{From: "::1000", To: "::2000"}, device.DHCP[0].RangeV6)
	assert.Equal(t, "opt2", device.DHCP[1].Interface)
	assert.True(t, device.DHCP[1].Enabled)
	assert.Nil(t, device.DHCP[1].RangeV6, "a stateless DHCPv6 service hands out no addresses")
}

// TestConverter_Dnsmasq_IPv6Reservations places a reservation with only IPv6
// addresses by those addresses, not on the only IPv4 scope.
func TestConverter_Dnsmasq_IPv6Reservations(t *testing.T) {
	t.Parallel()

	ranges := `<dhcp_ranges><interface>lan</interface><start_addr>192.168.1.100</start_addr>` +
		`<end_addr>192.168.1.199</end_addr></dhcp_ranges>` +
		`<dhcp_ranges><interface>opt1</interface><start_addr>fd00:1::100</start_addr>` +
		`<end_addr>fd00:1::1ff</end_addr></dhcp_ranges>` +
		`<dhcp_ranges><interface>opt2</interface><start_addr>::1000</start_addr>` +
		`<end_addr>::2000</end_addr><constructor>opt2</constructor></dhcp_ranges>`

	device, warnings := parseDnsmasqConfig(t, `<dnsmasq version="1.0.9"><enable>1</enable>`+ranges+
		`<hosts><host>v6a</host><ip>fd00:1::50</ip><hwaddr>aa:bb:cc:dd:ee:50</hwaddr></hosts>`+
		`<hosts><host>v6b</host><ip>fd00:2::50</ip><hwaddr>aa:bb:cc:dd:ee:51</hwaddr></hosts>`+
		`<hosts><host>v6c</host><ip>::60</ip><hwaddr>aa:bb:cc:dd:ee:52</hwaddr></hosts>`+
		`<hosts><host>v6d</host><ip>fd00:9::50</ip><hwaddr>aa:bb:cc:dd:ee:53</hwaddr></hosts>`+
		`</dnsmasq>`, "")

	require.Len(t, device.DHCP, 3)
	assert.Empty(t, device.DHCP[0].StaticLeases, "the IPv4 scope takes no IPv6-only reservation")
	assert.Equal(t, []common.DHCPStaticLease{{MAC: "aa:bb:cc:dd:ee:50", IPAddress: "fd00:1::50", Hostname: "v6a"}},
		device.DHCP[1].StaticLeases)
	assert.Equal(t, []common.DHCPStaticLease{
		{MAC: "aa:bb:cc:dd:ee:51", IPAddress: "fd00:2::50", Hostname: "v6b"},
		{MAC: "aa:bb:cc:dd:ee:52", IPAddress: "::60", Hostname: "v6c"},
	}, device.DHCP[2].StaticLeases)

	got := dnsmasqWarnings(warnings)
	require.Len(t, got, 1)
	assert.Equal(t, "v6d", got[0].Value)
}

// TestConverter_Dnsmasq_DiffClientIDChange reports a new client id on a
// reservation keyed by its MAC address.
func TestConverter_Dnsmasq_DiffClientIDChange(t *testing.T) {
	t.Parallel()

	config := func(cid string) string {
		return `<dnsmasq version="1.0.9"><enable>1</enable>` +
			`<hosts><host>a</host><ip>192.168.1.50</ip><hwaddr>aa:bb:cc:dd:ee:40</hwaddr><client_id>` + cid +
			`</client_id></hosts>` +
			`<dhcp_ranges><interface>lan</interface><start_addr>192.168.1.100</start_addr>` +
			`<end_addr>192.168.1.199</end_addr></dhcp_ranges></dnsmasq>`
	}
	oldDevice, _ := parseDnsmasqConfig(t, config("01:02:03"), "")
	newDevice, _ := parseDnsmasqConfig(t, config("01:02:04"), "")

	changes := diff.NewAnalyzer().CompareDHCP(oldDevice.DHCP, newDevice.DHCP)
	require.Len(t, changes, 1)
	assert.Equal(t, "dhcpd.dnsmasq.lan.staticmap[aa:bb:cc:dd:ee:40].cid", changes[0].Path)
	assert.Equal(t, "01:02:03", changes[0].OldValue)
	assert.Equal(t, "01:02:04", changes[0].NewValue)
}

// TestConverter_Dnsmasq_RelayedRangeReservations places a reservation on a
// range no interface's network holds by the network dnsmasq assumes for it:
// the range's subnet mask, or the class of its start address without one.
func TestConverter_Dnsmasq_RelayedRangeReservations(t *testing.T) {
	t.Parallel()

	device, warnings := parseDnsmasqConfig(t, `<dnsmasq version="1.0.9"><enable>1</enable>
    <dhcp_ranges><start_addr>172.16.0.100</start_addr><end_addr>172.16.0.199</end_addr><subnet_mask>255.255.255.0</subnet_mask></dhcp_ranges>
    <dhcp_ranges><start_addr>172.20.0.100</start_addr><end_addr>172.20.0.199</end_addr></dhcp_ranges>
    <hosts><host>masked</host><ip>172.16.0.50</ip><hwaddr>aa:bb:cc:dd:ee:60</hwaddr></hosts>
    <hosts><host>outside</host><ip>172.16.1.50</ip><hwaddr>aa:bb:cc:dd:ee:61</hwaddr></hosts>
    <hosts><host>classful</host><ip>172.20.9.9</ip><hwaddr>aa:bb:cc:dd:ee:62</hwaddr></hosts>
  </dnsmasq>`, "")

	require.Len(t, device.DHCP, 2)
	require.Len(t, device.DHCP[0].StaticLeases, 1)
	assert.Equal(t, "masked", device.DHCP[0].StaticLeases[0].Hostname)
	require.Len(t, device.DHCP[1].StaticLeases, 1)
	assert.Equal(t, "classful", device.DHCP[1].StaticLeases[0].Hostname, "172.20.0.0/16 is class B")

	got := dnsmasqWarnings(warnings)
	require.Len(t, got, 1)
	assert.Equal(t, "outside", got[0].Value)
}

// TestConverter_Dnsmasq_ReservationWithSeveralAddresses attaches a
// reservation to every scope one of its addresses reaches, once each.
func TestConverter_Dnsmasq_ReservationWithSeveralAddresses(t *testing.T) {
	t.Parallel()

	ranges := `<dhcp_ranges><interface>opt1</interface><start_addr>fd00:1::100</start_addr>` +
		`<end_addr>fd00:1::1ff</end_addr></dhcp_ranges>` +
		`<dhcp_ranges><interface>opt2</interface><start_addr>::1000</start_addr>` +
		`<end_addr>::2000</end_addr><constructor>opt2</constructor></dhcp_ranges>`

	device, warnings := parseDnsmasqConfig(t, `<dnsmasq version="1.0.9"><enable>1</enable>`+ranges+
		`<hosts><host>both</host><ip>fd00:1::50,fd00:2::50</ip><hwaddr>aa:bb:cc:dd:ee:70</hwaddr></hosts>`+
		`<hosts><host>mixed</host><ip>fd00:1::51,::61</ip><hwaddr>aa:bb:cc:dd:ee:71</hwaddr></hosts>`+
		`<hosts><host>twice</host><ip>fd00:2::52,::62</ip><hwaddr>aa:bb:cc:dd:ee:72</hwaddr></hosts>`+
		`</dnsmasq>`, "")

	assert.Empty(t, dnsmasqWarnings(warnings))
	require.Len(t, device.DHCP, 2)
	names := func(leases []common.DHCPStaticLease) []string {
		var out []string
		for _, l := range leases {
			out = append(out, l.Hostname)
		}
		return out
	}
	assert.Equal(t, []string{"both", "mixed"}, names(device.DHCP[0].StaticLeases))
	assert.Equal(t, []string{"both", "mixed", "twice"}, names(device.DHCP[1].StaticLeases))
}

// keaSubnets wraps Kea subnets and reservations in the elements a config
// holds them in.
func keaSubnets(subnets, reservations string) string {
	return `<OPNsense><Kea><dhcp4 version="1.0.4"><general><enabled>1</enabled>` +
		`<interfaces>lan,opt1</interfaces></general><subnets>` + subnets + `</subnets>` +
		`<reservations>` + reservations + `</reservations></dhcp4></Kea></OPNsense>`
}

// keaReservation is one Kea reservation in the given subnet.
func keaReservation(subnet, ip, mac string) string {
	return `<reservation><subnet>` + subnet + `</subnet><ip_address>` + ip + `</ip_address>` +
		`<hw_address>` + mac + `</hw_address></reservation>`
}

// diffPaths runs the DHCP diff and returns the change paths.
func diffPaths(oldDevice, newDevice *common.CommonDevice) []string {
	changes := diff.NewAnalyzer().CompareDHCP(oldDevice.DHCP, newDevice.DHCP)
	paths := make([]string, 0, len(changes))
	for _, c := range changes {
		paths = append(paths, c.Path)
	}

	return paths
}

// TestConverter_Kea_DiffKeysBySubnet pairs Kea subnets by their <subnet>,
// which Kea requires and keeps unique. Keyed by the pool start, a pool edit
// read as a removed and an added subnet and the reservation change was lost
// (k1, k3), and pool-less subnets were numbered by position, so deleting the
// first moved reservations between the others (k2).
func TestConverter_Kea_DiffKeysBySubnet(t *testing.T) {
	t.Parallel()

	const (
		uuid1 = "10000000-0000-4000-8000-000000000001"
		uuid2 = "10000000-0000-4000-8000-000000000002"
		uuid3 = "10000000-0000-4000-8000-000000000003"
	)
	subnet := func(uuid, cidr, pools string) string {
		return `<subnet4 uuid="` + uuid + `"><subnet>` + cidr + `</subnet><pools>` + pools + `</pools></subnet4>`
	}
	parse := func(subnets, reservations string) *common.CommonDevice {
		device, _ := parseDnsmasqConfig(t, "", keaSubnets(subnets, reservations))
		return device
	}

	// k1: pool and reservation edited.
	oldK1 := parse(subnet(uuid1, "10.0.1.0/24", "10.0.1.100-10.0.1.199"),
		keaReservation(uuid1, "10.0.1.10", "aa:bb:cc:00:00:01"))
	newK1 := parse(subnet(uuid1, "10.0.1.0/24", "10.0.1.50-10.0.1.199"),
		keaReservation(uuid1, "10.0.1.11", "aa:bb:cc:00:00:01"))
	require.Len(t, oldK1.DHCP, 1)
	assert.Equal(t, "10.0.1.0/24", oldK1.DHCP[0].Subnet)
	assert.Equal(t, []string{
		"dhcpd.kea[10.0.1.0/24].staticmap[aa:bb:cc:00:00:01].ipaddr",
		"dhcpd.kea[10.0.1.0/24].range",
	}, diffPaths(oldK1, newK1))

	// k2: three subnets without pools; the first is deleted.
	none := func(uuid, cidr string) string {
		return `<subnet4 uuid="` + uuid + `"><subnet>` + cidr + `</subnet></subnet4>`
	}
	leases := keaReservation(uuid2, "10.0.2.10", "aa:bb:cc:00:00:02") +
		keaReservation(uuid3, "10.0.3.10", "aa:bb:cc:00:00:03")
	oldK2 := parse(none(uuid1, "10.0.1.0/24")+none(uuid2, "10.0.2.0/24")+none(uuid3, "10.0.3.0/24"),
		keaReservation(uuid1, "10.0.1.10", "aa:bb:cc:00:00:01")+leases)
	newK2 := parse(none(uuid2, "10.0.2.0/24")+none(uuid3, "10.0.3.0/24"), leases)
	assert.Equal(t, []string{"dhcpd.kea[10.0.1.0/24]"}, diffPaths(oldK2, newK2))

	// k3: the pools of one subnet swap order and a reservation moves.
	second := subnet(uuid2, "10.0.2.0/24", "10.0.2.100-10.0.2.199")
	oldK3 := parse(subnet(uuid1, "10.0.1.0/24", "10.0.1.100-10.0.1.149\n10.0.1.150-10.0.1.199")+second,
		keaReservation(uuid1, "10.0.1.10", "aa:bb:cc:00:00:01"))
	newK3 := parse(subnet(uuid1, "10.0.1.0/24", "10.0.1.150-10.0.1.199\n10.0.1.100-10.0.1.149")+second,
		keaReservation(uuid1, "10.0.1.99", "aa:bb:cc:00:00:01"))
	assert.Equal(t, []string{
		"dhcpd.kea[10.0.1.0/24].staticmap[aa:bb:cc:00:00:01].ipaddr",
		"dhcpd.kea[10.0.1.0/24].range",
	}, diffPaths(oldK3, newK3))
}

// TestConverter_Dnsmasq_RelayedScopesDiffBySubnet names a dnsmasq range no
// interface's network holds by the network dnsmasq assumes for it, so a
// change to a reservation on the second of two such static ranges is
// reported (d1).
func TestConverter_Dnsmasq_RelayedScopesDiffBySubnet(t *testing.T) {
	t.Parallel()

	config := func(ip string) string {
		return `<dnsmasq version="1.0.9"><enable>1</enable>` +
			`<dhcp_ranges><start_addr>172.16.0.1</start_addr><mode>static</mode></dhcp_ranges>` +
			`<dhcp_ranges><start_addr>172.20.0.1</start_addr><mode>static</mode></dhcp_ranges>` +
			`<hosts><host>h1</host><ip>172.16.0.50</ip><hwaddr>aa:bb:cc:dd:ee:01</hwaddr></hosts>` +
			`<hosts><host>h2</host><ip>` + ip + `</ip><hwaddr>aa:bb:cc:dd:ee:02</hwaddr></hosts></dnsmasq>`
	}
	oldDevice, warnings := parseDnsmasqConfig(t, config("172.20.0.50"), "")
	assert.Empty(t, dnsmasqWarnings(warnings))
	newDevice, _ := parseDnsmasqConfig(t, config("172.20.0.51"), "")

	require.Len(t, oldDevice.DHCP, 2)
	assert.Equal(t, "172.16.0.0/16", oldDevice.DHCP[0].Subnet)
	assert.Equal(t, "172.20.0.0/16", oldDevice.DHCP[1].Subnet)
	assert.Equal(t, []string{"dhcpd.dnsmasq[172.20.0.0/16].staticmap[aa:bb:cc:dd:ee:02].ipaddr"},
		diffPaths(oldDevice, newDevice))
}

// rangeNetworks4Case is one case of TestConverter_Dnsmasq_RangeNetworks4.
type rangeNetworks4Case struct {
	name       string
	ranges     string
	host       string
	wantScope  int // index of the scope the lease reaches, -1 for none
	wantSubnet []string
}

// rangeNetworks4Cases lists the cases of TestConverter_Dnsmasq_RangeNetworks4.
func rangeNetworks4Cases() []rangeNetworks4Case {
	const (
		o1Ranges = `<dhcp_ranges><interface>opt1</interface><start_addr>10.0.1.100</start_addr>` +
			`<end_addr>10.0.1.199</end_addr></dhcp_ranges>` +
			`<dhcp_ranges><start_addr>10.50.0.100</start_addr><end_addr>10.50.0.199</end_addr></dhcp_ranges>`
		relayed22 = `<dhcp_ranges><start_addr>172.16.0.100</start_addr><end_addr>172.16.0.199</end_addr>` +
			`<subnet_mask>255.255.252.0</subnet_mask></dhcp_ranges>`
	)

	return []rangeNetworks4Case{
		{
			name: "named interface, range off its network, with a mask (r1)",
			ranges: `<dhcp_ranges><interface>opt1</interface><start_addr>172.16.0.100</start_addr>` +
				`<end_addr>172.16.0.199</end_addr><subnet_mask>255.255.255.0</subnet_mask></dhcp_ranges>`,
			host: "172.16.0.50", wantScope: 0, wantSubnet: []string{""},
		},
		{
			name: "local range with a mask wider than the interface",
			ranges: `<dhcp_ranges><interface>lan</interface><start_addr>192.168.1.100</start_addr>` +
				`<end_addr>192.168.1.199</end_addr><subnet_mask>255.255.252.0</subnet_mask></dhcp_ranges>`,
			host: "192.168.2.50", wantScope: 0, wantSubnet: []string{""},
		},
		{
			name:   "relayed range, /22 mask, inside",
			ranges: relayed22,
			host:   "172.16.3.50", wantScope: 0, wantSubnet: []string{"172.16.0.0/22"},
		},
		{
			name:   "relayed range, /22 mask, outside",
			ranges: relayed22,
			host:   "172.16.4.50", wantScope: -1, wantSubnet: []string{"172.16.0.0/22"},
		},
		{
			name:   "class A guess is /8",
			ranges: `<dhcp_ranges><start_addr>11.0.0.100</start_addr><end_addr>11.0.0.199</end_addr></dhcp_ranges>`,
			host:   "11.200.0.1", wantScope: 0, wantSubnet: []string{"11.0.0.0/8"},
		},
		{
			name: "class C guess is /24",
			ranges: `<dhcp_ranges><start_addr>203.0.113.100</start_addr>` +
				`<end_addr>203.0.113.199</end_addr></dhcp_ranges>`,
			host: "203.0.114.50", wantScope: -1, wantSubnet: []string{"203.0.113.0/24"},
		},
		{
			name: "no guess when start and end are in different classes",
			ranges: `<dhcp_ranges><start_addr>126.255.255.250</start_addr>` +
				`<end_addr>128.0.0.5</end_addr></dhcp_ranges>`,
			host: "126.255.255.251", wantScope: -1, wantSubnet: []string{""},
		},
		{
			name: "an address must share the guessed network with the start and the end",
			ranges: `<dhcp_ranges><start_addr>11.0.0.100</start_addr>` +
				`<end_addr>12.0.0.100</end_addr></dhcp_ranges>`,
			host: "11.5.5.5", wantScope: -1, wantSubnet: []string{"11.0.0.0/8"},
		},
		{
			name: "a mask that is not contiguous is applied bit by bit, inside",
			ranges: `<dhcp_ranges><start_addr>172.16.1.100</start_addr><end_addr>172.16.5.100</end_addr>` +
				`<subnet_mask>255.255.0.255</subnet_mask></dhcp_ranges>`,
			host: "172.16.9.100", wantScope: 0, wantSubnet: []string{"172.16.0.100/255.255.0.255"},
		},
		{
			name: "a mask that is not contiguous is applied bit by bit, outside",
			ranges: `<dhcp_ranges><start_addr>172.16.1.100</start_addr><end_addr>172.16.5.100</end_addr>` +
				`<subnet_mask>255.255.0.255</subnet_mask></dhcp_ranges>`,
			host: "172.16.9.101", wantScope: -1, wantSubnet: []string{"172.16.0.100/255.255.0.255"},
		},
		{
			name: "a mask narrower than the interface narrows what the range serves (n1)",
			ranges: `<dhcp_ranges><interface>lan</interface><start_addr>192.168.1.10</start_addr>` +
				`<end_addr>192.168.1.100</end_addr><subnet_mask>255.255.255.128</subnet_mask></dhcp_ranges>`,
			host: "192.168.1.200", wantScope: -1, wantSubnet: []string{""},
		},
		{
			name: "inside a narrower mask the range serves the reservation (n1)",
			ranges: `<dhcp_ranges><interface>lan</interface><start_addr>192.168.1.10</start_addr>` +
				`<end_addr>192.168.1.100</end_addr><subnet_mask>255.255.255.128</subnet_mask></dhcp_ranges>`,
			host: "192.168.1.120", wantScope: 0, wantSubnet: []string{""},
		},
		{
			name:   "an interface network wins over an overlapping relayed range (o1)",
			ranges: o1Ranges,
			host:   "10.0.1.60", wantScope: 0, wantSubnet: []string{"", "10.0.0.0/8"},
		},
		{
			name: "a local range wins over a relayed range listed before it",
			ranges: `<dhcp_ranges><start_addr>10.50.0.100</start_addr><end_addr>10.50.0.199</end_addr></dhcp_ranges>` +
				`<dhcp_ranges><interface>opt1</interface><start_addr>10.0.1.100</start_addr>` +
				`<end_addr>10.0.1.199</end_addr></dhcp_ranges>`,
			host: "10.0.1.60", wantScope: 1, wantSubnet: []string{"10.0.0.0/8", ""},
		},
		{
			name:   "the relayed range takes what no interface holds (o1)",
			ranges: o1Ranges,
			host:   "10.77.0.9", wantScope: 1, wantSubnet: []string{"", "10.0.0.0/8"},
		},
	}
}

// rangeNetworksDynamicCases lists the cases of
// TestConverter_Dnsmasq_RangeNetworks4 with a range on an interface that
// has no static IPv4 network.
func rangeNetworksDynamicCases() []rangeNetworks4Case {
	return []rangeNetworks4Case{
		{
			name: "a masked range on a DHCP interface is local (dynmask)",
			ranges: `<dhcp_ranges><start_addr>10.50.0.100</start_addr><end_addr>10.50.0.199</end_addr></dhcp_ranges>` +
				`<dhcp_ranges><interface>wan</interface><start_addr>10.0.9.100</start_addr>` +
				`<end_addr>10.0.9.199</end_addr><subnet_mask>255.255.255.0</subnet_mask></dhcp_ranges>`,
			host: "10.0.9.150", wantScope: 1, wantSubnet: []string{"10.0.0.0/8", ""},
		},
		{
			name: "a range on a known network wins over one on an interface with no static address (dyn_wide)",
			ranges: `<dhcp_ranges><interface>opt3</interface><start_addr>10.0.255.200</start_addr>` +
				`<end_addr>10.1.0.50</end_addr></dhcp_ranges>` +
				`<dhcp_ranges><interface>opt1</interface><start_addr>10.0.1.100</start_addr>` +
				`<end_addr>10.0.1.199</end_addr></dhcp_ranges>`,
			host: "10.0.1.60", wantScope: 1, wantSubnet: []string{"", ""},
		},
		{
			name: "a range on a DHCP interface holds only the smallest prefix around its pool",
			ranges: `<dhcp_ranges><interface>wan</interface><start_addr>10.0.9.100</start_addr>` +
				`<end_addr>10.0.9.120</end_addr></dhcp_ranges>`,
			host: "10.0.9.95", wantScope: -1, wantSubnet: []string{""},
		},
		{
			name: "a relayed range takes an address outside a DHCP interface's range (dyn)",
			ranges: `<dhcp_ranges><interface>wan</interface><start_addr>10.0.9.100</start_addr>` +
				`<end_addr>10.0.9.199</end_addr></dhcp_ranges>` +
				`<dhcp_ranges><start_addr>10.77.0.100</start_addr><end_addr>10.77.0.199</end_addr>` +
				`<subnet_mask>255.255.0.0</subnet_mask></dhcp_ranges>`,
			host: "10.77.0.9", wantScope: 1, wantSubnet: []string{"", "10.77.0.0/16"},
		},
		{
			name: "a range on an interface with only a virtual IP keeps its reservations (dyn_vip)",
			ranges: `<dhcp_ranges><interface>opt3</interface><start_addr>10.5.0.100</start_addr>` +
				`<end_addr>10.5.0.199</end_addr></dhcp_ranges>`,
			host: "10.5.0.150", wantScope: 0, wantSubnet: []string{""},
		},
		{
			name: "a range on a DHCP interface keeps the reservations in its pool (dyn_wan)",
			ranges: `<dhcp_ranges><interface>wan</interface><start_addr>10.0.9.100</start_addr>` +
				`<end_addr>10.0.9.199</end_addr></dhcp_ranges>`,
			host: "10.0.9.150", wantScope: 0, wantSubnet: []string{""},
		},
		{
			name: "a range on a DHCP interface wins over a relayed range listed before it",
			ranges: `<dhcp_ranges><start_addr>10.50.0.100</start_addr><end_addr>10.50.0.199</end_addr></dhcp_ranges>` +
				`<dhcp_ranges><interface>wan</interface><start_addr>10.0.9.100</start_addr>` +
				`<end_addr>10.0.9.199</end_addr></dhcp_ranges>`,
			host: "10.0.9.150", wantScope: 1, wantSubnet: []string{"10.0.0.0/8", ""},
		},
		{
			name: "a masked range on an interface the config does not define stays relayed",
			ranges: `<dhcp_ranges><start_addr>10.50.0.100</start_addr><end_addr>10.50.0.199</end_addr></dhcp_ranges>` +
				`<dhcp_ranges><interface>opt9</interface><start_addr>10.0.99.100</start_addr>` +
				`<end_addr>10.0.99.199</end_addr><subnet_mask>255.255.255.0</subnet_mask></dhcp_ranges>`,
			host: "10.0.99.150", wantScope: 0, wantSubnet: []string{"10.0.0.0/8", ""},
		},
	}
}

// rangeNetworks6Cases lists the IPv6 cases of
// TestConverter_Dnsmasq_RangeNetworks4.
func rangeNetworks6Cases() []rangeNetworks4Case {
	constructed := func(iface, prefixLen string) string {
		return `<dhcp_ranges><interface>` + iface + `</interface><start_addr>::1000</start_addr>` +
			`<end_addr>::2000</end_addr><constructor>` + iface + `</constructor><prefix_len>` + prefixLen +
			`</prefix_len></dhcp_ranges>`
	}

	return []rangeNetworks4Case{
		{
			name: "dnsmasq refuses any IPv6 range with a prefix_len below 64",
			ranges: `<dhcp_ranges><interface>opt2</interface><start_addr>fd00:2::1000</start_addr>` +
				`<end_addr>fd00:2::1fff</end_addr><prefix_len>48</prefix_len></dhcp_ranges>`,
			host: "fd00:2::50", wantScope: -1, wantSubnet: []string{""},
		},
		{
			name:   "a host part does not reach a range with a prefix_len below 64",
			ranges: constructed("opt2", "48"), host: "::50", wantScope: -1, wantSubnet: []string{""},
		},
		{
			name:   "a host part reaches a range constructed on a track6 interface",
			ranges: constructed("opt4", "64"), host: "::50", wantScope: 0, wantSubnet: []string{""},
		},
		{
			name:   "a host part written out in full is a host part",
			ranges: constructed("opt4", "64"), host: "0:0:0:0:0:0:0:50", wantScope: 0, wantSubnet: []string{""},
		},
		{
			name: "a range whose start is a host part written out in full names no network",
			ranges: `<dhcp_ranges><start_addr>0:0:0:0:0:0:0:1000</start_addr>` +
				`<end_addr>0:0:0:0:0:0:0:2000</end_addr></dhcp_ranges>`,
			host: "fd00:9::50", wantScope: -1, wantSubnet: []string{""},
		},
		{
			name:   "dnsmasq builds no range on an interface whose prefix is longer than 64",
			ranges: constructed("opt6", "64"), host: "::50", wantScope: -1, wantSubnet: []string{""},
		},
		{
			name:   "a range constructed on a /48 serves the /64 around the address",
			ranges: constructed("opt5", "64"), host: "fd00:5::1500", wantScope: 0, wantSubnet: []string{""},
		},
		{
			name:   "a range constructed on a /48 serves no other /64 of it",
			ranges: constructed("opt5", "64"), host: "fd00:5:0:9::1500", wantScope: -1, wantSubnet: []string{""},
		},
		{
			name:   "a constructor with a prefix_len between the interface's and 64 is refused",
			ranges: constructed("opt5", "56"), host: "fd00:5::1500", wantScope: -1, wantSubnet: []string{""},
		},
		{
			name: "an IPv6 range serves only its prefix_len network (n2)",
			ranges: `<dhcp_ranges><interface>opt2</interface><start_addr>fd00:2::1000</start_addr>` +
				`<end_addr>fd00:2::1fff</end_addr><prefix_len>112</prefix_len></dhcp_ranges>`,
			host: "fd00:2::9:50", wantScope: -1, wantSubnet: []string{""},
		},
		{
			name: "inside its prefix_len network an IPv6 range serves the reservation (n2)",
			ranges: `<dhcp_ranges><interface>opt2</interface><start_addr>fd00:2::1000</start_addr>` +
				`<end_addr>fd00:2::1fff</end_addr><prefix_len>112</prefix_len></dhcp_ranges>`,
			host: "fd00:2::50", wantScope: 0, wantSubnet: []string{""},
		},
		{
			name: "a constructed range is matched around the start dnsmasq builds",
			ranges: `<dhcp_ranges><interface>opt2</interface><start_addr>::1000</start_addr><end_addr>::2000</end_addr>` +
				`<constructor>opt2</constructor><prefix_len>64</prefix_len></dhcp_ranges>`,
			host:       "fd00:2::50",
			wantScope:  0,
			wantSubnet: []string{""},
		},
		{
			name: "dnsmasq refuses a constructed range with a prefix_len above 64",
			ranges: `<dhcp_ranges><interface>opt2</interface><start_addr>::1000</start_addr><end_addr>::2000</end_addr>` +
				`<constructor>opt2</constructor><prefix_len>112</prefix_len></dhcp_ranges>`,
			host:       "fd00:2::1050",
			wantScope:  -1,
			wantSubnet: []string{""},
		},
		{
			name: "a prefix_len shorter than the constructor's prefix builds no range",
			ranges: `<dhcp_ranges><interface>opt2</interface><start_addr>::1000</start_addr><end_addr>::2000</end_addr>` +
				`<constructor>opt2</constructor><prefix_len>48</prefix_len></dhcp_ranges>`,
			host:       "fd00:2::50",
			wantScope:  -1,
			wantSubnet: []string{""},
		},
		{
			name: "an IPv6 range no interface holds is named by its prefix",
			ranges: `<dhcp_ranges><start_addr>fd00:9::100</start_addr><end_addr>fd00:9::1ff</end_addr>` +
				`</dhcp_ranges>`,
			host: "fd00:9::50", wantScope: 0, wantSubnet: []string{"fd00:9::/64"},
		},
	}
}

// TestConverter_Dnsmasq_RangeNetworks4 places reservations by the network
// dnsmasq matches each range on: its subnet mask or prefix_len when set, else
// for a local range its interface's network, else for a relayed range its
// address class, with local ranges tried before relayed ones.
func TestConverter_Dnsmasq_RangeNetworks4(t *testing.T) {
	t.Parallel()

	tests := slices.Concat(rangeNetworks4Cases(), rangeNetworksDynamicCases(), rangeNetworks6Cases())

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			device, warnings := parseDnsmasqConfig(t, `<dnsmasq version="1.0.9"><enable>1</enable>`+tt.ranges+
				`<hosts><host>h</host><ip>`+tt.host+`</ip><hwaddr>aa:bb:cc:dd:ee:80</hwaddr></hosts></dnsmasq>`, "")

			require.Len(t, device.DHCP, len(tt.wantSubnet))
			for i, scope := range device.DHCP {
				assert.Equal(t, tt.wantSubnet[i], scope.Subnet, "subnet of scope %d", i)
				if i == tt.wantScope {
					assert.Len(t, scope.StaticLeases, 1, "scope %d", i)
				} else {
					assert.Empty(t, scope.StaticLeases, "scope %d", i)
				}
			}
			if tt.wantScope < 0 {
				got := dnsmasqWarnings(warnings)
				require.Len(t, got, 1)
				assert.Equal(t, "dnsmasq.hosts", got[0].Field)
			}
		})
	}
}

// TestConverter_Dnsmasq_GlobalOptionDoesNotPairScopes keeps two relayed ranges
// that share only a gateway every scope gets from a global option apart (d2):
// {10.50, 10.60} to {10.60, 10.70} is one range removed and one added, and
// nothing changes on 10.60. The test holds no reservations: every 10.x
// address lies in each range's guessed 10.0.0.0/8, so a reservation would go
// to whichever range comes first.
func TestConverter_Dnsmasq_GlobalOptionDoesNotPairScopes(t *testing.T) {
	t.Parallel()

	rangeXML := func(net string) string {
		return `<dhcp_ranges><start_addr>10.` + net + `.0.100</start_addr><end_addr>10.` + net +
			`.0.199</end_addr></dhcp_ranges>`
	}
	config := func(nets ...string) string {
		var x strings.Builder
		x.WriteString(`<dnsmasq version="1.0.9"><enable>1</enable>`)
		for _, n := range nets {
			x.WriteString(rangeXML(n))
		}
		x.WriteString(`<dhcp_options><option>3</option><value>192.168.1.1</value></dhcp_options></dnsmasq>`)
		return x.String()
	}
	oldDevice, _ := parseDnsmasqConfig(t, config("50", "60"), "")
	newDevice, _ := parseDnsmasqConfig(t, config("60", "70"), "")
	require.Len(t, oldDevice.DHCP, 2)
	assert.Equal(t, "192.168.1.1", oldDevice.DHCP[0].Gateway)

	assert.Equal(t, []string{
		"dhcpd.dnsmasq[10.0.0.0/8,10.50.0.100]",
		"dhcpd.dnsmasq[10.0.0.0/8,10.70.0.100]",
	}, diffPaths(oldDevice, newDevice))
}

// TestConverter_Dnsmasq_SharedNetworkRangesPairByRange pairs ranges that share
// one relayed network by the range, not by the reservations the converter
// puts on the first of them. The changes to scopes themselves are checked;
// reservations can still appear to move between such ranges.
func TestConverter_Dnsmasq_SharedNetworkRangesPairByRange(t *testing.T) {
	t.Parallel()

	host := func(name, ip, mac string) string {
		return `<hosts><host>` + name + `</host><ip>` + ip + `</ip><hwaddr>aa:bb:cc:dd:ee:` + mac + `</hwaddr></hosts>`
	}
	masked := func(from, to string) string {
		return `<dhcp_ranges><start_addr>` + from + `</start_addr><end_addr>` + to + `</end_addr>` +
			`<subnet_mask>255.255.255.0</subnet_mask></dhcp_ranges>`
	}
	guessed := func(from, to string) string {
		return `<dhcp_ranges><start_addr>` + from + `</start_addr><end_addr>` + to + `</end_addr></dhcp_ranges>`
	}
	gateway := `<dhcp_options><option>3</option><value>192.168.1.1</value></dhcp_options>`
	wrap := func(body string) string { return `<dnsmasq version="1.0.9"><enable>1</enable>` + body + `</dnsmasq>` }

	r50, r60, r70 := guessed("10.50.0.100", "10.50.0.199"), guessed("10.60.0.100", "10.60.0.199"),
		guessed("10.70.0.100", "10.70.0.199")
	b, b2 := host("b", "10.60.0.10", "52"), host("b2", "10.60.0.11", "54")
	s1, s2 := guessed("172.20.1.100", "172.20.1.199"), guessed("172.20.2.100", "172.20.2.199")
	h := host("h1", "172.20.1.10", "01") + host("h2", "172.20.2.10", "02") + host("h3", "172.20.2.11", "03")
	p := host("p1", "172.20.1.10", "01") + host("p2", "172.20.1.11", "02")
	v6a, v6b := guessed("fd00:9::100", "fd00:9::1ff"), guessed("fd00:9::200", "fd00:9::2ff")
	h6 := host("h6", "fd00:9::50", "61")

	tests := []struct {
		name     string
		old, new string
		want     []string
	}{
		{
			name: "a relayed /24 split in two, first deleted (a9)",
			old:  wrap(masked("172.20.1.100", "172.20.1.149") + masked("172.20.1.150", "172.20.1.199") + p),
			new:  wrap(masked("172.20.1.150", "172.20.1.199") + p),
			want: []string{"dhcpd.dnsmasq[172.20.1.0/24,172.20.1.100]"},
		},
		{
			name: "one range removed and one added beside an unchanged one (d2b)",
			old:  wrap(r50 + r60 + gateway + host("a", "10.50.0.10", "51") + b + b2),
			new:  wrap(r60 + r70 + gateway + b + b2 + host("c", "10.70.0.10", "53")),
			want: []string{"dhcpd.dnsmasq[10.0.0.0/8,10.50.0.100]", "dhcpd.dnsmasq[10.0.0.0/8,10.70.0.100]"},
		},
		{
			name: "two DHCPv6 ranges in one relayed /64 listed in the other order (v6r)",
			old:  wrap(v6a + v6b + h6),
			new:  wrap(v6b + v6a + h6),
			want: nil,
		},
		{
			name: "two DHCPv6 ranges with two reservations listed in the other order (v6r2)",
			old:  wrap(v6a + v6b + h6 + host("h7", "fd00:9::51", "62")),
			new:  wrap(v6b + v6a + h6 + host("h7", "fd00:9::51", "62")),
			want: nil,
		},
		{
			name: "the first of two DHCPv6 ranges in one relayed /64 deleted (v6d)",
			old:  wrap(v6a + v6b + h6),
			new:  wrap(v6b + h6),
			want: []string{"dhcpd.dnsmasq[fd00:9::/64,fd00:9::100]"},
		},
		{
			name: "two ranges listed in the other order (a6)",
			old:  wrap(s1 + s2 + h),
			new:  wrap(s2 + s1 + h),
			want: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			oldDevice, _ := parseDnsmasqConfig(t, tt.old, "")
			newDevice, _ := parseDnsmasqConfig(t, tt.new, "")
			var scopePaths []string
			for _, path := range diffPaths(oldDevice, newDevice) {
				if !strings.Contains(path, ".staticmap[") {
					scopePaths = append(scopePaths, path)
				}
			}
			assert.Equal(t, tt.want, scopePaths)
		})
	}
}

// TestConverter_Dnsmasq_SharedNetworkReservationChanges reports a reservation
// change in a range that shares its network with another, when the range
// itself pairs only through that reservation: its pool was edited (a4), or
// it is static and has none (e2).
func TestConverter_Dnsmasq_SharedNetworkReservationChanges(t *testing.T) {
	t.Parallel()

	host := func(name, ip, mac string) string {
		return `<hosts><host>` + name + `</host><ip>` + ip + `</ip><hwaddr>aa:bb:cc:dd:ee:` + mac + `</hwaddr></hosts>`
	}
	pool := func(from, to string) string {
		return `<dhcp_ranges><start_addr>` + from + `</start_addr><end_addr>` + to + `</end_addr></dhcp_ranges>`
	}
	static := func(start string) string {
		return `<dhcp_ranges><start_addr>` + start + `</start_addr><subnet_mask>255.255.255.0</subnet_mask>` +
			`<mode>static</mode></dhcp_ranges>`
	}
	wrap := func(body string) string { return `<dnsmasq version="1.0.9"><enable>1</enable>` + body + `</dnsmasq>` }
	p12 := host("p1", "172.20.1.10", "01") + host("p2", "172.20.1.11", "02")

	tests := []struct {
		name     string
		old, new string
		want     string
	}{
		{
			name: "a range split in two while its reservation moves (a4)",
			old:  wrap(pool("172.20.1.100", "172.20.1.199") + host("h", "172.20.1.10", "01")),
			new: wrap(pool("172.20.1.100", "172.20.1.149") + pool("172.20.1.150", "172.20.1.199") +
				host("h", "172.20.1.11", "01")),
			want: "dhcpd.dnsmasq[172.20.0.0/16].staticmap[aa:bb:cc:dd:ee:01].ipaddr",
		},
		{
			name: "a reservation added on one of two static ranges in one /24 (e2)",
			old:  wrap(static("172.20.1.0") + static("172.20.1.128") + p12),
			new:  wrap(static("172.20.1.0") + static("172.20.1.128") + p12 + host("p3", "172.20.1.12", "03")),
			want: "dhcpd.dnsmasq[172.20.1.0/24].staticmap[aa:bb:cc:dd:ee:03]",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			oldDevice, _ := parseDnsmasqConfig(t, tt.old, "")
			newDevice, _ := parseDnsmasqConfig(t, tt.new, "")
			assert.Contains(t, diffPaths(oldDevice, newDevice), tt.want)
		})
	}
}
