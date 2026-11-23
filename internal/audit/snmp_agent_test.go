package audit

import (
	"slices"
	"strings"
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/analysis"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// snmpAgentConfig is an OPNsense config whose WAN passes UDP 161 to the
// firewall, with the given SNMP elements spliced in at the top level and
// under <OPNsense>.
func snmpAgentConfig(topLevel, model string) string {
	return `<?xml version="1.0"?>
<opnsense>
  <system>
    <hostname>fw</hostname>
    <domain>example.com</domain>
  </system>
  <interfaces>
    <wan>
      <enable>1</enable>
      <if>vtnet0</if>
      <ipaddr>dhcp</ipaddr>
    </wan>
    <lan>
      <enable>1</enable>
      <if>vtnet1</if>
      <ipaddr>192.168.1.1</ipaddr>
      <subnet>24</subnet>
    </lan>
  </interfaces>
  <filter>
    <rule>
      <type>pass</type>
      <interface>wan</interface>
      <ipprotocol>inet</ipprotocol>
      <protocol>udp</protocol>
      <source>
        <any/>
      </source>
      <destination>
        <network>wanip</network>
        <port>161</port>
      </destination>
      <descr>monitoring</descr>
    </rule>
  </filter>` + topLevel + `
  <OPNsense>` + model + `
  </OPNsense>
</opnsense>`
}

const (
	// snmpStaleLegacy is the factory default's legacy block, which starts no
	// agent on any release.
	snmpStaleLegacy = `
  <snmpd>
    <syslocation/>
    <syscontact/>
    <rocommunity>public</rocommunity>
  </snmpd>`

	snmpNetsnmpDisabled = `
    <netsnmp>
      <general version="1.0.7">
        <enabled>0</enabled>
        <community>public</community>
      </general>
      <user version="1.0.1">
        <users/>
      </user>
    </netsnmp>`

	snmpNetsnmpPublic = `
    <netsnmp>
      <general version="1.0.7">
        <enabled>1</enabled>
        <community>public</community>
        <listen/>
      </general>
      <user version="1.0.1">
        <users/>
      </user>
    </netsnmp>`

	snmpNetsnmpV3Only = `
    <netsnmp>
      <general version="1.0.7">
        <enabled>1</enabled>
        <community/>
      </general>
      <user version="1.0.1">
        <users>
          <user uuid="1a0d8f0e-7d6b-4c39-a3a1-4e2b8c9d0001">
            <enabled>1</enabled>
            <username>monitor</username>
            <password>MonitorPass123</password>
            <enckey>MonitorKey12345</enckey>
            <readwrite>0</readwrite>
          </user>
        </users>
      </user>
    </netsnmp>`
)

// TestSNMPAgent_ControlsFollowTheAgentTheConfigStarts drives OPNsense configs
// through parse, convert, the FIREWALL and STIG plugins and red mode. The
// verdicts follow the agent the config starts: the os-net-snmp model when it
// is enabled, a legacy <snmpd> block with <enable> when it is not, and never
// the legacy block the factory default left behind without <enable>.
func TestSNMPAgent_ControlsFollowTheAgentTheConfigStarts(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		topLevel string
		model    string
		// running is whether an agent runs; defaultCommunity whether it
		// answers "public".
		running          bool
		defaultCommunity bool
	}{
		{name: "stale legacy block only", topLevel: snmpStaleLegacy},
		{name: "stale legacy block and net-snmp disabled", topLevel: snmpStaleLegacy, model: snmpNetsnmpDisabled},
		{name: "net-snmp enabled with public", model: snmpNetsnmpPublic, running: true, defaultCommunity: true},
		{name: "net-snmp enabled with SNMPv3 users only", model: snmpNetsnmpV3Only, running: true},
		{
			name: "legacy block with enable and net-snmp disabled",
			topLevel: `
  <snmpd>
    <rocommunity>legacycomm</rocommunity>
    <enable/>
  </snmpd>`,
			model:   snmpNetsnmpDisabled,
			running: true,
		},
	}

	logger := newTestLogger(t)
	pm := NewPluginManager(logger, nil)
	require.NoError(t, pm.InitializePlugins(t.Context()))

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			device := parseConfig(t, snmpAgentConfig(tc.topLevel, tc.model))
			assert.Equal(t, tc.running, device.SNMP.IsEnabled())

			services := analysis.ComputeStatistics(device).EnabledServices
			assert.Equal(t, tc.running, slices.Contains(services, analysis.ServiceNameSNMP), "enabled services")

			results, err := pm.GetRegistry().RunComplianceChecks(device, []string{"firewall", "stig"}, logger)
			require.NoError(t, err)

			assert.Equal(t, !tc.running, results.Compliance["firewall"]["FIREWALL-045"], "FIREWALL-045")
			assert.Equal(t, !tc.defaultCommunity, results.Compliance["firewall"]["FIREWALL-046"], "FIREWALL-046")
			assert.Equal(t, !tc.running, results.Compliance["stig"]["V-206690"], "V-206690")

			report := newRedReport(device)
			runRedAnalysis(report)
			_, exposed := findingByTitlePrefix(report.Findings, "WAN-Exposed Service: SNMP")
			assert.Equal(t, tc.running, exposed, "red-mode SNMP exposure")
		})
	}
}

// TestSNMPAgent_ListenAddressesDecideWANExposure keeps the WAN rule passing
// UDP 161 and varies the agent's listen list. With no port forward to
// loopback, an agent bound only to loopback answers no other host: it stays
// among the services red mode considers, as local, and draws no WAN exposure.
// Any other address, an unparseable one, or an empty list (every IPv4 address
// and the IPv6 loopback) is still judged by the rule.
func TestSNMPAgent_ListenAddressesDecideWANExposure(t *testing.T) {
	t.Parallel()

	tests := []struct {
		listen string
		want   analysis.Reachability
	}{
		{listen: "", want: analysis.WANReachable},
		{listen: "127.0.0.1", want: analysis.Local},
		{listen: "127.0.0.1,::1", want: analysis.Local},
		{listen: "127.0.0.0/8", want: analysis.Local},
		{listen: "::1/128", want: analysis.Local},
		// ::1/127 also holds ::, the unspecified address, so it is not loopback.
		{listen: "::1/127", want: analysis.WANReachable},
		{listen: "127.0.0.1,192.168.1.1", want: analysis.WANReachable},
		{listen: "0.0.0.0", want: analysis.WANReachable},
		{listen: "localhost", want: analysis.WANReachable},
	}

	for _, tc := range tests {
		t.Run("listen="+tc.listen, func(t *testing.T) {
			t.Parallel()

			model := strings.Replace(snmpNetsnmpPublic, "<listen/>", "<listen>"+tc.listen+"</listen>", 1)
			device := parseConfig(t, snmpAgentConfig("", model))

			services := serviceExposures(device)
			idx := slices.IndexFunc(services, func(s exposedService) bool { return s.name == "snmp" })
			require.GreaterOrEqual(t, idx, 0, "snmp missing from the services red mode considers: %+v", services)
			assert.Equal(t, tc.want, services[idx].reachability)

			report := newRedReport(device)
			runRedAnalysis(report)

			_, exposed := findingByTitlePrefix(report.Findings, "WAN-Exposed Service: SNMP")
			assert.Equal(t, tc.want == analysis.WANReachable, exposed, "red-mode SNMP exposure")
		})
	}
}

// TestSNMPAgent_LoopbackOnlyAgentStaysLocalWithPacketFilteringDisabled sets
// <system><disablefilter>, which turns pf off, and varies the agent's listen
// list. With no port forward to loopback, an agent bound only to loopback
// answers no other host with or without pf, so it stays local and draws no WAN
// exposure, with or without a WAN rule passing UDP 161. The cases with any
// other listen list keep that rule, and they are reported as WAN-exposed.
func TestSNMPAgent_LoopbackOnlyAgentStaysLocalWithPacketFilteringDisabled(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		listen  string
		wanRule bool
		local   bool
	}{
		{name: "IPv4 loopback, no rule", listen: "127.0.0.1", local: true},
		{name: "IPv6 loopback, no rule", listen: "::1", local: true},
		{name: "IPv4 loopback, WAN rule", listen: "127.0.0.1", wanRule: true, local: true},
		{name: "both loopbacks, WAN rule", listen: "127.0.0.1,::1", wanRule: true, local: true},
		{name: "loopback and a LAN address, WAN rule", listen: "127.0.0.1,192.168.1.1", wanRule: true},
		{name: "no listen address, WAN rule", wanRule: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			model := strings.Replace(snmpNetsnmpPublic, "<listen/>", "<listen>"+tc.listen+"</listen>", 1)
			config := strings.Replace(snmpAgentConfig("", model),
				"</domain>", "</domain>\n    <disablefilter>enabled</disablefilter>", 1)
			if !tc.wanRule {
				start := strings.Index(config, "<filter>")
				end := strings.Index(config, "</filter>") + len("</filter>")
				config = config[:start] + "<filter/>" + config[end:]
			}

			device := parseConfig(t, config)

			services := serviceExposures(device)
			idx := slices.IndexFunc(services, func(s exposedService) bool { return s.name == "snmp" })
			require.GreaterOrEqual(t, idx, 0, "snmp missing from the services red mode considers: %+v", services)
			assert.Equal(t, tc.local, services[idx].reachability == analysis.Local,
				"reachability %s", services[idx].reachability)

			report := newRedReport(device)
			runRedAnalysis(report)

			_, exposed := findingByTitlePrefix(report.Findings, "WAN-Exposed Service: SNMP")
			assert.Equal(t, !tc.local, exposed, "red-mode SNMP exposure")
		})
	}
}

// TestSNMPAgent_SnmpdBindAddressIsNotRead pins what the model reference says
// of an <snmpd> agent: no bind address is read for it, so it is judged by the
// firewall rules alone. pfSense binds bsnmpd to <snmpd><bindip>, an address or
// an interface name, and an agent bound there to loopback is still reported as
// WAN-exposed when a WAN rule passes UDP 161. That over-reports.
func TestSNMPAgent_SnmpdBindAddressIsNotRead(t *testing.T) {
	t.Parallel()

	for _, bindip := range []string{"127.0.0.1", "lo0"} {
		t.Run("bindip="+bindip, func(t *testing.T) {
			t.Parallel()

			device := parseConfig(t, `<?xml version="1.0"?>
<pfsense>
  <version>23.3</version>
  <system>
    <hostname>pf</hostname>
    <domain>example.com</domain>
  </system>
  <interfaces>
    <wan>
      <enable></enable>
      <if>vtnet0</if>
      <ipaddr>dhcp</ipaddr>
    </wan>
  </interfaces>
  <filter>
    <rule>
      <type>pass</type>
      <interface>wan</interface>
      <ipprotocol>inet</ipprotocol>
      <protocol>udp</protocol>
      <source>
        <any></any>
      </source>
      <destination>
        <network>wanip</network>
        <port>161</port>
      </destination>
      <descr>monitoring</descr>
    </rule>
  </filter>
  <snmpd>
    <rocommunity>pfcomm</rocommunity>
    <enable></enable>
    <bindip>`+bindip+`</bindip>
    <ipprotocol>4</ipprotocol>
  </snmpd>
</pfsense>`)
			require.True(t, device.SNMP.Enabled, "the agent runs")
			assert.Empty(t, device.SNMP.ListenAddresses, "no bind address is read for an <snmpd> agent")

			report := newRedReport(device)
			runRedAnalysis(report)

			_, exposed := findingByTitlePrefix(report.Findings, "WAN-Exposed Service: SNMP")
			assert.True(t, exposed, "judged by the WAN rule alone")
		})
	}
}
