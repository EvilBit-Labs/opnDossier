package audit

import (
	"slices"
	"strings"
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/analysis"
	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// snmpForwardConfig is an OPNsense config with a net-snmp agent answering
// "public" on the given listen list, with the given filter rules, port
// forwards and aliases.
func snmpForwardConfig(listen, rules, forwards, aliases string) string {
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
      <ipaddr>198.51.100.2</ipaddr>
      <subnet>24</subnet>
    </wan>
    <lan>
      <enable>1</enable>
      <if>vtnet1</if>
      <ipaddr>192.168.1.1</ipaddr>
      <subnet>24</subnet>
    </lan>
  </interfaces>
  <filter>` + rules + `
  </filter>
  <nat>
    <outbound>
      <mode>automatic</mode>
    </outbound>` + forwards + `
  </nat>
  <OPNsense>
    <Firewall>
      <Alias version="1.0.1">
        <aliases>` + aliases + `
        </aliases>
      </Alias>
    </Firewall>
    <netsnmp>
      <general version="1.0.7">
        <enabled>1</enabled>
        <community>public</community>
        <listen>` + listen + `</listen>
      </general>
      <user version="1.0.1">
        <users/>
      </user>
    </netsnmp>
  </OPNsense>
</opnsense>`
}

// snmpForwardRule is a WAN pass rule for UDP 161 to dest. A non-empty assoc
// links it to the port forward that stores it.
func snmpForwardRule(dest, assoc string) string {
	return `
    <rule>
      <type>pass</type>
      <associated-rule-id>` + assoc + `</associated-rule-id>
      <interface>wan</interface>
      <ipprotocol>inet</ipprotocol>
      <protocol>udp</protocol>
      <source>
        <any>1</any>
      </source>
      <destination>
        <address>` + dest + `</address>
        <port>161</port>
      </destination>
      <descr>snmp</descr>
    </rule>`
}

// snmpLegacyForward is a port forward as OPNsense wrote it up to 25.7, from
// UDP 161 on the WAN address to target, with any extra elements appended.
func snmpLegacyForward(target, assoc, extra string) string {
	return `
    <rule>
      <protocol>udp</protocol>
      <interface>wan</interface>
      <ipprotocol>inet</ipprotocol>
      <descr>snmp forward</descr>
      <associated-rule-id>` + assoc + `</associated-rule-id>
      <target>` + target + `</target>
      <local-port>161</local-port>
      <source>
        <any>1</any>
      </source>
      <destination>
        <network>wanip</network>
        <port>161</port>
      </destination>` + extra + `
    </rule>`
}

// snmpProxyForward is a transparent web proxy's port forward: TCP 80 on the
// LAN to target port 3128, in the shape snmpLegacyForward writes.
func snmpProxyForward(target string) string {
	return strings.NewReplacer(
		"<interface>wan</interface>", "<interface>lan</interface>",
		"<protocol>udp</protocol>", "<protocol>tcp</protocol>",
		"<local-port>161</local-port>", "<local-port>3128</local-port>",
		"<port>161</port>", "<port>80</port>",
	).Replace(snmpLegacyForward(target, "", ""))
}

// snmpModelForward is the same port forward as OPNsense 26.1 and later write
// it, with every flag element present.
func snmpModelForward(target, disabled string) string {
	return `
    <rule uuid="b2b2b2b2-0000-4000-8000-0000000000a1">
      <sequence>100</sequence>
      <disabled>` + disabled + `</disabled>
      <nordr>0</nordr>
      <interface>wan</interface>
      <ipprotocol>inet</ipprotocol>
      <protocol>udp</protocol>
      <source>
        <network/>
        <port/>
        <not>0</not>
      </source>
      <destination>
        <network>wanip</network>
        <port>161</port>
        <not>0</not>
      </destination>
      <target>` + target + `</target>
      <local-port>161</local-port>
      <descr>snmp forward</descr>
      <pass/>
      <associated-rule-id/>
    </rule>`
}

// snmpForwardAlias is an alias of the given type with newline-separated
// members.
func snmpForwardAlias(uuid, name, aliasType, members string) string {
	return `
          <alias uuid="` + uuid + `">
            <name>` + name + `</name>
            <type>` + aliasType + `</type>
            <content>` + members + `</content>
          </alias>`
}

// TestSNMPAgent_PortForwardToLoopbackKeepsWANExposure drives OPNsense configs
// with a net-snmp agent bound only to 127.0.0.1 through parse, convert and red
// mode. pf rewrites a forward's destination before delivery, so a WAN forward
// of UDP 161 to loopback reaches that agent, and the filter rule passing it
// decides the agent's reachability as for any other listen list. Without such
// a forward, a WAN rule to 127.0.0.1 of its own delivers nothing to the agent,
// so it stays local, as it does when the only forward to loopback cannot reach
// UDP 161. The cases vary what the forward targets, its flags in both stored
// shapes, its place in the list, and the service it forwards.
func TestSNMPAgent_PortForwardToLoopbackKeepsWANExposure(t *testing.T) {
	t.Parallel()

	const (
		loopHost = `127.0.0.1`
		lanHost  = `192.168.1.50`
	)

	aliases := snmpForwardAlias("c3c3c3c3-0000-4000-8000-000000000001", "LOOP_HOST", "host", loopHost) +
		snmpForwardAlias("c3c3c3c3-0000-4000-8000-000000000002", "LAN_HOST", "host", lanHost) +
		snmpForwardAlias("c3c3c3c3-0000-4000-8000-000000000003", "SNMP_GROUP", "networkgroup", "LAN_HOST\nLOOP_HOST")

	tests := []struct {
		name     string
		rules    string
		forwards string
		// disabled and noRDR are what the last forward must convert to, so a
		// case cannot pass on a flag the parser did not read.
		disabled, noRDR bool
		exposed         bool
	}{
		{
			name:     "forward to 127.0.0.1",
			rules:    snmpForwardRule(loopHost, "nat_1"),
			forwards: snmpLegacyForward(loopHost, "nat_1", ""),
			exposed:  true,
		},
		{
			name:     "forward to an alias holding 127.0.0.1",
			rules:    snmpForwardRule("LOOP_HOST", "nat_1"),
			forwards: snmpLegacyForward("LOOP_HOST", "nat_1", ""),
			exposed:  true,
		},
		{
			name:     "forward to a network group naming that alias second",
			rules:    snmpForwardRule("SNMP_GROUP", "nat_1"),
			forwards: snmpLegacyForward("SNMP_GROUP", "nat_1", ""),
			exposed:  true,
		},
		{
			name:     "forward to a LAN host first, to 127.0.0.1 second",
			rules:    snmpForwardRule(lanHost, "nat_0") + snmpForwardRule(loopHost, "nat_1"),
			forwards: snmpLegacyForward(lanHost, "nat_0", "") + snmpLegacyForward(loopHost, "nat_1", ""),
			exposed:  true,
		},
		{
			name:     "26.1 forward to 127.0.0.1, not disabled",
			rules:    snmpForwardRule(loopHost, "nat_1"),
			forwards: snmpModelForward(loopHost, "0"),
			exposed:  true,
		},
		{
			// pf reads (self) as every address of the firewall, lo0's among
			// them.
			name:     "forward to (self)",
			rules:    snmpForwardNetworkRule("(self)"),
			forwards: snmpLegacyForward("(self)", "nat_1", ""),
			exposed:  true,
		},
		{
			name:     "26.1 forward to (self)",
			rules:    snmpForwardNetworkRule("(self)"),
			forwards: snmpModelForward("(self)", "0"),
			exposed:  true,
		},
		{
			// A transparent proxy's TCP forward to loopback cannot reach the
			// agent on UDP 161.
			name:     "rule to 127.0.0.1 of its own, LAN forward of TCP 80 to 127.0.0.1 port 3128",
			rules:    snmpForwardRule(loopHost, ""),
			forwards: snmpProxyForward(loopHost),
		},
		{
			name:  "rule to 127.0.0.1 of its own, no forward",
			rules: snmpForwardRule(loopHost, ""),
		},
		{
			name:     "rule to 127.0.0.1 of its own, forward to a LAN host",
			rules:    snmpForwardRule(loopHost, "") + snmpForwardRule(lanHost, "nat_0"),
			forwards: snmpLegacyForward(lanHost, "nat_0", ""),
		},
		{
			name:     "rule to 127.0.0.1 of its own, forward to an alias holding a LAN host",
			rules:    snmpForwardRule(loopHost, "") + snmpForwardRule("LAN_HOST", "nat_0"),
			forwards: snmpLegacyForward("LAN_HOST", "nat_0", ""),
		},
		{
			name:     "rule to 127.0.0.1 of its own, disabled forward to 127.0.0.1",
			rules:    snmpForwardRule(loopHost, ""),
			forwards: snmpLegacyForward(loopHost, "", "\n      <disabled>1</disabled>"),
			disabled: true,
		},
		{
			name:     "rule to 127.0.0.1 of its own, no-RDR forward naming 127.0.0.1",
			rules:    snmpForwardRule(loopHost, ""),
			forwards: snmpLegacyForward(loopHost, "", "\n      <nordr>1</nordr>"),
			noRDR:    true,
		},
		{
			name:     "rule to 127.0.0.1 of its own, disabled 26.1 forward to 127.0.0.1",
			rules:    snmpForwardRule(loopHost, ""),
			forwards: snmpModelForward(loopHost, "1"),
			disabled: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			device := parseConfig(t, snmpForwardConfig(loopHost, tc.rules, tc.forwards, aliases))
			require.Equal(t, []string{loopHost}, device.SNMP.ListenAddresses)
			require.Len(t, device.NAT.InboundRules, strings.Count(tc.forwards, "<target>"))
			if len(device.NAT.InboundRules) > 0 {
				last := device.NAT.InboundRules[len(device.NAT.InboundRules)-1]
				require.Equal(t, tc.disabled, last.Disabled, "disabled")
				require.Equal(t, tc.noRDR, last.NoRDR, "no-RDR")
			}

			assertSNMPForwardExposure(t, device, tc.exposed)
		})
	}
}

// assertSNMPForwardExposure checks that red mode gives the SNMP agent on device
// the reachability exposed implies, and reports it as WAN-exposed exactly when
// exposed is true.
func assertSNMPForwardExposure(t *testing.T, device *common.CommonDevice, exposed bool) {
	t.Helper()

	want := analysis.Local
	if exposed {
		want = analysis.WANReachable
	}

	assertSNMPReachability(t, device, want)
}

// assertSNMPReachability checks that red mode gives the SNMP agent on device
// the reachability want, and reports it as WAN-exposed exactly when want is
// WAN-reachable.
func assertSNMPReachability(t *testing.T, device *common.CommonDevice, want analysis.Reachability) {
	t.Helper()

	services := serviceExposures(device)
	idx := slices.IndexFunc(services, func(s exposedService) bool { return s.name == serviceNameSNMP })
	require.GreaterOrEqual(t, idx, 0, "snmp missing from the services red mode considers: %+v", services)
	assert.Equal(t, want, services[idx].reachability)

	report := newRedReport(device)
	runRedAnalysis(report)

	_, reported := findingByTitlePrefix(report.Findings, "WAN-Exposed Service: SNMP")
	assert.Equal(t, want == analysis.WANReachable, reported, "red-mode SNMP exposure")
}

// TestForwardsToLoopback_TargetsAndFlags checks which port forwards count as
// redirecting traffic to loopback. A target counts when it is, or spans, a
// loopback address, in either family or IPv4-mapped; when it is (self), which
// pf reads as every address of the firewall, while (SELF) is no target OPNsense
// redirects to and does not count; when it is an alias, or names one, that
// holds one or gets its addresses at runtime, as a URL table does; and when it
// is a name no alias defines that has the shape of an alias name. A disabled
// or no-RDR forward never counts, and the counting forward may sit anywhere in
// the list.
func TestForwardsToLoopback_TargetsAndFlags(t *testing.T) {
	t.Parallel()

	objects := common.NamedObjects{
		"LOOP_HOST": {Name: "LOOP_HOST", Type: common.NamedObjectTypeHost, Members: []string{"127.0.0.1"}},
		"LAN_HOST":  {Name: "LAN_HOST", Type: common.NamedObjectTypeHost, Members: []string{"192.168.1.50"}},
		"SPAN_RANGE": {
			Name:    "SPAN_RANGE",
			Type:    common.NamedObjectTypeHost,
			Members: []string{"126.255.255.250-127.0.0.5"},
		},
		"UNSTORED": {Name: "UNSTORED", Type: common.NamedObjectTypeHost, Members: []string{"bogons"}},
		"URL_TABLE": {
			Name:    "URL_TABLE",
			Type:    aliasTypeURLTable,
			Members: []string{"https://example.com/list.txt"},
		},
		"TABLE_GROUP": {Name: "TABLE_GROUP", Type: aliasTypeNetworkGroup, Members: []string{"LAN_HOST", "URL_TABLE"}},
		"SNMP_GROUP":  {Name: "SNMP_GROUP", Type: aliasTypeNetworkGroup, Members: []string{"LAN_HOST", "LOOP_HOST"}},
		"LAN_GROUP":   {Name: "LAN_GROUP", Type: aliasTypeNetworkGroup, Members: []string{"LAN_HOST"}},
	}

	forward := func(target string) common.InboundNATRule {
		return common.InboundNATRule{Interfaces: []string{"wan"}, Protocol: "udp", InternalIP: target}
	}

	tests := []struct {
		name     string
		forwards []common.InboundNATRule
		want     bool
	}{
		{name: "IPv4 loopback", forwards: []common.InboundNATRule{forward("127.0.0.1")}, want: true},
		{name: "another IPv4 loopback address", forwards: []common.InboundNATRule{forward("127.0.0.2")}, want: true},
		{name: "IPv6 loopback", forwards: []common.InboundNATRule{forward("::1")}, want: true},
		{name: "IPv4-mapped loopback", forwards: []common.InboundNATRule{forward("::ffff:127.0.0.1")}, want: true},
		{name: "loopback network", forwards: []common.InboundNATRule{forward("127.0.0.0/8")}, want: true},
		{name: "network spanning loopback", forwards: []common.InboundNATRule{forward("0.0.0.0/0")}, want: true},
		{name: "the firewall itself", forwards: []common.InboundNATRule{forward("(self)")}, want: true},
		{name: "the firewall itself in upper case", forwards: []common.InboundNATRule{forward("(SELF)")}},
		{name: "LAN host", forwards: []common.InboundNATRule{forward("192.168.1.50")}},
		{name: "IPv6 host", forwards: []common.InboundNATRule{forward("2001:db8::50")}},
		{name: "no target", forwards: []common.InboundNATRule{forward("")}},
		{name: "hostname with a domain", forwards: []common.InboundNATRule{forward("snmp.example.com")}},
		{name: "name no alias defines", forwards: []common.InboundNATRule{forward("DELETED_ALIAS")}, want: true},
		{name: "alias holding loopback", forwards: []common.InboundNATRule{forward("LOOP_HOST")}, want: true},
		{name: "alias holding a LAN host", forwards: []common.InboundNATRule{forward("LAN_HOST")}},
		{
			name:     "alias holding a range spanning loopback",
			forwards: []common.InboundNATRule{forward("SPAN_RANGE")},
			want:     true,
		},
		{
			name:     "alias naming a table the config does not store",
			forwards: []common.InboundNATRule{forward("UNSTORED")},
			want:     true,
		},
		{name: "URL table alias", forwards: []common.InboundNATRule{forward("URL_TABLE")}, want: true},
		{
			name:     "network group naming the URL table second",
			forwards: []common.InboundNATRule{forward("TABLE_GROUP")},
			want:     true,
		},
		{
			name:     "network group naming the loopback alias second",
			forwards: []common.InboundNATRule{forward("SNMP_GROUP")},
			want:     true,
		},
		{name: "network group naming a LAN alias", forwards: []common.InboundNATRule{forward("LAN_GROUP")}},
		{
			name: "disabled forward to loopback",
			forwards: []common.InboundNATRule{func() common.InboundNATRule {
				f := forward("127.0.0.1")
				f.Disabled = true

				return f
			}()},
		},
		{
			name: "no-RDR forward naming loopback",
			forwards: []common.InboundNATRule{func() common.InboundNATRule {
				f := forward("127.0.0.1")
				f.NoRDR = true

				return f
			}()},
		},
		{
			name:     "forward to a LAN host, then to loopback",
			forwards: []common.InboundNATRule{forward("192.168.1.50"), forward("127.0.0.1")},
			want:     true,
		},
		{name: "no forward"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			device := &common.CommonDevice{
				NAT:          common.NATConfig{InboundRules: tc.forwards},
				NamedObjects: objects,
			}

			assert.Equal(t, tc.want, forwardsToLoopback(device))

			// The forward decides whether a loopback-only agent is Local.
			device.SNMP = common.SNMPConfig{Enabled: true, ListenAddresses: []string{"127.0.0.1"}}
			services := []exposedService{
				{kind: exploitKindSNMP, name: serviceNameSNMP, reachability: analysis.WANReachable},
			}
			applySNMPListen(device, services)

			want := analysis.Local
			if tc.want {
				want = analysis.WANReachable
			}

			assert.Equal(t, want, services[0].reachability)
		})
	}
}
