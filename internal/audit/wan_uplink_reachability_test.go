package audit

import (
	"slices"
	"strings"
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/analysis"
	"github.com/EvilBit-Labs/opnDossier/internal/plugins/firewall"
	"github.com/EvilBit-Labs/opnDossier/internal/plugins/sans"
	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
)

// uplinkConfig is an OPNsense 26.7 config with the two shapes a WAN can take
// besides the "wan" key: an interface group (Firewall: Groups writes the group
// under <ifgroups>, comma-separated, and registers it under <interfaces> with
// type group) and a second uplink, which always keeps an optN key. wan is
// blocked and filtered, so any WAN finding below comes from the other shapes.
// {OPT1}, {GROUP}, {GATEWAYS}, {MEMBERS}, {RULES} and {NAT} are filled per
// case. The group's entry under <interfaces> carries its name as descr, as
// pf.inc pf_interfaces writes it.
const uplinkConfig = `<?xml version="1.0"?>
<opnsense>
  <system>
    <hostname>fw</hostname>
    <domain>example.com</domain>
    <webgui><protocol>https</protocol></webgui>
  </system>
  <interfaces>
    <wan>
      <enable>1</enable>
      <if>vtnet0</if>
      <ipaddr>dhcp</ipaddr>
      <blockpriv>1</blockpriv>
      <blockbogons>1</blockbogons>
    </wan>
    <lan>
      <enable>1</enable>
      <if>vtnet1</if>
      <ipaddr>192.168.1.1</ipaddr>
      <subnet>24</subnet>
    </lan>
    <opt1>
      <enable>1</enable>
      <if>vtnet2</if>
      <descr>ISP2</descr>
      {OPT1}
    </opt1>
    <opt2>
      <enable>1</enable>
      <if>vtnet3</if>
      <descr>SERVERS</descr>
      <ipaddr>10.0.2.1</ipaddr>
      <subnet>24</subnet>
    </opt2>
    <{GROUP}>
      <internal_dynamic>1</internal_dynamic>
      <descr>{GROUP}</descr>
      <if>{GROUP}</if>
      <virtual>1</virtual>
      <enable>1</enable>
      <type>group</type>
    </{GROUP}>
  </interfaces>
  <ifgroups version="1.0.0">
    <ifgroupentry uuid="d4d4d4d4-0000-4000-8000-000000000001">
      <ifname>{GROUP}</ifname>
      <members>{MEMBERS}</members>
      <nogroup>0</nogroup>
      <sequence>0</sequence>
      <descr>Uplinks</descr>
    </ifgroupentry>
  </ifgroups>
  <filter>{RULES}</filter>
  <nat><outbound><mode>automatic</mode></outbound>{NAT}</nat>
  <OPNsense>
    <Gateways version="1.0.0">{GATEWAYS}</Gateways>
  </OPNsense>
</opnsense>`

// staticOpt1 is opt1 with a static address and no gateway selected.
const staticOpt1 = `<ipaddr>198.51.100.2</ipaddr><subnet>24</subnet>`

// guiRuleOn passes any source to the firewall's web GUI on iface.
func guiRuleOn(iface string) string {
	return `<rule>
      <type>pass</type>
      <interface>` + iface + `</interface>
      <ipprotocol>inet</ipprotocol>
      <protocol>tcp</protocol>
      <source><any>1</any></source>
      <destination><network>(self)</network><port>443</port></destination>
      <descr>web GUI</descr>
    </rule>`
}

// gatewayItem is a model gateway on iface at 198.51.100.1; defaultGW is the
// <defaultgw> text.
func gatewayItem(name, iface, defaultGW string) string {
	return `<gateway_item uuid="e5e5e5e5-0000-4000-8000-` + strings.Repeat("0", 12-len(name)) + name + `">
      <disabled>0</disabled>
      <name>` + name + `</name>
      <interface>` + iface + `</interface>
      <ipprotocol>inet</ipprotocol>
      <gateway>198.51.100.1</gateway>
      <defaultgw>` + defaultGW + `</defaultgw>
    </gateway_item>`
}

// uplinkCase fills uplinkConfig. Empty fields take a LAN-only default.
type uplinkCase struct {
	opt1     string
	group    string
	gateways string
	members  string
	rules    string
	nat      string
}

func (c uplinkCase) config() string {
	opt1 := c.opt1
	if opt1 == "" {
		opt1 = staticOpt1
	}

	members := c.members
	if members == "" {
		members = "lan,opt2"
	}

	group := c.group
	if group == "" {
		group = "UPLINKS"
	}

	return strings.NewReplacer(
		"{OPT1}", opt1,
		"{GROUP}", group,
		"{GATEWAYS}", c.gateways,
		"{MEMBERS}", members,
		"{RULES}", c.rules,
		"{NAT}", c.nat,
	).Replace(uplinkConfig)
}

// failedControls runs the firewall and SANS plugins and returns the controls
// that failed.
func failedControls(t *testing.T, config string) []string {
	t.Helper()

	device := parseConfig(t, config)

	fwFindings, _, err := firewall.NewPlugin().RunChecks(device)
	if err != nil {
		t.Fatal(err)
	}

	sansFindings, _, err := sans.NewPlugin().RunChecks(device)
	if err != nil {
		t.Fatal(err)
	}

	findings := slices.Concat(fwFindings, sansFindings)
	failed := make([]string, 0, len(findings))

	for _, finding := range findings {
		failed = append(failed, finding.Reference)
	}

	return failed
}

// TestWANReachability_UplinkShapes drives each shape through parse, red-mode
// analysis and the blue-mode plugins. A rule passing any source to the web GUI
// must read as WAN-exposed when its interface is an uplink, and as LAN-only
// when it is not, so each WAN case has a LAN twin that differs in one element.
func TestWANReachability_UplinkShapes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		config  uplinkCase
		wantWAN bool
		// wantUplinks is the WAN interface count red mode enumerates: wan,
		// plus opt1 when the case makes it an uplink. A group entry is
		// never counted.
		wantUplinks int
	}{
		{
			name:    "rule on a group whose second member is wan",
			config:  uplinkCase{members: "lan,wan", rules: guiRuleOn("UPLINKS")},
			wantWAN: true,
		},
		{
			name:    "rule on a group in the space-separated form older releases wrote",
			config:  uplinkCase{members: "lan wan", rules: guiRuleOn("UPLINKS")},
			wantWAN: true,
		},
		{
			name:    "rule on a group whose members are both inside",
			config:  uplinkCase{members: "lan,opt2", rules: guiRuleOn("UPLINKS")},
			wantWAN: false,
		},
		{
			name: "rule on a group whose second member is a second uplink",
			config: uplinkCase{
				members:  "lan,opt1",
				opt1:     staticOpt1 + `<gateway>ISP2_GW</gateway>`,
				gateways: gatewayItem("ISP2_GW", "opt1", "0"),
				rules:    guiRuleOn("UPLINKS"),
			},
			wantWAN:     true,
			wantUplinks: 2,
		},
		{
			name: "rule on a second uplink that selects its gateway",
			config: uplinkCase{
				opt1:     staticOpt1 + `<gateway>ISP2_GW</gateway>`,
				gateways: gatewayItem("ISP2_GW", "opt1", "0"),
				rules:    guiRuleOn("opt1"),
			},
			wantWAN:     true,
			wantUplinks: 2,
		},
		{
			name: "rule on a second uplink that carries the default gateway",
			config: uplinkCase{
				gateways: gatewayItem("ISP2_GW", "opt1", "1"),
				rules:    guiRuleOn("opt1"),
			},
			wantWAN:     true,
			wantUplinks: 2,
		},
		{
			name:        "rule on a second uplink on PPPoE",
			config:      uplinkCase{opt1: `<ipaddr>pppoe</ipaddr>`, rules: guiRuleOn("opt1")},
			wantWAN:     true,
			wantUplinks: 2,
		},
		{
			name:        "rule on a second uplink on DHCPv6",
			config:      uplinkCase{opt1: staticOpt1 + `<ipaddrv6>dhcp6</ipaddrv6>`, rules: guiRuleOn("opt1")},
			wantWAN:     true,
			wantUplinks: 2,
		},
		{
			name: "rule on an inside interface holding a gateway that is not the default",
			config: uplinkCase{
				gateways: gatewayItem("CORE_GW", "opt1", "0"),
				rules:    guiRuleOn("opt1"),
			},
			wantWAN: false,
		},
		{
			name:    "rule on an inside interface whose gateway selection is disabled",
			config:  uplinkCase{opt1: staticOpt1 + `<gateway>none</gateway>`, rules: guiRuleOn("opt1")},
			wantWAN: false,
		},
		{
			name:    "rule on an inside interface that tracks the uplink's prefix",
			config:  uplinkCase{opt1: staticOpt1 + `<ipaddrv6>track6</ipaddrv6>`, rules: guiRuleOn("opt1")},
			wantWAN: false,
		},
		{
			name: "rule on an inside interface left selecting a gateway that is on wan",
			config: uplinkCase{
				opt1:     staticOpt1 + `<gateway>WAN_GW</gateway>`,
				gateways: gatewayItem("WAN_GW", "wan", "0"),
				rules:    guiRuleOn("opt1"),
			},
			wantWAN: false,
		},
		{
			name:        "rule on an interface selecting a gateway the config does not define",
			config:      uplinkCase{opt1: staticOpt1 + `<gateway>GONE_GW</gateway>`, rules: guiRuleOn("opt1")},
			wantWAN:     true,
			wantUplinks: 2,
		},
		{
			name:    "rule on a wan-prefixed group whose members are both inside",
			config:  uplinkCase{group: "WAN_ALL", members: "lan,opt2", rules: guiRuleOn("WAN_ALL")},
			wantWAN: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			wantUplinks := 1
			if tt.wantUplinks != 0 {
				wantUplinks = tt.wantUplinks
			}

			assertUplinkVerdicts(t, tt.config.config(), tt.wantWAN, wantUplinks)
		})
	}
}

// assertUplinkVerdicts checks every consumer that reads a rule's or an
// interface's WAN reachability on config: red mode's web GUI exposure, its
// Overly Permissive WAN Rule weakness and its WAN interface count, blue mode's
// Overly Permissive WAN Rule finding, and FIREWALL-023.
func assertUplinkVerdicts(t *testing.T, config string, wantWAN bool, wantUplinks int) {
	t.Helper()

	report := newRedReport(parseConfig(t, config))
	runRedAnalysis(report)

	_, exposed := findingByTitlePrefix(report.Findings, "WAN-Exposed Service: Web Administration")
	if exposed != wantWAN {
		t.Errorf("web GUI WAN-exposed = %v, want %v; findings: %+v", exposed, wantWAN, report.Findings)
	}

	_, weakness := findingByTitlePrefix(report.Findings, "Exposed Weakness: Overly Permissive WAN Rule")
	if weakness != wantWAN {
		t.Errorf("red Overly Permissive WAN Rule = %v, want %v; findings: %+v", weakness, wantWAN, report.Findings)
	}

	data, ok := report.Metadata["enumeration_data"].(enumerationData)
	if !ok {
		t.Fatalf("enumeration_data = %T, want enumerationData", report.Metadata["enumeration_data"])
	}

	if data.WANInterfaces != wantUplinks {
		t.Errorf("enumeration_data.WANInterfaces = %d, want %d", data.WANInterfaces, wantUplinks)
	}

	blue := slices.ContainsFunc(
		analysis.DetectSecurityIssues(parseConfig(t, config)),
		func(f common.SecurityFinding) bool {
			return f.Issue == "Overly Permissive WAN Rule"
		},
	)
	if blue != wantWAN {
		t.Errorf("blue Overly Permissive WAN Rule = %v, want %v", blue, wantWAN)
	}

	failed := failedControls(t, config)
	if got := slices.Contains(failed, "FIREWALL-023"); got != wantWAN {
		t.Errorf("FIREWALL-023 failed = %v, want %v; failed controls: %v", got, wantWAN, failed)
	}
}

// TestWANReachability_SecondUplinkFiltering covers the interface-level
// controls. A second uplink without Block private networks and Block bogon
// networks fails them, as wan would; an inside interface without them does not.
func TestWANReachability_SecondUplinkFiltering(t *testing.T) {
	t.Parallel()

	controls := []string{"FIREWALL-029", "FIREWALL-030", "SANS-FW-012"}

	tests := []struct {
		name     string
		config   uplinkCase
		wantFail bool
	}{
		{
			name: "second uplink selecting a gateway that is not the default",
			config: uplinkCase{
				opt1:     staticOpt1 + `<gateway>ISP2_GW</gateway>`,
				gateways: gatewayItem("ISP2_GW", "opt1", "0"),
			},
			wantFail: true,
		},
		{
			name:     "second uplink carrying the default gateway without selecting it",
			config:   uplinkCase{gateways: gatewayItem("ISP2_GW", "opt1", "1")},
			wantFail: true,
		},
		{
			name:     "inside interface with static addressing",
			config:   uplinkCase{},
			wantFail: false,
		},
		{
			name: "inside interface left selecting a gateway that is on wan",
			config: uplinkCase{
				opt1:     staticOpt1 + `<gateway>WAN_GW</gateway>`,
				gateways: gatewayItem("WAN_GW", "wan", "0"),
			},
			wantFail: false,
		},
		{
			name:     "wan-prefixed group whose members are both inside",
			config:   uplinkCase{group: "WANS", members: "lan,opt2"},
			wantFail: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			failed := failedControls(t, tt.config.config())
			for _, control := range controls {
				if got := slices.Contains(failed, control); got != tt.wantFail {
					t.Errorf("%s failed = %v, want %v; failed controls: %v", control, got, tt.wantFail, failed)
				}
			}
		})
	}
}

// TestWANReachability_PortForwardOnGroup covers red mode's port forward
// finding. The DNat model, and the legacy port forward page, accept an
// interface group, and pf applies the forward on every member.
func TestWANReachability_PortForwardOnGroup(t *testing.T) {
	t.Parallel()

	const forward = `<rule>
      <protocol>tcp</protocol>
      <interface>UPLINKS</interface>
      <ipprotocol>inet</ipprotocol>
      <source><any>1</any></source>
      <destination><any>1</any><port>8443</port></destination>
      <target>192.168.1.50</target>
      <local-port>443</local-port>
      <descr>web server</descr>
    </rule>`

	// The pass rule the forward needs sits on the group too, as the port
	// forward page writes it for a forward on the group.
	const allowRule = `<rule>
      <type>pass</type>
      <interface>UPLINKS</interface>
      <ipprotocol>inet</ipprotocol>
      <protocol>tcp</protocol>
      <source><any>1</any></source>
      <destination><address>192.168.1.50</address><port>443</port></destination>
      <descr>web server forward</descr>
    </rule>`

	for _, tt := range []struct {
		members string
		want    int
	}{
		{members: "lan,wan", want: 1},
		{members: "lan,opt2", want: 0},
	} {
		t.Run(tt.members, func(t *testing.T) {
			t.Parallel()

			report := newRedReport(
				parseConfig(t, uplinkCase{members: tt.members, rules: allowRule, nat: forward}.config()),
			)
			runRedAnalysis(report)

			if got := report.Metadata["weak_nat_rules_count"]; got != tt.want {
				t.Errorf("weak_nat_rules_count = %v, want %d; findings: %+v", got, tt.want, report.Findings)
			}
		})
	}
}
