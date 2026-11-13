package audit

import (
	"slices"
	"strings"
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/plugins/firewall"
	"github.com/EvilBit-Labs/opnDossier/internal/plugins/sans"
)

// uplinkConfig is an OPNsense 26.7 config with the two shapes a WAN can take
// besides the "wan" key: an interface group (Firewall: Groups writes the group
// under <ifgroups>, comma-separated, and registers it under <interfaces> with
// type group) and a second uplink, which always keeps an optN key. wan is
// blocked and filtered, so any WAN finding below comes from the other shapes.
// {OPT1}, {GATEWAYS}, {MEMBERS}, {RULES} and {NAT} are filled per case.
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
    <UPLINKS>
      <internal_dynamic>1</internal_dynamic>
      <descr>Uplinks</descr>
      <if>UPLINKS</if>
      <virtual>1</virtual>
      <enable>1</enable>
      <type>group</type>
    </UPLINKS>
  </interfaces>
  <ifgroups version="1.0.0">
    <ifgroupentry uuid="d4d4d4d4-0000-4000-8000-000000000001">
      <ifname>UPLINKS</ifname>
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

// uplinkCase fills uplinkConfig. Empty fields take a LAN-only default.
type uplinkCase struct {
	opt1     string
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

	return strings.NewReplacer(
		"{OPT1}", opt1,
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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			config := tt.config.config()

			report := newRedReport(parseConfig(t, config))
			runRedAnalysis(report)

			_, exposed := findingByTitlePrefix(report.Findings, "WAN-Exposed Service: Web Administration")
			if exposed != tt.wantWAN {
				t.Errorf("web GUI WAN-exposed = %v, want %v; findings: %+v", exposed, tt.wantWAN, report.Findings)
			}

			failed := failedControls(t, config)
			if got := slices.Contains(failed, "FIREWALL-023"); got != tt.wantWAN {
				t.Errorf("FIREWALL-023 failed = %v, want %v; failed controls: %v", got, tt.wantWAN, failed)
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
