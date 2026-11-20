package audit

import (
	"regexp"
	"strings"
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/analysis"
	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
)

// assignedInterface matches one assigned interface entry in <interfaces>. Their
// children are never named lan, wan or optN, so the lazy match ends at the
// entry's own closing tag.
var assignedInterface = regexp.MustCompile(`(?s)<(lan|wan|opt\d+)>.*?</(lan|wan|opt\d+)>`)

// interfaceEnable and interfaceDevice match the enable flag and the device of
// an interface entry, in the spelling each vendor fixture uses.
var (
	interfaceEnable = regexp.MustCompile(`<enable>[^<]*</enable>`)
	interfaceDevice = regexp.MustCompile(`<if>[^<]*</if>`)
)

// virtualInterfaces are the loopback and OpenVPN group entries OPNsense
// registers with <virtual>, both enabled.
const virtualInterfaces = "<lo0><enable>1</enable><if>lo0</if><virtual>1</virtual></lo0>" +
	"<openvpn><enable>1</enable><if>openvpn</if><type>group</type><virtual>1</virtual></openvpn>"

// rewriteInterfaces applies edit to every assigned interface entry in the
// first <interfaces> block after </system>, which is the assignment table in
// both vendor fixtures. edit receives the key, the entry and the fixture's wan
// entry, and returns the entry's replacement.
func rewriteInterfaces(t *testing.T, raw string, edit func(key, entry, wan string) string) string {
	t.Helper()

	start := strings.Index(raw, "</system>")
	open := strings.Index(raw[start:], "<interfaces>")
	closing := strings.Index(raw[start:], "</interfaces>")

	if start < 0 || open < 0 || closing < open {
		t.Fatal("fixture has no <interfaces> block after </system>")
	}

	open += start
	closing += start
	block := raw[open:closing]

	var wan string

	for _, entry := range assignedInterface.FindAllString(block, -1) {
		if strings.HasPrefix(entry, "<wan>") {
			wan = entry
		}
	}

	if !interfaceEnable.MatchString(wan) || !interfaceDevice.MatchString(wan) {
		t.Fatalf("fixture wan entry has no enable flag or device: %s", wan)
	}

	block = assignedInterface.ReplaceAllStringFunc(block, func(entry string) string {
		return edit(assignedInterface.FindStringSubmatch(entry)[1], entry, wan)
	})

	return raw[:open] + block + raw[closing:]
}

// renamed returns entry under key, optionally without its enable flag.
func renamed(entry, from, key string, enabled bool) string {
	entry = strings.ReplaceAll(entry, from+">", key+">")
	if !enabled {
		entry = interfaceEnable.ReplaceAllString(entry, "")
	}

	return entry
}

// antiLockoutShape is one interface layout with the reachability each vendor
// gives the web GUI and SSH under it.
type antiLockoutShape struct {
	name       string
	interfaces func(key, entry, wan string) string
	lockout    string
	opnWAN     bool
	pfWAN      bool
}

// antiLockoutShapes lists the layouts that decide where the rule goes. The
// fixtures' lan entry is reused as opt1 or opt2 where a shape needs one with a
// device. The comments marked "Releases differ" are where OPNsense up to
// 22.7.4 and later releases put the rule on different interfaces.
func antiLockoutShapes() []antiLockoutShape {
	keep := func(key, entry, _ string) string {
		if key == ifaceKeyWAN {
			return entry
		}

		return ""
	}

	return []antiLockoutShape{
		{name: "lan and wan", interfaces: func(_, entry, _ string) string { return entry }},
		{name: "wan only", interfaces: keep, opnWAN: true, pfWAN: true},
		{name: "wan only, page value", interfaces: keep, lockout: "<noantilockout>1</noantilockout>"},
		{name: "wan only, empty element", interfaces: keep, lockout: "<noantilockout/>"},
		{
			name: "wan only, wan disabled",
			interfaces: func(key, entry, _ string) string {
				return renamed(keep(key, entry, ""), ifaceKeyWAN, ifaceKeyWAN, false)
			},
		},
		{
			name: "wan only, wan without a device",
			interfaces: func(key, entry, _ string) string {
				return interfaceDevice.ReplaceAllString(keep(key, entry, ""), "")
			},
		},
		{
			name: "wan and opt1",
			interfaces: func(key, entry, _ string) string {
				if key == ifaceKeyLAN {
					return renamed(entry, ifaceKeyLAN, ifaceKeyOpt1, true)
				}

				return keep(key, entry, "")
			},
		},
		{
			name: "wan and opt2",
			interfaces: func(key, entry, _ string) string {
				if key == ifaceKeyLAN {
					return renamed(entry, ifaceKeyLAN, "opt2", true)
				}

				return keep(key, entry, "")
			},
		},
		{
			// A disabled opt1 still has a device, so 22.7.4 put the rule there,
			// and later releases take it by its key.
			name: "wan and a disabled opt1",
			interfaces: func(key, entry, _ string) string {
				if key == ifaceKeyLAN {
					return renamed(entry, ifaceKeyLAN, ifaceKeyOpt1, false)
				}

				return keep(key, entry, "")
			},
		},
		{
			// Releases differ: 22.7.4 found no lan or opt1 with a device and wan the only
			// enabled interface; later releases put the rule on the lan key.
			name: "wan and a lan without a device",
			interfaces: func(key, entry, _ string) string {
				if key == ifaceKeyLAN {
					return "<lan><descr>LAN</descr></lan>"
				}

				return keep(key, entry, "")
			},
			opnWAN: true,
		},
		{
			// The enabled opt2 makes wan one of two enabled interfaces, so even
			// 22.7.4 puts the rule nowhere near the WAN.
			name: "wan, a lan without a device and an enabled opt2",
			interfaces: func(key, entry, wan string) string {
				switch key {
				case ifaceKeyLAN:
					return "<lan><descr>LAN</descr></lan>" + renamed(entry, ifaceKeyLAN, "opt2", true)
				default:
					return keep(key, entry, wan)
				}
			},
		},
		{
			// Releases differ: the loopback and OpenVPN entries are enabled but virtual,
			// so 22.7.4 still counted wan as the only enabled interface.
			name: "wan, a disabled opt2 and virtual entries",
			interfaces: func(key, entry, _ string) string {
				if key == ifaceKeyLAN {
					return renamed(entry, ifaceKeyLAN, "opt2", false) + virtualInterfaces
				}

				return keep(key, entry, "")
			},
			opnWAN: true,
		},
	}
}

// TestRedMode_AntiLockoutOnWAN_EndToEnd rewrites each vendor's fixture into the
// interface shapes that decide where the anti-lockout rule goes and drives the
// result through parse, convert and red mode. Both vendors put the rule on the
// WAN of a firewall with no LAN or OPT interface, and red mode must then report the web GUI, and
// on OPNsense SSH, as WAN-exposed although no rule in the config passes them.
// The fixtures hold no WAN pass rule to the firewall, so every other shape stays
// LAN-only. SSH is enabled only on OPNsense, in the form its page writes: the
// pfSense schema reads an element pfSense does not write for it.
func TestRedMode_AntiLockoutOnWAN_EndToEnd(t *testing.T) {
	t.Parallel()

	const gui = "<protocol>https</protocol>"

	vendors := []struct {
		name, fixture, ssh, withSSH string
		pfSense                     bool
	}{
		{
			name: "opnsense", fixture: "config.xml.sample", ssh: "<ssh>\n      <group>admins</group>",
			withSSH: "<ssh><enabled>enabled</enabled><group>admins</group>",
		},
		{name: "pfsense", fixture: "pfsense/config-pfSense.xml", pfSense: true},
	}

	for _, vendor := range vendors {
		raw := readFixture(t, vendor.fixture)
		requireFixtureHolds(t, raw, map[string]int{gui: 1, "<noantilockout": 0})

		portals := []string{"webgui"}
		if vendor.ssh != "" {
			requireFixtureHolds(t, raw, map[string]int{vendor.ssh: 1})
			raw = strings.Replace(raw, vendor.ssh, vendor.withSSH, 1)
			portals = append(portals, "ssh")
		}

		for _, shape := range antiLockoutShapes() {
			t.Run(vendor.name+"/"+shape.name, func(t *testing.T) {
				t.Parallel()

				config := rewriteInterfaces(t, raw, shape.interfaces)
				config = strings.Replace(config, gui, gui+shape.lockout, 1)

				report := newRedReport(parseConfig(t, config))
				runRedAnalysis(report)

				onWAN := shape.opnWAN
				if vendor.pfSense {
					onWAN = shape.pfWAN
				}

				want := analysis.LANOnly
				if onWAN {
					want = analysis.WANReachable
				}

				checkAntiLockoutPortals(t, report, portals, want)
			})
		}
	}
}

// TestAntiLockout_LeavesSNMPAlone checks that the anti-lockout rule exposes
// only the web GUI and SSH. The vendor rule passes their ports and no other, so
// an SNMP agent on a WAN-only firewall stays LAN-only.
func TestAntiLockout_LeavesSNMPAlone(t *testing.T) {
	t.Parallel()

	device := &common.CommonDevice{
		System:     common.System{WebGUI: common.WebGUI{Protocol: "https"}, SSH: common.SSH{Enabled: true}},
		Interfaces: []common.Interface{{Name: ifaceKeyWAN, PhysicalIf: "vtnet0", Enabled: true}},
		SNMP:       common.SNMPConfig{ROCommunity: "monitoring"},
	}

	want := map[string]analysis.Reachability{
		"webgui": analysis.WANReachable,
		"ssh":    analysis.WANReachable,
		"snmp":   analysis.LANOnly,
	}

	services := serviceExposures(device)
	if len(services) != len(want) {
		t.Fatalf("services = %+v, want web GUI, SSH and SNMP", services)
	}

	for _, svc := range services {
		if svc.reachability != want[svc.name] {
			t.Errorf("%s reachability = %q, want %q", svc.name, svc.reachability, want[svc.name])
		}
	}
}

// checkAntiLockoutPortals checks the reachability of each named portal in the
// admin-portal inventory, and that each WAN-reachable one has its finding.
func checkAntiLockoutPortals(t *testing.T, report *Report, names []string, want analysis.Reachability) {
	t.Helper()

	portals, ok := report.Metadata["admin_portals"].([]adminPortal)
	if !ok {
		t.Fatalf("admin_portals has type %T", report.Metadata["admin_portals"])
	}

	titles := map[string]string{
		"webgui": "WAN-Exposed Service: Web Administration Interface",
		"ssh":    "WAN-Exposed Service: SSH Remote Administration",
	}

	for _, name := range names {
		idx := -1

		for i, portal := range portals {
			if portal.Name == name {
				idx = i
			}
		}

		if idx < 0 {
			t.Fatalf("no %s portal in %+v", name, portals)
		}

		if portals[idx].Reachability != want {
			t.Errorf("%s reachability = %q, want %q", name, portals[idx].Reachability, want)
		}

		if _, found := findingByTitlePrefix(report.Findings, titles[name]); found != (want == analysis.WANReachable) {
			t.Errorf("%s finding present = %v, want reachability %q", name, found, want)
		}
	}
}
