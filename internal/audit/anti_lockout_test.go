package audit

import (
	"regexp"
	"strings"
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/analysis"
)

// assignedInterface matches one assigned interface entry in <interfaces>. Their
// children are never named lan, wan or optN, so the lazy match ends at the
// entry's own closing tag.
var assignedInterface = regexp.MustCompile(`(?s)<(lan|wan|opt\d+)>.*?</(lan|wan|opt\d+)>`)

// rewriteInterfaces applies edit to every assigned interface entry in the
// first <interfaces> block after </system>, which is the assignment table in
// both vendor fixtures. edit receives the key and the entry and returns its
// replacement.
func rewriteInterfaces(t *testing.T, raw string, edit func(key, entry string) string) string {
	t.Helper()

	start := strings.Index(raw, "</system>")
	open := strings.Index(raw[start:], "<interfaces>")
	closing := strings.Index(raw[start:], "</interfaces>")

	if start < 0 || open < 0 || closing < open {
		t.Fatal("fixture has no <interfaces> block after </system>")
	}

	open += start
	closing += start

	block := assignedInterface.ReplaceAllStringFunc(raw[open:closing], func(entry string) string {
		return edit(assignedInterface.FindStringSubmatch(entry)[1], entry)
	})

	return raw[:open] + block + raw[closing:]
}

// TestRedMode_AntiLockoutOnWAN_EndToEnd rewrites each vendor's fixture into the
// interface shapes that decide where the anti-lockout rule goes, enables SSH,
// and drives the result through parse, convert and red mode. Both vendors put
// the rule on the WAN of a firewall with no LAN, and red mode must then report
// the web GUI and SSH as WAN-exposed although no rule in the config passes
// them. The fixtures hold no WAN pass rule to the firewall, so every other row
// stays LAN-only.
func TestRedMode_AntiLockoutOnWAN_EndToEnd(t *testing.T) {
	t.Parallel()

	const gui = "<protocol>https</protocol>"

	wanOnly := func(key, entry string) string {
		if key == ifaceKeyWAN {
			return entry
		}

		return ""
	}

	// lanWithoutDevice keeps wan and a disabled lan with no device, the one
	// shape where OPNsense up to 22.7 put the rule on the WAN and later
	// releases and pfSense put it on the LAN or nowhere.
	lanWithoutDevice := func(key, entry string) string {
		switch key {
		case ifaceKeyWAN:
			return entry
		case ifaceKeyLAN:
			return "<lan><descr>LAN</descr></lan>"
		default:
			return ""
		}
	}

	renameLAN := func(key, entry string) string {
		if key == ifaceKeyLAN {
			return strings.ReplaceAll(entry, "lan>", "opt1>")
		}

		return wanOnly(key, entry)
	}

	unchanged := func(_, entry string) string { return entry }

	vendors := []struct {
		name, fixture, ssh, withSSH string
		legacyOnWAN                 bool
	}{
		{
			"opnsense", "config.xml.sample", "<ssh>\n      <group>admins</group>",
			"<ssh><enabled>enabled</enabled><group>admins</group>", true,
		},
		{"pfsense", "pfsense/config-pfSense.xml", "<webgui>", "<ssh><enabled/></ssh><webgui>", false},
	}

	shapes := []struct {
		name       string
		interfaces func(key, entry string) string
		lockout    string
		onWAN      func(legacyOnWAN bool) bool
	}{
		{"lan and wan", unchanged, "", func(bool) bool { return false }},
		{"wan only", wanOnly, "", func(bool) bool { return true }},
		{"wan only, page value", wanOnly, "<noantilockout>1</noantilockout>", func(bool) bool { return false }},
		{"wan only, empty element", wanOnly, "<noantilockout/>", func(bool) bool { return false }},
		{"wan and opt1", renameLAN, "", func(bool) bool { return false }},
		{"wan and lan without a device", lanWithoutDevice, "", func(legacy bool) bool { return legacy }},
	}

	for _, vendor := range vendors {
		raw := readFixture(t, vendor.fixture)
		requireFixtureHolds(t, raw, map[string]int{gui: 1, vendor.ssh: 1, "<noantilockout": 0})

		raw = strings.Replace(raw, vendor.ssh, vendor.withSSH, 1)

		for _, shape := range shapes {
			t.Run(vendor.name+"/"+shape.name, func(t *testing.T) {
				t.Parallel()

				config := rewriteInterfaces(t, raw, shape.interfaces)
				config = strings.Replace(config, gui, gui+shape.lockout, 1)

				report := newRedReport(parseConfig(t, config))
				runRedAnalysis(report)

				want := analysis.LANOnly
				if shape.onWAN(vendor.legacyOnWAN) {
					want = analysis.WANReachable
				}

				checkAntiLockoutPortals(t, report, want)
			})
		}
	}
}

// checkAntiLockoutPortals checks the web GUI and SSH reachability in the
// admin-portal inventory, and that each WAN-reachable one has its finding.
func checkAntiLockoutPortals(t *testing.T, report *Report, want analysis.Reachability) {
	t.Helper()

	portals, ok := report.Metadata["admin_portals"].([]adminPortal)
	if !ok {
		t.Fatalf("admin_portals has type %T", report.Metadata["admin_portals"])
	}

	titles := map[string]string{
		"webgui": "WAN-Exposed Service: Web Administration Interface",
		"ssh":    "WAN-Exposed Service: SSH Remote Administration",
	}

	for name, title := range titles {
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

		if _, found := findingByTitlePrefix(report.Findings, title); found != (want == analysis.WANReachable) {
			t.Errorf("%s finding present = %v, want reachability %q", name, found, want)
		}
	}
}
