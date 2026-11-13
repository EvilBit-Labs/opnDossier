package audit

import (
	"slices"
	"strings"
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/analysis"
	"github.com/EvilBit-Labs/opnDossier/internal/compliance"
	"github.com/EvilBit-Labs/opnDossier/internal/plugins/firewall"
	"github.com/EvilBit-Labs/opnDossier/internal/plugins/sans"
	"github.com/EvilBit-Labs/opnDossier/internal/plugins/stig"
	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
)

// packetFilterAnchor is the first child of <system> in both vendor fixtures;
// the element under test is written right after it.
const packetFilterAnchor = "<optimization>normal</optimization>"

// packetFilterControlsByPlugin lists, per plugin, the controls that must fail
// when packet filtering is disabled. They are spelled out here rather than read
// from the plugins so that dropping one from a plugin fails this test.
var packetFilterControlsByPlugin = map[string][]string{
	"firewall": {
		"FIREWALL-022", "FIREWALL-023", "FIREWALL-024", "FIREWALL-027",
		"FIREWALL-028", "FIREWALL-029", "FIREWALL-030", "FIREWALL-041",
	},
	"sans": {
		"SANS-FW-001", "SANS-FW-002", "SANS-FW-003", "SANS-FW-007", "SANS-FW-012",
		"SANS-FW-014", "SANS-FW-016", "SANS-FW-017", "SANS-FW-018", "SANS-FW-019",
		"SANS-FW-020", "SANS-FW-021", "SANS-FW-022", "SANS-FW-024",
	},
	"stig": {"V-206694", "V-206674", "V-206701", "V-206682"},
}

// TestPacketFilterDisabled_EndToEnd writes <system><disablefilter> into each
// vendor's fixture and drives it through parse, convert, the compliance plugins
// and red mode. Both vendors test the element with isset() and turn pf off, so
// the page's "enabled" and an empty element must both read as disabled, and only
// an absent element as filtering. The fixtures enable SSH so that the red-mode
// rows cover a second service.
func TestPacketFilterDisabled_EndToEnd(t *testing.T) {
	t.Parallel()

	const (
		opnSSH = "<ssh>\n      <group>admins</group>"
		pfSSH  = "<webgui>"
	)

	vendors := []struct {
		name    string
		fixture string
		ssh     string
		withSSH string
	}{
		{"opnsense", "config.xml.sample", opnSSH, "<ssh><enabled>enabled</enabled><group>admins</group>"},
		{"pfsense", "pfsense/config-pfSense.xml", pfSSH, "<ssh><enabled/></ssh><webgui>"},
	}

	shapes := []struct {
		name     string
		element  string
		disabled bool
	}{
		{"absent", "", false},
		{"empty element", "<disablefilter/>", true},
		{"page value", "<disablefilter>enabled</disablefilter>", true},
	}

	for _, vendor := range vendors {
		raw := readFixture(t, vendor.fixture)
		requireFixtureHolds(t, raw, map[string]int{packetFilterAnchor: 1, vendor.ssh: 1, "<disablefilter": 0})

		raw = strings.Replace(raw, vendor.ssh, vendor.withSSH, 1)

		for _, shape := range shapes {
			t.Run(vendor.name+"/"+shape.name, func(t *testing.T) {
				t.Parallel()

				device := parseConfig(t, strings.Replace(raw, packetFilterAnchor, packetFilterAnchor+shape.element, 1))

				if device.System.PacketFilterDisabled != shape.disabled {
					t.Fatalf("PacketFilterDisabled = %v, want %v", device.System.PacketFilterDisabled, shape.disabled)
				}

				checkPacketFilterControls(t, device, shape.disabled)
				checkPacketFilterRedMode(t, newRedReport(device), shape.disabled)
			})
		}
	}
}

// checkPacketFilterControls runs each plugin and checks that its packet filter
// controls all fail when filtering is disabled, and that no packet-filter
// finding appears when it is on.
func checkPacketFilterControls(t *testing.T, device *common.CommonDevice, disabled bool) {
	t.Helper()

	plugins := map[string]compliance.Plugin{
		"firewall": firewall.NewPlugin(),
		"sans":     sans.NewPlugin(),
		"stig":     stig.NewPlugin(),
	}

	for name, plugin := range plugins {
		findings, evaluated, err := plugin.RunChecks(device)
		if err != nil {
			t.Fatal(err)
		}

		for _, control := range packetFilterControlsByPlugin[name] {
			if disabled && !slices.Contains(evaluated, control) {
				t.Errorf("%s: %s is not evaluated with packet filtering disabled", name, control)
			}

			fired := slices.ContainsFunc(findings, func(f compliance.Finding) bool {
				return slices.Contains(f.References, control)
			})
			if disabled && !fired {
				t.Errorf("%s: %s passes with packet filtering disabled", name, control)
			}
		}

		// A control that fails its own check keeps that finding, so with
		// filtering disabled a plugin may add none; with it on, it must add none.
		if !disabled && slices.ContainsFunc(findings, func(f compliance.Finding) bool {
			return f.Component == compliance.PacketFilterComponent
		}) {
			t.Errorf("%s: packet-filter finding with packet filtering on", name)
		}
	}
}

// checkPacketFilterRedMode checks that red mode reports the management services
// and the setting itself as WAN-exposed exactly when filtering is disabled. The
// fixtures hold no WAN pass rule to the firewall, so with filtering on both
// services stay LAN-only.
func checkPacketFilterRedMode(t *testing.T, report *Report, disabled bool) {
	t.Helper()

	runRedAnalysis(report)

	want := analysis.LANOnly
	if disabled {
		want = analysis.WANReachable
	}

	portals, ok := report.Metadata["admin_portals"].([]adminPortal)
	if !ok {
		t.Fatalf("admin_portals has type %T", report.Metadata["admin_portals"])
	}

	names := make([]string, 0, len(portals))

	for _, portal := range portals {
		names = append(names, portal.Name)

		if (portal.Name == "webgui" || portal.Name == "ssh") && portal.Reachability != want {
			t.Errorf("%s reachability = %q, want %q", portal.Name, portal.Reachability, want)
		}
	}

	if !slices.Contains(names, "ssh") || !slices.Contains(names, "webgui") {
		t.Fatalf("admin portals %v, want webgui and ssh", names)
	}

	_, flagged := findingByTitlePrefix(report.Findings, "Exposed Weakness: Packet Filtering Disabled")
	if flagged != disabled {
		t.Errorf("packet filtering finding present = %v, want %v: %+v", flagged, disabled, report.Findings)
	}
}
