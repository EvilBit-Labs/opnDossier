package audit

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/analysis"
	"github.com/EvilBit-Labs/opnDossier/internal/cfgparser"
	"github.com/EvilBit-Labs/opnDossier/internal/constants"
	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
	"github.com/EvilBit-Labs/opnDossier/pkg/parser"
	_ "github.com/EvilBit-Labs/opnDossier/pkg/parser/opnsense" // self-registers OPNsense parser via init()
	_ "github.com/EvilBit-Labs/opnDossier/pkg/parser/pfsense"  // self-registers pfSense parser via init()
)

// TestReport_RedAnalysisMethods exercises the five red-mode analysis methods
// against a fixture with WebGUI=http, an enabled WAN interface, and a single
// LAN-scoped pass rule. No WAN rule permits any management port, so nothing is
// WAN-exposed — the counts are all zero and the WebGUI portal is retained as
// LAN-only in the inventory.
func TestReport_RedAnalysisMethods(t *testing.T) {
	t.Parallel()

	newReport := func() *Report {
		return newRedReport(&common.CommonDevice{
			System: common.System{
				Hostname: "test-host",
				WebGUI:   common.WebGUI{Protocol: "http"},
			},
			Interfaces: []common.Interface{
				{Name: "wan", Enabled: true},
				{Name: "lan", Enabled: true},
			},
			FirewallRules: []common.FirewallRule{
				{Type: common.RuleTypePass, Interfaces: []string{"lan"}},
			},
			Users: []common.User{{Name: "admin"}},
		})
	}

	t.Run("addWANExposedServices", func(t *testing.T) {
		t.Parallel()
		report := newReport()
		report.addWANExposedServices(serviceExposures(report.Configuration), false)

		if got := report.Metadata["wan_exposed_services_count"]; got != 0 {
			t.Errorf("wan_exposed_services_count = %v, want 0 (no WAN rule permits a service port)", got)
		}
		if report.Metadata["wan_exposure_scan_completed"] != true {
			t.Error("wan_exposure_scan_completed should be true")
		}
	})

	t.Run("addWeakNATRules", func(t *testing.T) {
		t.Parallel()
		report := newReport()
		report.addWeakNATRules(false)

		if got := report.Metadata["weak_nat_rules_count"]; got != 0 {
			t.Errorf("weak_nat_rules_count = %v, want 0 (no inbound NAT rules)", got)
		}
	})

	t.Run("addAdminPortals", func(t *testing.T) {
		t.Parallel()
		report := newReport()
		report.addAdminPortals(serviceExposures(report.Configuration))

		portals, ok := report.Metadata["admin_portals"].([]adminPortal)
		if !ok {
			t.Fatalf("admin_portals = %v (%T), want []adminPortal",
				report.Metadata["admin_portals"], report.Metadata["admin_portals"])
		}
		// WebGUI is always present (SSH is not enabled in this fixture), LAN-only.
		if len(portals) != 1 {
			t.Fatalf("admin_portals len = %d, want 1 (webgui)", len(portals))
		}
		if portals[0].Name != "webgui" || portals[0].Reachability != analysis.LANOnly {
			t.Errorf("admin_portals[0] = %+v, want webgui tagged lan", portals[0])
		}
	})

	t.Run("addAttackSurfaces", func(t *testing.T) {
		t.Parallel()
		report := newReport()
		observations := analysis.ScanObservations(report.Configuration)
		report.addAttackSurfaces(observations, false)

		// The insecure-WebGUI observation is system-wide (Local), not WAN, so no
		// observation is reframed as a red exposure for this fixture.
		if got := report.Metadata["attack_surfaces_count"]; got != 0 {
			t.Errorf("attack_surfaces_count = %v, want 0 (no WAN-reachable observation)", got)
		}
	})

	t.Run("addEnumerationData", func(t *testing.T) {
		t.Parallel()
		report := newReport()
		report.addEnumerationData()

		data, ok := report.Metadata["enumeration_data"].(enumerationData)
		if !ok {
			t.Fatalf("enumeration_data = %v (%T), want enumerationData",
				report.Metadata["enumeration_data"], report.Metadata["enumeration_data"])
		}
		want := enumerationData{
			Interfaces:      2,
			WANInterfaces:   1,
			FirewallRules:   1,
			InboundNATRules: 0,
			Users:           1,
			Groups:          0,
		}
		if data != want {
			t.Errorf("enumeration_data = %+v, want %+v", data, want)
		}
	})
}

// newRedReport builds a red-mode Report over the given device for red-analysis
// tests.
func newRedReport(device *common.CommonDevice) *Report {
	return &Report{
		Mode:          ModeRed,
		Configuration: device,
		Findings:      make([]Finding, 0),
		Compliance:    make(map[string]ComplianceResult),
		Metadata:      make(map[string]any),
	}
}

// runRedAnalysis runs the full red-mode analysis pipeline over the report, in
// the same order as generateRedReport.
func runRedAnalysis(report *Report) {
	observations := analysis.ScanObservations(report.Configuration)
	services := serviceExposures(report.Configuration)
	report.addWANExposedServices(services, false)
	report.addWeakNATRules(false)
	report.addAdminPortals(services)
	report.addAttackSurfaces(observations, false)
	report.addEnumerationData()
}

// findingByTitlePrefix returns the first Finding whose Title starts with prefix.
func findingByTitlePrefix(findings []Finding, prefix string) (Finding, bool) {
	for _, f := range findings {
		if strings.HasPrefix(f.Title, prefix) {
			return f, true
		}
	}

	return Finding{}, false
}

// TestRedMode_SSHExposedViaWANPassRule covers AE2 and R19: a config allowing
// SSH from a WAN source produces a non-zero exposed-service Finding for SSH,
// tagged WAN-reachable with AttackSurface detail — the false negative the plan
// was written to eliminate.
func TestRedMode_SSHExposedViaWANPassRule(t *testing.T) {
	t.Parallel()

	device := &common.CommonDevice{
		System: common.System{
			SSH: common.SSH{Enabled: true, Port: "22"},
		},
		Interfaces: []common.Interface{
			{Name: "wan", Enabled: true},
			{Name: "lan", Enabled: true},
		},
		FirewallRules: []common.FirewallRule{
			{
				Type:        common.RuleTypePass,
				Interfaces:  []string{"wan"},
				Source:      common.RuleEndpoint{Address: constants.NetworkAny},
				Destination: common.RuleEndpoint{Port: "22"},
			},
		},
	}

	report := newRedReport(device)
	runRedAnalysis(report)

	if got := report.Metadata["wan_exposed_services_count"]; got == 0 {
		t.Fatal("wan_exposed_services_count = 0, want > 0 (SSH exposed via WAN pass rule) — R19 false negative")
	}

	ssh, ok := findingByTitlePrefix(report.Findings, "WAN-Exposed Service: SSH")
	if !ok {
		t.Fatalf("expected a WAN-Exposed SSH finding, got findings %+v", report.Findings)
	}
	if ssh.AttackSurface == nil {
		t.Fatal("SSH exposure finding must carry AttackSurface detail")
	}
	if !slices.Contains(ssh.AttackSurface.Ports, 22) {
		t.Errorf("SSH AttackSurface.Ports = %v, want to contain 22", ssh.AttackSurface.Ports)
	}
	if ssh.ExploitNotes == "" {
		t.Error("SSH exposure finding must carry an ExploitNote")
	}
}

// TestRedMode_LANOnlyAdminPortalNotInWANLead covers AE3 (both halves): a
// LAN-only admin portal is PRESENT in the admin-portal inventory tagged "lan"
// AND ABSENT from the WAN-exposed Findings. Asserting only the absence would
// let a "portal dropped entirely" regression pass.
func TestRedMode_LANOnlyAdminPortalNotInWANLead(t *testing.T) {
	t.Parallel()

	device := &common.CommonDevice{
		System: common.System{
			WebGUI: common.WebGUI{Protocol: constants.ProtocolHTTPS},
		},
		Interfaces: []common.Interface{
			{Name: "wan", Enabled: true},
			{Name: "lan", Enabled: true},
		},
		// Only a LAN pass rule — the WebGUI is reachable from LAN, never WAN.
		FirewallRules: []common.FirewallRule{
			{Type: common.RuleTypePass, Interfaces: []string{"lan"}},
		},
	}

	report := newRedReport(device)
	runRedAnalysis(report)

	// Half 1: present in the inventory, tagged lan.
	portals, ok := report.Metadata["admin_portals"].([]adminPortal)
	if !ok {
		t.Fatalf(
			"admin_portals = %v (%T), want []adminPortal",
			report.Metadata["admin_portals"],
			report.Metadata["admin_portals"],
		)
	}
	webgui, found := adminPortalByName(portals, "webgui")
	if !found {
		t.Fatalf("admin_portals must retain the LAN-only webgui portal, got %+v", portals)
	}
	if webgui.Reachability != analysis.LANOnly {
		t.Errorf("webgui portal reachability = %q, want %q", webgui.Reachability, analysis.LANOnly)
	}

	// Half 2: absent from the WAN-exposed Findings.
	if _, present := findingByTitlePrefix(report.Findings, "WAN-Exposed Service"); present {
		t.Errorf("a LAN-only portal must not appear in the WAN-exposed Findings, got %+v", report.Findings)
	}
}

// adminPortalByName returns the portal with the given name.
func adminPortalByName(portals []adminPortal, name string) (adminPortal, bool) {
	for _, p := range portals {
		if p.Name == name {
			return p, true
		}
	}

	return adminPortal{}, false
}

// TestRedMode_WANHygieneObservationBecomesExposure asserts a WAN-reachable
// shared-engine hygiene observation (an any-to-any pass rule on WAN) is
// reframed as a red exposure Finding via addAttackSurfaces.
func TestRedMode_WANHygieneObservationBecomesExposure(t *testing.T) {
	t.Parallel()

	device := &common.CommonDevice{
		Interfaces: []common.Interface{
			{Name: "wan", Enabled: true},
			{Name: "lan", Enabled: true},
		},
		FirewallRules: []common.FirewallRule{
			{
				Type:        common.RuleTypePass,
				Interfaces:  []string{"wan"},
				Source:      common.RuleEndpoint{Address: constants.NetworkAny},
				Destination: common.RuleEndpoint{Address: constants.NetworkAny},
			},
		},
	}

	report := newRedReport(device)
	runRedAnalysis(report)

	if got := report.Metadata["attack_surfaces_count"]; got == 0 {
		t.Fatal("attack_surfaces_count = 0, want > 0 (WAN any-to-any rule reframed as exposure)")
	}
	if _, ok := findingByTitlePrefix(report.Findings, "Exposed Weakness:"); !ok {
		t.Errorf("expected a reframed 'Exposed Weakness' finding, got %+v", report.Findings)
	}
}

// TestRedMode_RegressionBattery (R23/R24) locks the red-mode correctness
// invariants against known-bad and known-good configs: multi-WAN, floating,
// and IPv6 exposure must be surfaced; a NAT rule with no matching pass rule and
// an all-LAN config must not be reported WAN-exposed.
//
//nolint:funlen // test table or data declaration; length is in data not logic
func TestRedMode_RegressionBattery(t *testing.T) {
	t.Parallel()

	wanLAN := []common.Interface{{Name: "wan", Enabled: true}, {Name: "lan", Enabled: true}}

	tests := []struct {
		name              string
		device            *common.CommonDevice
		wantFindingPrefix string // required Finding title prefix ("" = expect none)
		wantNoWANExposure bool   // wan_exposed_services_count must be 0
	}{
		{
			name: "AE5 multi-WAN: SSH exposed via WAN2 pass rule",
			device: &common.CommonDevice{
				System:     common.System{SSH: common.SSH{Enabled: true, Port: "22"}},
				Interfaces: []common.Interface{{Name: "wan2", Enabled: true}, {Name: "lan", Enabled: true}},
				FirewallRules: []common.FirewallRule{
					{
						Type:        common.RuleTypePass,
						Interfaces:  []string{"wan2"},
						Destination: common.RuleEndpoint{Port: "22"},
					},
				},
			},
			wantFindingPrefix: "WAN-Exposed Service: SSH",
		},
		{
			name: "AE6 floating rule exposes WebGUI (lands in Findings)",
			device: &common.CommonDevice{
				System:     common.System{WebGUI: common.WebGUI{Protocol: constants.ProtocolHTTPS}},
				Interfaces: wanLAN,
				FirewallRules: []common.FirewallRule{
					{Type: common.RuleTypePass, Floating: true, Destination: common.RuleEndpoint{Port: "443"}},
				},
			},
			wantFindingPrefix: "WAN-Exposed Service: Web Administration Interface",
		},
		{
			name: "AE6 IPv6 WAN interface exposes SSH",
			device: &common.CommonDevice{
				System: common.System{SSH: common.SSH{Enabled: true, Port: "22"}},
				Interfaces: []common.Interface{
					{Name: "wan", Enabled: true, IPv6Address: "2001:db8::1"},
					{Name: "lan", Enabled: true},
				},
				FirewallRules: []common.FirewallRule{
					{
						Type:        common.RuleTypePass,
						Interfaces:  []string{"wan"},
						IPProtocol:  common.IPProtocolInet6,
						Destination: common.RuleEndpoint{Port: "22"},
					},
				},
			},
			wantFindingPrefix: "WAN-Exposed Service: SSH",
		},
		{
			name: "port range: SSH exposed when WAN rule permits a range covering 22",
			device: &common.CommonDevice{
				System:     common.System{SSH: common.SSH{Enabled: true, Port: "22"}},
				Interfaces: wanLAN,
				FirewallRules: []common.FirewallRule{
					{
						Type:        common.RuleTypePass,
						Interfaces:  []string{"wan"},
						Destination: common.RuleEndpoint{Port: "20-25"},
					},
				},
			},
			wantFindingPrefix: "WAN-Exposed Service: SSH",
		},
		{
			name: "port list: SSH exposed when WAN rule permits a comma list containing 22",
			device: &common.CommonDevice{
				System:     common.System{SSH: common.SSH{Enabled: true, Port: "22"}},
				Interfaces: wanLAN,
				FirewallRules: []common.FirewallRule{
					{
						Type:        common.RuleTypePass,
						Interfaces:  []string{"wan"},
						Destination: common.RuleEndpoint{Port: "80,22,443"},
					},
				},
			},
			wantFindingPrefix: "WAN-Exposed Service: SSH",
		},
		{
			name: "port range miss: SSH not exposed when WAN rule range excludes 22",
			device: &common.CommonDevice{
				System: common.System{
					SSH:    common.SSH{Enabled: true, Port: "22"},
					WebGUI: common.WebGUI{Protocol: constants.ProtocolHTTPS},
				},
				Interfaces: wanLAN,
				FirewallRules: []common.FirewallRule{
					{
						Type:        common.RuleTypePass,
						Interfaces:  []string{"wan"},
						Source:      common.RuleEndpoint{Address: "198.51.100.0/24"},
						Destination: common.RuleEndpoint{Port: "8000-9000"},
					},
				},
			},
			wantNoWANExposure: true,
		},
		{
			name: "parsePort fallback: malformed negative WebGUI port still resolves to the https default (443)",
			device: &common.CommonDevice{
				System:     common.System{WebGUI: common.WebGUI{Protocol: constants.ProtocolHTTPS, Port: "-22"}},
				Interfaces: wanLAN,
				FirewallRules: []common.FirewallRule{
					{
						Type:        common.RuleTypePass,
						Interfaces:  []string{"wan"},
						Destination: common.RuleEndpoint{Port: "443"},
					},
				},
			},
			wantFindingPrefix: "WAN-Exposed Service: Web Administration Interface",
		},
		{
			name: "parsePort fallback: out-of-range WebGUI port still resolves to the https default (443)",
			device: &common.CommonDevice{
				System:     common.System{WebGUI: common.WebGUI{Protocol: constants.ProtocolHTTPS, Port: "99999"}},
				Interfaces: wanLAN,
				FirewallRules: []common.FirewallRule{
					{
						Type:        common.RuleTypePass,
						Interfaces:  []string{"wan"},
						Destination: common.RuleEndpoint{Port: "443"},
					},
				},
			},
			wantFindingPrefix: "WAN-Exposed Service: Web Administration Interface",
		},
		{
			name: "http WebGUI: exposed when WAN rule permits the default http port 80",
			device: &common.CommonDevice{
				System:     common.System{WebGUI: common.WebGUI{Protocol: "http"}},
				Interfaces: wanLAN,
				FirewallRules: []common.FirewallRule{
					{
						Type:        common.RuleTypePass,
						Interfaces:  []string{"wan"},
						Destination: common.RuleEndpoint{Port: "80"},
					},
				},
			},
			wantFindingPrefix: "WAN-Exposed Service: Web Administration Interface",
		},
		{
			name: "disabled WAN pass rule does not permit the port it would otherwise expose",
			device: &common.CommonDevice{
				System:     common.System{SSH: common.SSH{Enabled: true, Port: "22"}},
				Interfaces: wanLAN,
				FirewallRules: []common.FirewallRule{
					{
						Type:        common.RuleTypePass,
						Interfaces:  []string{"wan"},
						Destination: common.RuleEndpoint{Port: "22"},
						Disabled:    true,
					},
				},
			},
			wantNoWANExposure: true,
		},
		{
			name: "block-type WAN rule does not permit the port it matches",
			device: &common.CommonDevice{
				System:     common.System{SSH: common.SSH{Enabled: true, Port: "22"}},
				Interfaces: wanLAN,
				FirewallRules: []common.FirewallRule{
					{
						Type:        common.RuleTypeBlock,
						Interfaces:  []string{"wan"},
						Destination: common.RuleEndpoint{Port: "22"},
					},
				},
			},
			wantNoWANExposure: true,
		},
		{
			name: "SNMP not exposed when the only WAN rule permits a different port",
			device: &common.CommonDevice{
				// The WAN rule below permits port 8080 only — deliberately not
				// 443, since the WebGUI is always present in serviceExposures
				// and defaults to port 443, which would otherwise make this a
				// WebGUI-exposure case instead of the intended SNMP miss.
				SNMP:       common.SNMPConfig{ROCommunity: "public"},
				Interfaces: wanLAN,
				FirewallRules: []common.FirewallRule{
					{
						Type:        common.RuleTypePass,
						Interfaces:  []string{"wan"},
						Source:      common.RuleEndpoint{Address: "198.51.100.0/24"},
						Destination: common.RuleEndpoint{Port: "8080"},
					},
				},
			},
			wantNoWANExposure: true,
		},
		{
			name: "port alias: unresolvable alias over-reports SSH as exposed (safe direction)",
			device: &common.CommonDevice{
				System:     common.System{SSH: common.SSH{Enabled: true, Port: "22"}},
				Interfaces: wanLAN,
				FirewallRules: []common.FirewallRule{
					{
						Type:        common.RuleTypePass,
						Interfaces:  []string{"wan"},
						Destination: common.RuleEndpoint{Port: "MgmtPorts"},
					},
				},
			},
			wantFindingPrefix: "WAN-Exposed Service: SSH",
		},
		{
			name: "custom WebGUI port: exposed when WAN rule permits the configured port",
			device: &common.CommonDevice{
				System:     common.System{WebGUI: common.WebGUI{Protocol: constants.ProtocolHTTPS, Port: "8443"}},
				Interfaces: wanLAN,
				FirewallRules: []common.FirewallRule{
					{
						Type:        common.RuleTypePass,
						Interfaces:  []string{"wan"},
						Destination: common.RuleEndpoint{Port: "8443"},
					},
				},
			},
			wantFindingPrefix: "WAN-Exposed Service: Web Administration Interface",
		},
		{
			name: "custom WebGUI port: not exposed when WAN rule permits only the default 443",
			device: &common.CommonDevice{
				System:     common.System{WebGUI: common.WebGUI{Protocol: constants.ProtocolHTTPS, Port: "8443"}},
				Interfaces: wanLAN,
				FirewallRules: []common.FirewallRule{
					{
						Type:        common.RuleTypePass,
						Interfaces:  []string{"wan"},
						Source:      common.RuleEndpoint{Address: "198.51.100.0/24"},
						Destination: common.RuleEndpoint{Port: "443"},
					},
				},
			},
			wantNoWANExposure: true,
		},
		{
			name: "SNMP exposed via WAN rule permitting 161",
			device: &common.CommonDevice{
				SNMP:       common.SNMPConfig{ROCommunity: "public"},
				Interfaces: wanLAN,
				FirewallRules: []common.FirewallRule{
					{
						Type:        common.RuleTypePass,
						Interfaces:  []string{"wan"},
						Destination: common.RuleEndpoint{Port: "161"},
					},
				},
			},
			wantFindingPrefix: "WAN-Exposed Service: SNMP",
		},
		{
			name: "R3 NAT with no matching pass rule is not WAN-exposed",
			device: &common.CommonDevice{
				System:     common.System{SSH: common.SSH{Enabled: true, Port: "22"}},
				Interfaces: wanLAN,
				NAT: common.NATConfig{
					InboundRules: []common.InboundNATRule{
						{Interfaces: []string{"wan"}, ExternalPort: "22"},
					},
				},
			},
			wantNoWANExposure: true,
		},
		{
			name: "clean all-LAN config has no WAN exposure",
			device: &common.CommonDevice{
				System: common.System{
					SSH:    common.SSH{Enabled: true, Port: "22"},
					WebGUI: common.WebGUI{Protocol: constants.ProtocolHTTPS},
				},
				Interfaces: wanLAN,
				FirewallRules: []common.FirewallRule{
					{Type: common.RuleTypePass, Interfaces: []string{"lan"}},
				},
			},
			wantNoWANExposure: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			report := newRedReport(tt.device)
			runRedAnalysis(report)

			if tt.wantNoWANExposure {
				// Assert every red exposure producer, not just the service
				// count: a case like "R3 NAT with no matching pass rule" would
				// still incorrectly pass if addWeakNATRules emitted a
				// "WAN-Reachable Port Forward" Finding (that Finding is counted
				// by weak_nat_rules_count, not wan_exposed_services_count), and
				// likewise for addAttackSurfaces/attack_surfaces_count.
				if got := report.Metadata["wan_exposed_services_count"]; got != 0 {
					t.Errorf("wan_exposed_services_count = %v, want 0", got)
				}

				if got := report.Metadata["weak_nat_rules_count"]; got != 0 {
					t.Errorf("weak_nat_rules_count = %v, want 0", got)
				}

				if got := report.Metadata["attack_surfaces_count"]; got != 0 {
					t.Errorf("attack_surfaces_count = %v, want 0", got)
				}

				for _, f := range report.Findings {
					if f.Type == findingTypeExposure {
						t.Errorf("unexpected exposure finding: %+v", f)
					}
				}

				return
			}

			if _, ok := findingByTitlePrefix(report.Findings, tt.wantFindingPrefix); !ok {
				t.Errorf("expected a finding titled %q, got %+v", tt.wantFindingPrefix, report.Findings)
			}
		})
	}
}

// TestRedMode_WeakNATRule_PositivePath covers the addWeakNATRules Finding-
// emitting branch (R15): a WAN inbound NAT rule correlated with an enabled WAN
// pass rule produces a "WAN-Reachable Port Forward" Finding with AttackSurface.
func TestRedMode_WeakNATRule_PositivePath(t *testing.T) {
	t.Parallel()

	device := &common.CommonDevice{
		Interfaces: []common.Interface{{Name: "wan", Enabled: true}, {Name: "lan", Enabled: true}},
		FirewallRules: []common.FirewallRule{
			{Type: common.RuleTypePass, Interfaces: []string{"wan"}},
		},
		NAT: common.NATConfig{
			InboundRules: []common.InboundNATRule{
				{Interfaces: []string{"wan"}, ExternalPort: "3389", Protocol: "tcp"},
			},
		},
	}

	report := newRedReport(device)
	runRedAnalysis(report)

	if got := report.Metadata["weak_nat_rules_count"]; got != 1 {
		t.Fatalf("weak_nat_rules_count = %v, want 1", got)
	}

	nat, ok := findingByTitlePrefix(report.Findings, "WAN-Reachable Port Forward")
	if !ok {
		t.Fatalf("expected a WAN-Reachable Port Forward finding, got %+v", report.Findings)
	}
	if nat.AttackSurface == nil || !slices.Contains(nat.AttackSurface.Ports, 3389) {
		t.Errorf("NAT finding AttackSurface = %+v, want Ports to contain 3389", nat.AttackSurface)
	}
}

// TestRedMode_WeakNATRule_PortFromDestination covers the port on the Finding.
// Neither vendor writes <externalport>; the port a forward matches on is the
// destination port, so the Finding reads that when ExternalPort is empty.
func TestRedMode_WeakNATRule_PortFromDestination(t *testing.T) {
	t.Parallel()

	device := &common.CommonDevice{
		Interfaces: []common.Interface{{Name: "wan", Enabled: true}},
		FirewallRules: []common.FirewallRule{
			{Type: common.RuleTypePass, Interfaces: []string{"wan"}},
		},
		NAT: common.NATConfig{
			InboundRules: []common.InboundNATRule{{
				Interfaces:  []string{"wan"},
				Protocol:    "tcp",
				Destination: common.RuleEndpoint{Address: "wanip", Port: "8443"},
				InternalIP:  "192.168.1.50",
			}},
		},
	}

	report := newRedReport(device)
	runRedAnalysis(report)

	nat, ok := findingByTitlePrefix(report.Findings, "WAN-Reachable Port Forward")
	if !ok {
		t.Fatalf("expected a WAN-Reachable Port Forward finding, got %+v", report.Findings)
	}
	if nat.AttackSurface == nil || !slices.Equal(nat.AttackSurface.Ports, []int{8443}) {
		t.Errorf("NAT finding AttackSurface = %+v, want Ports [8443]", nat.AttackSurface)
	}
}

// TestRedMode_WeakNATRule_NoRDRNotReported covers a no-RDR rule, which exempts
// traffic from redirection and forwards nothing, so it is not an exposure.
func TestRedMode_WeakNATRule_NoRDRNotReported(t *testing.T) {
	t.Parallel()

	device := &common.CommonDevice{
		Interfaces: []common.Interface{{Name: "wan", Enabled: true}},
		FirewallRules: []common.FirewallRule{
			{Type: common.RuleTypePass, Interfaces: []string{"wan"}},
		},
		NAT: common.NATConfig{
			InboundRules: []common.InboundNATRule{{
				Interfaces:  []string{"wan"},
				Protocol:    "tcp",
				Destination: common.RuleEndpoint{Address: "wanip", Port: "443"},
				NoRDR:       true,
			}},
		},
	}

	report := newRedReport(device)
	runRedAnalysis(report)

	if got := report.Metadata["weak_nat_rules_count"]; got != 0 {
		t.Errorf("weak_nat_rules_count = %v, want 0 (a no-RDR rule forwards nothing)", got)
	}
	if f, ok := findingByTitlePrefix(report.Findings, "WAN-Reachable Port Forward"); ok {
		t.Errorf("unexpected finding for a no-RDR rule: %+v", f)
	}
}

// TestRedMode_NATForward_DoesNotExposeFirewallLocalService covers the
// serviceReachability/wanRulePermitsPort correctness fix: a WAN-reachable NAT
// port-forward must never be treated as evidence that the FIREWALL'S OWN
// management service (WebGUI/SSH/SNMP) is WAN-reachable, even when the NAT
// rule's ExternalPort happens to equal the management service's port. The NAT
// rule here forwards WAN port 22 to an unrelated internal host
// (InternalIP=192.0.2.50); the only firewall pass rule permits an unrelated
// port (80). The port forward itself is a legitimate, separately-reported
// exposure (weak_nat_rules_count == 1), but nothing in this config exposes the
// firewall's own SSH daemon, so no "WAN-Exposed Service: SSH" finding may
// appear.
func TestRedMode_NATForward_DoesNotExposeFirewallLocalService(t *testing.T) {
	t.Parallel()

	device := &common.CommonDevice{
		System:     common.System{SSH: common.SSH{Enabled: true, Port: "22"}},
		Interfaces: []common.Interface{{Name: "wan", Enabled: true}, {Name: "lan", Enabled: true}},
		FirewallRules: []common.FirewallRule{
			{
				Type:        common.RuleTypePass,
				Interfaces:  []string{"wan"},
				Destination: common.RuleEndpoint{Port: "80"},
			},
		},
		NAT: common.NATConfig{
			InboundRules: []common.InboundNATRule{
				{
					Interfaces:   []string{"wan"},
					ExternalPort: "22",
					InternalIP:   "192.0.2.50",
					InternalPort: "22",
				},
			},
		},
	}

	report := newRedReport(device)
	runRedAnalysis(report)

	if got := report.Metadata["weak_nat_rules_count"]; got != 1 {
		t.Errorf("weak_nat_rules_count = %v, want 1 (the port forward is a legitimate, distinct exposure)", got)
	}

	if got := report.Metadata["wan_exposed_services_count"]; got != 0 {
		t.Errorf("wan_exposed_services_count = %v, want 0 (firewall-local SSH was never actually exposed)", got)
	}

	if _, ok := findingByTitlePrefix(report.Findings, "WAN-Exposed Service: SSH"); ok {
		t.Errorf("unexpected WAN-Exposed Service: SSH finding — NAT forward to a distinct host must not "+
			"be conflated with firewall-local service exposure: %+v", report.Findings)
	}
}

// TestRedMode_FindingsOrderedBySeverity covers R16: red exposure findings lead
// with the most urgent. A WebGUI exposure (critical) must sort ahead of an SSH
// exposure (high) when both are WAN-reachable via a broad any-port WAN rule.
func TestRedMode_FindingsOrderedBySeverity(t *testing.T) {
	t.Parallel()

	device := &common.CommonDevice{
		System: common.System{
			SSH:    common.SSH{Enabled: true, Port: "22"},
			WebGUI: common.WebGUI{Protocol: constants.ProtocolHTTPS},
		},
		Interfaces: []common.Interface{{Name: "wan", Enabled: true}, {Name: "lan", Enabled: true}},
		// Any-port WAN rule exposes every management service.
		FirewallRules: []common.FirewallRule{
			{
				Type:       common.RuleTypePass,
				Interfaces: []string{"wan"},
				Source:     common.RuleEndpoint{Address: constants.NetworkAny},
			},
		},
	}

	report := newRedReport(device)
	runRedAnalysis(report)

	if len(report.Findings) < 2 {
		t.Fatalf("expected >= 2 findings, got %d: %+v", len(report.Findings), report.Findings)
	}
	// The first finding must be the critical WebGUI exposure, ahead of SSH (high).
	if report.Findings[0].Severity != string(analysis.SeverityCritical) {
		t.Errorf("first finding severity = %q, want %q (most urgent leads)",
			report.Findings[0].Severity, analysis.SeverityCritical)
	}
}

// TestRedMode_AnyToAnyComponentCollision pins the intended one-exposure-per-
// config-element behavior (A3): when a WAN-scoped any-to-any pass rule triggers
// both the "Overly Permissive WAN Rule" and "Any-to-Any Pass Rule" observations
// on the same filter.rule[N] Component, addAttackSurfaces emits exactly one
// exposure finding for that element — the shared engine appends the permissive-
// WAN observation first, so it is the one retained. This is deliberate: a single
// rule is one exposure, not two.
func TestRedMode_AnyToAnyComponentCollision(t *testing.T) {
	t.Parallel()

	device := &common.CommonDevice{
		Interfaces: []common.Interface{{Name: "wan", Enabled: true}, {Name: "lan", Enabled: true}},
		FirewallRules: []common.FirewallRule{
			{
				Type:        common.RuleTypePass,
				Interfaces:  []string{"wan"},
				Source:      common.RuleEndpoint{Address: constants.NetworkAny},
				Destination: common.RuleEndpoint{Address: constants.NetworkAny},
			},
		},
	}

	report := newRedReport(device)
	runRedAnalysis(report)

	count := 0
	var survivor Finding
	for _, f := range report.Findings {
		if f.Component == "filter.rule[0]" {
			count++
			survivor = f
		}
	}
	if count != 1 {
		t.Errorf("filter.rule[0] exposure findings = %d, want exactly 1 (one exposure per config element)", count)
	}
	// Pin WHICH observation survives the collision: DetectSecurityIssues runs
	// first inside ScanObservations and contributes "Overly Permissive WAN
	// Rule" for this rule; detectAnyToAnyRules runs later and contributes
	// "Any-to-Any Pass Rule" for the same Component. addAttackSurfaces keeps
	// the first-seen observation per Component, so the permissive-WAN framing
	// must win.
	wantTitle := "Exposed Weakness: Overly Permissive WAN Rule"
	if survivor.Title != wantTitle {
		t.Errorf("surviving filter.rule[0] finding Title = %q, want %q", survivor.Title, wantTitle)
	}
}

// TestRedMode_BlackhatChangesToneNotSafety covers AE7 and R20 end-to-end
// through GenerateReport (the real ModeConfig.Blackhat wiring): the
// --audit-blackhat variant changes the ExploitNote text but never introduces
// instructional content — the R21 denylist passes for both tone variants.
func TestRedMode_BlackhatChangesToneNotSafety(t *testing.T) {
	t.Parallel()

	device := &common.CommonDevice{
		System:     common.System{SSH: common.SSH{Enabled: true, Port: "22"}},
		Interfaces: []common.Interface{{Name: "wan", Enabled: true}, {Name: "lan", Enabled: true}},
		FirewallRules: []common.FirewallRule{
			{Type: common.RuleTypePass, Interfaces: []string{"wan"}, Destination: common.RuleEndpoint{Port: "22"}},
		},
	}

	mc := NewModeController(NewPluginRegistry(), newTestLogger(t))

	exploitNoteFrom := func(blackhat bool) string {
		report, err := mc.GenerateReport(context.Background(), device, &ModeConfig{Mode: ModeRed, Blackhat: blackhat})
		if err != nil {
			t.Fatalf("GenerateReport(blackhat=%v) error = %v", blackhat, err)
		}
		ssh, ok := findingByTitlePrefix(report.Findings, "WAN-Exposed Service: SSH")
		if !ok {
			t.Fatalf("blackhat=%v: expected an SSH exposure finding, got %+v", blackhat, report.Findings)
		}

		return ssh.ExploitNotes
	}

	standard := exploitNoteFrom(false)
	blackhat := exploitNoteFrom(true)

	if standard == "" || blackhat == "" {
		t.Fatal("both tone variants must produce a non-empty ExploitNote")
	}
	if standard == blackhat {
		t.Error("--audit-blackhat must change the ExploitNote tone")
	}
	// The safety invariant holds regardless of tone.
	for _, note := range []string{standard, blackhat} {
		if pattern, unsafe := FindInstructionalContent(note); unsafe {
			t.Errorf("ExploitNote matched instructional pattern %q (tone must not affect safety): %q", pattern, note)
		}
	}
}

// TestRedMode_NoStubMarkersRemain is the U5 verification gate: after full red
// analysis, no metadata value carries the old `{not_implemented, stub}` marker
// shape — every red method now performs real analysis.
func TestRedMode_NoStubMarkersRemain(t *testing.T) {
	t.Parallel()

	device := &common.CommonDevice{
		System:     common.System{SSH: common.SSH{Enabled: true, Port: "22"}},
		Interfaces: []common.Interface{{Name: "wan", Enabled: true}},
		FirewallRules: []common.FirewallRule{
			{Type: common.RuleTypePass, Interfaces: []string{"wan"}, Destination: common.RuleEndpoint{Port: "22"}},
		},
	}

	report := newRedReport(device)
	runRedAnalysis(report)

	for key, value := range report.Metadata {
		marker, ok := value.(map[string]any)
		if !ok {
			continue
		}
		if marker["stub"] == true || marker["not_implemented"] == true {
			t.Errorf("metadata[%q] still carries a stub marker: %v", key, marker)
		}
	}
}

// TestRulePortPermits is a focused table test on the pure port-matching
// predicate underlying wanRulePermitsPort: exact numeric match, numeric range
// (including reversed bounds), comma-separated lists (including empty and
// whitespace-padded tokens), and the deliberate over-report behavior for
// unresolvable aliases and empty/"any" rule ports.
func TestRulePortPermits(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		rulePort    string
		servicePort int
		want        bool
	}{
		{name: "empty rule port permits everything", rulePort: "", servicePort: 22, want: true},
		{name: "any rule port permits everything", rulePort: constants.NetworkAny, servicePort: 22, want: true},
		{name: "exact numeric match", rulePort: "22", servicePort: 22, want: true},
		{name: "exact numeric miss", rulePort: "23", servicePort: 22, want: false},
		{name: "range hit", rulePort: "20-25", servicePort: 22, want: true},
		{name: "range miss", rulePort: "80-90", servicePort: 22, want: false},
		{name: "reversed range still contains the port", rulePort: "25-20", servicePort: 22, want: true},
		{name: "comma list hit", rulePort: "80,22,443", servicePort: 22, want: true},
		{name: "comma list miss", rulePort: "80,21,443", servicePort: 22, want: false},
		{name: "comma list with empty token still matches", rulePort: "22,,443", servicePort: 22, want: true},
		{
			name:        "comma list with empty token: non-matching port still misses",
			rulePort:    "22,,443",
			servicePort: 100,
			want:        false,
		},
		{name: "whitespace-padded tokens", rulePort: "22, 443", servicePort: 443, want: true},
		{name: "unresolvable alias over-reports (safe direction)", rulePort: "MgmtPorts", servicePort: 22, want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := rulePortPermits(tt.rulePort, tt.servicePort); got != tt.want {
				t.Errorf("rulePortPermits(%q, %d) = %v, want %v", tt.rulePort, tt.servicePort, got, tt.want)
			}
		})
	}
}

// TestParsePortRange is a focused table test on the pure "N-M" range parser:
// normal ranges, reversed bounds (normalized low/high), and non-range inputs
// that must report ok=false rather than a nonsensical bound pair.
func TestParsePortRange(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		token  string
		wantLo int
		wantHi int
		wantOK bool
	}{
		{name: "ascending range", token: "20-25", wantLo: 20, wantHi: 25, wantOK: true},
		{name: "reversed range is normalized", token: "25-20", wantLo: 20, wantHi: 25, wantOK: true},
		{name: "single port is not a range", token: "22", wantOK: false},
		{name: "non-numeric low bound", token: "abc-25", wantOK: false},
		{name: "non-numeric high bound", token: "20-abc", wantOK: false},
		{name: "empty token is not a range", token: "", wantOK: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			lo, hi, ok := parsePortRange(tt.token)
			if ok != tt.wantOK {
				t.Fatalf("parsePortRange(%q) ok = %v, want %v", tt.token, ok, tt.wantOK)
			}
			if !ok {
				return
			}
			if lo != tt.wantLo || hi != tt.wantHi {
				t.Errorf("parsePortRange(%q) = (%d, %d), want (%d, %d)", tt.token, lo, hi, tt.wantLo, tt.wantHi)
			}
		})
	}
}

// TestExploitNoteTemplates_MatchesAllKinds guards the exploitNoteKind const
// list against drifting from the exploitNoteTemplates map: every kind
// returned by allExploitNoteKinds() must have a template entry, and the map
// must not carry orphaned entries for kinds no longer in the const list.
func TestExploitNoteTemplates_MatchesAllKinds(t *testing.T) {
	t.Parallel()

	kinds := allExploitNoteKinds()

	for _, kind := range kinds {
		if _, ok := exploitNoteTemplates[kind]; !ok {
			t.Errorf("exploitNoteTemplates is missing an entry for kind %q", kind)
		}
	}

	if len(exploitNoteTemplates) != len(kinds) {
		t.Errorf(
			"exploitNoteTemplates has %d entries but allExploitNoteKinds() lists %d kinds — the two have drifted apart",
			len(exploitNoteTemplates), len(kinds),
		)
	}
}

// TestReport_AddComplianceAnalysis_CompletionFlag pins both branches of the
// compliance_check_completed honesty fix (see the doc comment on
// addComplianceAnalysis): the flag is false when no compliance plugin
// actually executed (an empty Compliance map) and true once at least one
// plugin result is present, regardless of that plugin's own findings.
func TestReport_AddComplianceAnalysis_CompletionFlag(t *testing.T) {
	t.Parallel()

	t.Run("empty compliance map yields false", func(t *testing.T) {
		t.Parallel()

		report := newRedReport(&common.CommonDevice{})
		report.addComplianceAnalysis()

		if got := report.Metadata["compliance_check_completed"]; got != false {
			t.Errorf("compliance_check_completed = %v, want false (no plugin executed)", got)
		}
	})

	t.Run("populated compliance map yields true", func(t *testing.T) {
		t.Parallel()

		report := newRedReport(&common.CommonDevice{})
		report.Compliance["firewall"] = ComplianceResult{}
		report.addComplianceAnalysis()

		if got := report.Metadata["compliance_check_completed"]; got != true {
			t.Errorf("compliance_check_completed = %v, want true (a plugin executed)", got)
		}
	})
}

// TestRedMode_PortForwardCompanionRule_ExposesOnlyTheFirewallTarget covers the
// filter rule a port forward stores for itself, and the same rule with no link.
// pf matches either after rdr, so a rule passing WAN traffic to another host on
// 443 does not expose the firewall's own web GUI; one whose target is the
// firewall, or cannot be told apart from it, still does. A rule of its own to
// an address no forward targets stays counted: nothing says the firewall does
// not hold that address. Only the address is compared, so a forward that is
// disabled or on another interface still accounts for its rule: the OPNsense
// list page toggles only linked rules, and disabling a forward leaves an
// unassociated rule enabled.
func TestRedMode_PortForwardCompanionRule_ExposesOnlyTheFirewallTarget(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		destination common.RuleEndpoint
		linked      bool
		wantExposed bool
	}{
		{"companion to another host", common.RuleEndpoint{Address: "10.0.2.2", Port: "443"}, true, false},
		{"companion to another IPv6 host", common.RuleEndpoint{Address: "2001:db8::50", Port: "443"}, true, false},
		{"companion to loopback", common.RuleEndpoint{Address: "127.0.0.1", Port: "443"}, true, true},
		{"companion to another loopback address", common.RuleEndpoint{Address: "127.0.0.2", Port: "443"}, true, true},
		{"companion to the LAN address", common.RuleEndpoint{Address: "192.168.1.1", Port: "443"}, true, true},
		{"companion to the WAN IPv6 address", common.RuleEndpoint{Address: "2001:db8::2", Port: "443"}, true, true},
		{"companion to a name no alias defines", common.RuleEndpoint{Address: "UNDEFINED", Port: "443"}, true, true},
		{"companion to a CARP address", common.RuleEndpoint{Address: "192.168.1.254", Port: "443"}, true, true},
		{
			"companion to a negated host",
			common.RuleEndpoint{Address: "10.0.2.2", Port: "443", Negated: true},
			true,
			true,
		},
		{"no link, a forward's target", common.RuleEndpoint{Address: "10.0.3.3", Port: "443"}, false, false},
		{"no link, a forward's port range", common.RuleEndpoint{Address: "10.0.3.3", Port: "443-453"}, false, false},
		{"no link, a forward to the LAN", common.RuleEndpoint{Address: "192.168.1.1", Port: "443"}, false, true},
		{
			"no link, a forward to a name no alias defines",
			common.RuleEndpoint{Address: "UNDEFINED", Port: "443"},
			false,
			true,
		},
		{"no link, a disabled forward's target", common.RuleEndpoint{Address: "10.0.3.4", Port: "443"}, false, false},
		{
			"no link, a target on another interface",
			common.RuleEndpoint{Address: "10.0.3.5", Port: "443"},
			false,
			false,
		},
		{
			"no link, a target spelled another way",
			common.RuleEndpoint{Address: "2001:0db8:0:0::60", Port: "443"},
			false,
			false,
		},
		{"no link, a disabled forward's alias", aliasEndpoint("WEB_OFF"), false, false},
		{"no link, an alias on another interface", aliasEndpoint("WEB_LAN"), false, false},
		{
			"no link, a negated forward's target",
			common.RuleEndpoint{Address: "10.0.3.3", Port: "443", Negated: true},
			false,
			true,
		},
		{"rule of its own to another host", common.RuleEndpoint{Address: "10.0.2.2", Port: "443"}, false, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			rule := common.FirewallRule{
				Type:        common.RuleTypePass,
				Interfaces:  []string{"wan"},
				Destination: tc.destination,
			}
			if tc.linked {
				rule.AssociatedRuleID = "nat_5e7bb3f7a503d5.68828728"
			}

			device := portForwardDevice(rule)
			device.NAT.InboundRules = []common.InboundNATRule{
				{Interfaces: []string{"wan"}, InternalIP: "10.0.3.3", LocalPort: "443"},
				{Interfaces: []string{"wan"}, InternalIP: "192.168.1.1", LocalPort: "443"},
				{Interfaces: []string{"wan"}, InternalIP: "UNDEFINED", LocalPort: "443"},
				{Interfaces: []string{"wan"}, InternalIP: "10.0.3.4", LocalPort: "443", Disabled: true},
				{Interfaces: []string{"lan"}, InternalIP: "10.0.3.5", LocalPort: "443"},
				{Interfaces: []string{"wan"}, InternalIP: "2001:db8::60", LocalPort: "443"},
				{Interfaces: []string{"wan"}, InternalIP: "WEB_OFF", LocalPort: "443", Disabled: true},
				{Interfaces: []string{"lan"}, InternalIP: "WEB_LAN", LocalPort: "443"},
			}
			device.NamedObjects = common.NamedObjects{
				"WEB_OFF": {Type: common.NamedObjectTypeHost, Members: []string{"10.0.3.6"}},
				"WEB_LAN": {Type: common.NamedObjectTypeHost, Members: []string{"10.0.3.7"}},
			}

			assertWebGUIExposed(t, device, tc.wantExposed)
		})
	}
}

// TestRedMode_PortForwardToNetwork_ExposesOnlyTheFirewallTarget covers a forward
// whose target is a literal network, which the OPNsense page accepts and copies
// onto the forward's rule as it stands. The rule, linked or not, does not expose
// the web GUI unless the network holds an address of the firewall, since traffic
// to that address passes the rule too. A network no forward targets stays
// counted, as a host does: nothing says the firewall has no address there.
func TestRedMode_PortForwardToNetwork_ExposesOnlyTheFirewallTarget(t *testing.T) {
	t.Parallel()

	to := func(address string) common.RuleEndpoint {
		return common.RuleEndpoint{Address: address, Port: "443"}
	}

	negated := to("10.0.4.0/24")
	negated.Negated = true

	tests := []struct {
		name        string
		destination common.RuleEndpoint
		linked      bool
		wantExposed bool
	}{
		{"companion to another network", to("10.0.4.0/24"), true, false},
		{"companion to another IPv6 network", to("2001:db8:4::/64"), true, false},
		{"companion to the LAN network", to("192.168.1.0/24"), true, true},
		{"companion to the CARP address's network", to("192.168.1.128/25"), true, true},
		{"companion to the WAN IPv6 network", to("2001:db8::/64"), true, true},
		{"companion to the loopback network", to("127.0.0.0/8"), true, true},
		{"companion to part of the loopback network", to("127.1.0.0/16"), true, true},
		{"companion to a negated network", negated, true, true},
		{"no link, a forward's network", to("10.0.4.0/24"), false, false},
		{"no link, a forward's IPv6 network", to("2001:db8:4::/64"), false, false},
		{"no link, a forward's network with host bits", to("10.0.5.0/24"), false, false},
		{"no link, a network with host bits", to("10.0.4.9/24"), false, false},
		{"no link, a forward's host as a network", to("10.0.3.3/32"), false, false},
		{"no link, a forward to the LAN network", to("192.168.1.0/24"), false, true},
		{"no link, part of a forward's network", to("10.0.4.0/25"), false, true},
		{"no link, a host in a forward's network", to("10.0.4.9"), false, true},
		{"no link, a network around a forward's host", to("10.0.3.0/24"), false, true},
		{"no link, a negated forward's network", negated, false, true},
		{"rule of its own to another network", to("10.0.6.0/24"), false, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			rule := common.FirewallRule{
				Type:        common.RuleTypePass,
				Interfaces:  []string{"wan"},
				Destination: tc.destination,
			}
			if tc.linked {
				rule.AssociatedRuleID = "nat_5e7bb3f7a503d5.68828728"
			}

			device := portForwardDevice(rule)
			device.NAT.InboundRules = []common.InboundNATRule{
				{Interfaces: []string{"wan"}, InternalIP: "10.0.3.3", LocalPort: "443"},
				{Interfaces: []string{"wan"}, InternalIP: "10.0.4.0/24", LocalPort: "443"},
				{Interfaces: []string{"wan"}, InternalIP: "2001:db8:4:0::/64", LocalPort: "443"},
				{Interfaces: []string{"wan"}, InternalIP: "10.0.5.7/24", LocalPort: "443"},
				{Interfaces: []string{"wan"}, InternalIP: "192.168.1.0/24", LocalPort: "443"},
			}

			assertWebGUIExposed(t, device, tc.wantExposed)
		})
	}
}

// TestRedMode_PortForwardToNetwork_SpanningLoopback covers a firewall that
// records no address of its own, as with DHCP on every interface. A network wide
// enough to hold a loopback address still holds the firewall, literal or in an
// alias, though no recorded address falls inside it.
func TestRedMode_PortForwardToNetwork_SpanningLoopback(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		network     string
		wantExposed bool
	}{
		{"every IPv4 address", "0.0.0.0/0", true},
		{"every IPv6 address", "::/0", true},
		{"the half of IPv4 with loopback", "0.0.0.0/1", true},
		{"a network around 127.0.0.0/8", "126.0.0.0/7", true},
		{"the other half of IPv4", "128.0.0.0/1", false},
		{"another network", "10.0.4.0/24", false},
	}

	for _, tc := range tests {
		destinations := map[string]common.RuleEndpoint{
			"literal": {Address: tc.network, Port: "443"},
			"alias":   aliasEndpoint("TARGET"),
		}

		for label, destination := range destinations {
			t.Run(tc.name+", "+label, func(t *testing.T) {
				t.Parallel()

				device := portForwardDevice(common.FirewallRule{
					Type:             common.RuleTypePass,
					Interfaces:       []string{"wan"},
					AssociatedRuleID: "nat_5e7bb3f7a503d5.68828728",
					Destination:      destination,
				})
				device.Interfaces = []common.Interface{{Name: "wan", Enabled: true}, {Name: "lan", Enabled: true}}
				device.VirtualIPs = nil
				device.NamedObjects = common.NamedObjects{
					"TARGET": {Type: common.NamedObjectTypeNetwork, Members: []string{tc.network}},
				}
				device.NAT.InboundRules = []common.InboundNATRule{
					{Interfaces: []string{"wan"}, InternalIP: "TARGET", LocalPort: "443"},
				}

				assertWebGUIExposed(t, device, tc.wantExposed)
			})
		}
	}
}

// TestRedMode_PortForwardToAlias_ExposesOnlyTheFirewallTarget covers a forward
// whose target is an alias. Both vendors copy the alias name onto the forward's
// rule, linked or not, so a WAN pass rule naming it is that forward's rule and
// does not expose the web GUI, unless the alias holds an address of the firewall.
// An alias that cannot be expanded has no member to test and counts as the
// forward's rule too.
func TestRedMode_PortForwardToAlias_ExposesOnlyTheFirewallTarget(t *testing.T) {
	t.Parallel()

	host := func(members ...string) common.NamedObject {
		return common.NamedObject{Type: common.NamedObjectTypeHost, Members: members}
	}
	network := func(members ...string) common.NamedObject {
		return common.NamedObject{Type: common.NamedObjectTypeNetwork, Members: members}
	}

	tests := []struct {
		name        string
		alias       common.NamedObject
		wantExposed bool
	}{
		{"other hosts", host("10.0.3.3", "10.0.3.4"), false},
		{"another network", network("10.0.3.0/24"), false},
		{"a range of other hosts", host("10.0.3.3-10.0.3.9"), false},
		{"a range next to the LAN address", host("192.168.1.2-192.168.1.9"), false},
		{"a hostname", host("web.example.com"), false},
		{"nothing", host(), false},
		{"a URL table", common.NamedObject{Type: "urltable", Members: []string{"https://example.com/l"}}, false},
		{"a GeoIP table", common.NamedObject{Type: common.NamedObjectTypeGeoIP, Members: []string{"US"}}, false},
		{"the LAN address among others", host("10.0.3.3", "192.168.1.1"), true},
		{"the WAN IPv6 address", host("2001:db8::2"), true},
		{"a CARP address", host("192.168.1.254"), true},
		{"a loopback address", host("127.0.0.1"), true},
		{"another loopback address", host("127.0.0.2"), true},
		{"the network of the LAN address", network("192.168.1.0/24"), true},
		{"a loopback network", network("127.0.0.0/8"), true},
		{"part of the loopback network", network("127.1.0.0/16"), true},
		{"a range over the LAN address", host("192.168.1.1-192.168.1.9"), true},
		{"a loopback range", host("127.0.0.1-127.0.0.9"), true},
		{"a range of other loopback addresses", host("127.0.0.2-127.0.0.9"), true},
		{"the LAN address in a nested alias", host("10.0.3.3", "NESTED_LAN"), true},
		{"the LAN address behind a nesting loop", host("LOOP"), true},
	}

	for _, tc := range tests {
		for label, link := range map[string]string{"no link": "", "linked": "nat_5e7bb3f7a503d5.68828728"} {
			t.Run(tc.name+", "+label, func(t *testing.T) {
				t.Parallel()

				device := portForwardDevice(common.FirewallRule{
					Type:             common.RuleTypePass,
					Interfaces:       []string{"wan"},
					AssociatedRuleID: link,
					Destination:      aliasEndpoint("TARGET"),
				})
				device.NamedObjects = common.NamedObjects{
					"TARGET":     tc.alias,
					"NESTED_LAN": host("192.168.1.1"),
					"LOOP":       host("TARGET", "192.168.1.1"),
				}
				device.NAT.InboundRules = []common.InboundNATRule{
					{Interfaces: []string{"wan"}, InternalIP: "TARGET", LocalPort: "443"},
				}

				assertWebGUIExposed(t, device, tc.wantExposed)
			})
		}
	}
}

// TestRedMode_RuleToAlias_NotAForwardsRule covers the rules a forward to an
// alias does not account for: one naming an alias no forward targets, linked or
// not, and one negating the alias a forward targets, which matches everything
// else. Both stay counted, the over-report direction.
func TestRedMode_RuleToAlias_NotAForwardsRule(t *testing.T) {
	t.Parallel()

	negated := aliasEndpoint("TARGET")
	negated.Negated = true

	tests := []struct {
		name        string
		destination common.RuleEndpoint
		link        string
	}{
		{"an alias no forward targets", aliasEndpoint("OTHER"), ""},
		{"a linked rule to an alias no forward targets", aliasEndpoint("OTHER"), "nat_5e7bb3f7a503d5.68828728"},
		{"the target negated", negated, ""},
		{"the target negated on a linked rule", negated, "nat_5e7bb3f7a503d5.68828728"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			device := portForwardDevice(common.FirewallRule{
				Type:             common.RuleTypePass,
				Interfaces:       []string{"wan"},
				AssociatedRuleID: tc.link,
				Destination:      tc.destination,
			})
			device.NamedObjects = common.NamedObjects{
				"TARGET": {Type: common.NamedObjectTypeHost, Members: []string{"10.0.3.3"}},
				"OTHER":  {Type: common.NamedObjectTypeHost, Members: []string{"10.0.3.4"}},
			}
			device.NAT.InboundRules = []common.InboundNATRule{
				{Interfaces: []string{"wan"}, InternalIP: "TARGET", LocalPort: "443"},
			}

			assertWebGUIExposed(t, device, true)
		})
	}
}

// aliasEndpoint returns the destination a rule to the named alias converts to,
// on port 443.
func aliasEndpoint(name string) common.RuleEndpoint {
	return common.RuleEndpoint{Address: name, AddressRef: &common.ObjectRef{Name: name}, Port: "443"}
}

// portForwardDevice returns a firewall with an HTTPS web GUI on 443, an interface
// address on either family, a CARP address, and rule as its only filter rule.
func portForwardDevice(rule common.FirewallRule) *common.CommonDevice {
	return &common.CommonDevice{
		System: common.System{WebGUI: common.WebGUI{Protocol: constants.ProtocolHTTPS}},
		Interfaces: []common.Interface{
			{Name: "wan", Enabled: true, IPAddress: "203.0.113.2", IPv6Address: "2001:db8::2"},
			{Name: "lan", Enabled: true, IPAddress: "192.168.1.1"},
		},
		VirtualIPs: []common.VirtualIP{
			{Mode: common.VIPModeCarp, Interface: "lan", Subnet: "192.168.1.254"},
		},
		FirewallRules: []common.FirewallRule{rule},
	}
}

// assertWebGUIExposed runs the red analysis and checks whether it reports the
// firewall's web GUI as WAN-exposed.
func assertWebGUIExposed(t *testing.T, device *common.CommonDevice, want bool) {
	t.Helper()

	report := newRedReport(device)
	runRedAnalysis(report)

	_, exposed := findingByTitlePrefix(report.Findings, "WAN-Exposed Service: Web Administration")
	if exposed != want {
		t.Errorf("web GUI exposed = %v, want %v: %+v", exposed, want, report.Findings)
	}
}

// readFixture returns a config from testdata.
func readFixture(t *testing.T, name string) string {
	t.Helper()

	raw, err := os.ReadFile(filepath.Join("..", "..", "testdata", filepath.FromSlash(name)))
	if err != nil {
		t.Fatal(err)
	}

	return string(raw)
}

// parseConfig converts config, leaving its vendor to the factory to detect.
func parseConfig(t *testing.T, config string) *common.CommonDevice {
	t.Helper()

	device, _, err := parser.NewFactory(cfgparser.NewXMLParser()).CreateDevice(
		context.Background(), strings.NewReader(config), common.DeviceTypeUnknown, false)
	if err != nil {
		t.Fatal(err)
	}

	return device
}

// TestRedMode_PortForwardToAlias_EndToEnd rewrites each vendor's port forward
// fixture to a forward whose target is an alias, with the rule the port forward
// page stores for it: the alias on <address>, no <type> on pfSense and on
// OPNsense up to 24.7, and no link for "Add unassociated filter rule".
func TestRedMode_PortForwardToAlias_EndToEnd(t *testing.T) {
	t.Parallel()

	const (
		pfSenseConfig  = "pfsense/config-pfSense.xml"
		opnSenseConfig = "opnsense-legacy-port-forwards.xml"
		pfSenseLink80  = "<associated-rule-id>nat_5e7bb3b731ebf3.20248323</associated-rule-id>"
		pfSenseLink443 = "<associated-rule-id>nat_5e7bb3f7a503d5.68828728</associated-rule-id>"
		opnSenseLink   = "<associated-rule-id>nat_68dd1c2a4b5c61.23456789</associated-rule-id>"
		noLink         = "<associated-rule-id></associated-rule-id>"
		aliasOpen      = "<aliases><alias><name>WEB_HOST</name><type>host</type><address>"
		aliasClose     = "</address></alias></aliases>"
	)

	pfSenseAlias := func(unlink bool, members string) *strings.Replacer {
		pairs := []string{
			"<target>10.0.2.2</target>", "<target>WEB_HOST</target>",
			"<address>10.0.2.2</address>", "<address>WEB_HOST</address>",
			"<aliases></aliases>", aliasOpen + members + aliasClose,
		}
		if unlink {
			pairs = append(pairs, pfSenseLink80, noLink, pfSenseLink443, noLink)
		}

		return strings.NewReplacer(pairs...)
	}
	opnSenseAlias := func(typed, unlink bool, member string) *strings.Replacer {
		const typeElement = "<type>pass</type>\n      "

		link := opnSenseLink
		if unlink {
			link = noLink
		}

		companion := link
		if typed {
			companion = typeElement + link
		}

		return strings.NewReplacer(
			typeElement+opnSenseLink, companion,
			opnSenseLink, link,
			"<target>192.168.10.50</target>", "<target>MAIL_HOST</target>",
			"<address>192.168.10.50</address>", "<address>MAIL_HOST</address>",
			"<content>192.168.20.25</content>", "<content>"+member+"</content>",
			"<local-port>8443</local-port>", "<local-port>443</local-port>",
			"<port>8443</port>", "<port>443</port>",
		)
	}

	tests := []struct {
		name        string
		fixture     string
		replacer    *strings.Replacer
		wantExposed bool
	}{
		{"pfSense, linked", pfSenseConfig, pfSenseAlias(false, "10.0.2.2"), false},
		{"pfSense, no link", pfSenseConfig, pfSenseAlias(true, "10.0.2.2"), false},
		{"pfSense, a network", pfSenseConfig, pfSenseAlias(false, "10.0.2.2/31"), false},
		{"pfSense, the network of an interface", pfSenseConfig, pfSenseAlias(false, "10.0.2.0/24"), true},
		{"pfSense, holding the LAN address", pfSenseConfig, pfSenseAlias(false, "10.0.2.2 192.168.1.1"), true},
		{"pfSense, no link, holding the LAN address", pfSenseConfig, pfSenseAlias(true, "192.168.1.1"), true},
		{"OPNsense, no type", opnSenseConfig, opnSenseAlias(false, false, "192.168.20.25"), false},
		{"OPNsense, no type, no link", opnSenseConfig, opnSenseAlias(false, true, "192.168.20.25"), false},
		{"OPNsense, type pass, no link", opnSenseConfig, opnSenseAlias(true, true, "192.168.20.25"), false},
		{"OPNsense, holding the DMZ address", opnSenseConfig, opnSenseAlias(false, false, "192.168.20.1"), true},
		{"OPNsense, no link, with the DMZ address", opnSenseConfig, opnSenseAlias(false, true, "192.168.20.1"), true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			device := parseConfig(t, tc.replacer.Replace(readFixture(t, tc.fixture)))
			if !slices.ContainsFunc(device.FirewallRules, func(rule common.FirewallRule) bool {
				return rule.Destination.AddressRef != nil
			}) {
				t.Fatal("the rewritten fixture has no rule to an alias")
			}

			assertWebGUIExposed(t, device, tc.wantExposed)
		})
	}
}

// TestRedMode_PortForwardToNetwork_EndToEnd rewrites the legacy port forward
// fixture to a forward whose target is a literal network. firewall_nat_edit.php
// accepts one (is_subnet) and copies it onto the forward's rule as it stands.
// The web GUI reads as exposed only when the network holds an address of the
// firewall, as the LAN and DMZ networks of this fixture do.
func TestRedMode_PortForwardToNetwork_EndToEnd(t *testing.T) {
	t.Parallel()

	const (
		link  = "<associated-rule-id>nat_68dd1c2a4b5c61.23456789</associated-rule-id>"
		typed = "<type>pass</type>\n      " + link
	)

	raw := readFixture(t, "opnsense-legacy-port-forwards.xml")

	rewrite := func(network string, typeless, unlink bool) string {
		config := raw
		if typeless {
			config = strings.Replace(config, typed, link, 1)
		}

		if unlink {
			config = strings.ReplaceAll(config, link, "<associated-rule-id/>")
		}

		return strings.NewReplacer(
			"<target>192.168.10.50</target>", "<target>"+network+"</target>",
			"<address>192.168.10.50</address>", "<address>"+network+"</address>",
			"<local-port>8443</local-port>", "<local-port>443</local-port>",
			"<port>8443</port>", "<port>443</port>",
		).Replace(config)
	}

	tests := []struct {
		name        string
		network     string
		typeless    bool
		unlink      bool
		wantExposed bool
	}{
		{"no type, linked", "192.168.30.0/24", true, false, false},
		{"no type, no link", "192.168.30.0/24", true, true, false},
		{"type pass, linked", "192.168.30.0/24", false, false, false},
		{"type pass, no link", "192.168.30.0/24", false, true, false},
		{"the DMZ network, no type, linked", "192.168.20.0/24", true, false, true},
		{"the DMZ network, no type, no link", "192.168.20.0/24", true, true, true},
		{"the LAN network, type pass, linked", "192.168.10.0/24", false, false, true},
		{"the LAN network, type pass, no link", "192.168.10.0/24", false, true, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			device := parseConfig(t, rewrite(tc.network, tc.typeless, tc.unlink))
			if !slices.ContainsFunc(device.NAT.InboundRules, func(nat common.InboundNATRule) bool {
				return nat.InternalIP == tc.network
			}) {
				t.Fatal("the rewritten fixture has no forward to the network")
			}

			assertWebGUIExposed(t, device, tc.wantExposed)
		})
	}
}

// TestRedMode_UnassociatedPortForwardRule_EndToEnd rewrites the legacy port
// forward fixture to what "Add unassociated filter rule" leaves in config.xml
// (firewall_nat_edit.php): the forward's rule with no link on either side, with
// no <type> up to 24.7 and with one from 25.1. The forward lands on 443, so the
// rule's port is the web GUI's, and the GUI must not read as WAN-exposed. Moving
// the forward to another host leaves the rule as one of its own, which counts.
func TestRedMode_UnassociatedPortForwardRule_EndToEnd(t *testing.T) {
	t.Parallel()

	raw := readFixture(t, "opnsense-legacy-port-forwards.xml")

	const (
		link   = "<associated-rule-id>nat_68dd1c2a4b5c61.23456789</associated-rule-id>"
		typed  = "<type>pass</type>\n      " + link
		target = "<target>192.168.10.50</target>"
	)

	for _, want := range []string{typed, target} {
		if strings.Count(raw, want) != 1 {
			t.Fatalf("fixture no longer holds %q exactly once", want)
		}
	}

	unassociated := strings.NewReplacer(
		link, "<associated-rule-id/>",
		"<local-port>8443</local-port>", "<local-port>443</local-port>",
		"<port>8443</port>", "<port>443</port>",
	)
	typedConfig := unassociated.Replace(raw)
	typelessConfig := unassociated.Replace(strings.Replace(raw, typed, link, 1))
	movedConfig := strings.Replace(typelessConfig, target, "<target>192.168.10.51</target>", 1)

	tests := []struct {
		name        string
		config      string
		wantExposed bool
	}{
		{"up to 24.7, no type", typelessConfig, false},
		{"25.1 to 25.7, type pass", typedConfig, false},
		{"forward moved to another host", movedConfig, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			assertWebGUIExposed(t, parseConfig(t, tc.config), tc.wantExposed)
		})
	}
}
