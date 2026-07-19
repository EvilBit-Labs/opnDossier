package audit

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/analysis"
	"github.com/EvilBit-Labs/opnDossier/internal/constants"
	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
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
