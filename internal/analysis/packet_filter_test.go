package analysis_test

import (
	"slices"
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/analysis"
	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
)

// packetFilterDevice returns a device with a WAN that blocks private and bogon
// networks, an HTTPS GUI and one rule, so that every input the packet filter
// setting changes is present. Only PacketFilterDisabled differs between calls.
func packetFilterDevice(disabled bool) *common.CommonDevice {
	return &common.CommonDevice{
		System: common.System{
			WebGUI:               common.WebGUI{Protocol: "https"},
			PacketFilterDisabled: disabled,
		},
		Interfaces: []common.Interface{
			{Name: "lan", Enabled: true},
			{Name: "wan", Enabled: true, BlockPrivate: true, BlockBogons: true},
		},
		FirewallRules: []common.FirewallRule{
			{Type: common.RuleTypePass, Interfaces: []string{"lan"}, Source: common.RuleEndpoint{Address: "lan"}},
		},
	}
}

// TestDetectSecurityIssues_PacketFilterDisabled checks that a firewall with pf
// off gets a critical finding, and that the shared engine tags it WAN-reachable
// so red mode reports it as an exposure.
func TestDetectSecurityIssues_PacketFilterDisabled(t *testing.T) {
	t.Parallel()

	for _, disabled := range []bool{false, true} {
		findings := analysis.DetectSecurityIssues(packetFilterDevice(disabled))

		idx := slices.IndexFunc(findings, func(f common.SecurityFinding) bool {
			return f.Component == analysis.PacketFilterDisabledComponent
		})
		if (idx >= 0) != disabled {
			t.Fatalf("disabled=%v: finding present = %v: %+v", disabled, idx >= 0, findings)
		}

		if disabled && findings[idx].Severity != common.SeverityCritical {
			t.Errorf("severity = %q, want critical", findings[idx].Severity)
		}

		observations := analysis.ScanObservations(packetFilterDevice(disabled))

		obs := slices.IndexFunc(observations, func(o analysis.Observation) bool {
			return o.Component == analysis.PacketFilterDisabledComponent
		})
		if (obs >= 0) != disabled {
			t.Fatalf("disabled=%v: observation present = %v", disabled, obs >= 0)
		}

		if disabled && observations[obs].Reachability != analysis.WANReachable {
			t.Errorf("reachability = %q, want %q", observations[obs].Reachability, analysis.WANReachable)
		}
	}
}

// TestComputeStatistics_PacketFilterDisabled checks that the block options pf
// enforces and the credit for loaded rules are withdrawn when pf is off, and
// that nothing else in the feature list changes.
func TestComputeStatistics_PacketFilterDisabled(t *testing.T) {
	t.Parallel()

	on := analysis.ComputeStatistics(packetFilterDevice(false))
	off := analysis.ComputeStatistics(packetFilterDevice(true))

	wantOn := []string{"Block Bogon Networks", "Block Private Networks", "HTTPS Web GUI"}
	if !slices.Equal(on.SecurityFeatures, wantOn) {
		t.Fatalf("filtering on: features = %v, want %v", on.SecurityFeatures, wantOn)
	}

	if want := []string{"HTTPS Web GUI"}; !slices.Equal(off.SecurityFeatures, want) {
		t.Errorf("filtering off: features = %v, want %v", off.SecurityFeatures, want)
	}

	if off.Summary.SecurityScore >= on.Summary.SecurityScore {
		t.Errorf("score with filtering off = %d, want below %d", off.Summary.SecurityScore, on.Summary.SecurityScore)
	}

	// The device above scores only for its HTTPS GUI once the loaded-rule
	// credit is withdrawn; a bare device with one rule scores nothing.
	bare := &common.CommonDevice{System: common.System{PacketFilterDisabled: true}}
	if got := analysis.ComputeSecurityScore(bare, &common.Statistics{TotalFirewallRules: 1}); got != 0 {
		t.Errorf("loaded-rule credit with filtering off = %d, want 0", got)
	}
}
