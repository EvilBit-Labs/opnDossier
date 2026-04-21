// Package sans — benchmarks and call-count regression tests that lock in the
// single-pass RunChecks contract (see PERF-H1, PERF-H2, TEST-H4).
package sans

import (
	"fmt"
	"testing"

	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
)

// largeDeviceFixture builds a realistic CommonDevice with ruleCount firewall
// rules plus other resources the SANS checks traverse.
func largeDeviceFixture(ruleCount int) *common.CommonDevice {
	rules := make([]common.FirewallRule, ruleCount)
	for i := range rules {
		rules[i] = common.FirewallRule{
			UUID:        fmt.Sprintf("rule-%d", i),
			Type:        common.RuleTypePass,
			Description: fmt.Sprintf("sans benchmark rule %d", i),
			Interfaces:  []string{"wan"},
			Protocol:    "tcp",
			Source:      common.RuleEndpoint{Address: fmt.Sprintf("10.0.%d.0/24", i%256)},
			Destination: common.RuleEndpoint{Address: "192.168.1.10", Port: "443"},
			StateType:   "keep state",
		}
	}

	return &common.CommonDevice{
		System: common.System{
			Hostname: "bench-sans",
			WebGUI:   common.WebGUI{Protocol: "https"},
		},
		Interfaces: []common.Interface{
			{Name: "wan", Enabled: true, BlockPrivate: true, BlockBogons: true},
			{Name: "lan", Enabled: true},
		},
		FirewallRules: rules,
		Sysctl: []common.SysctlItem{
			{Tunable: "net.inet.ip.sourceroute", Value: "0"},
		},
		Syslog: common.SyslogConfig{
			Enabled:       true,
			RemoteServer:  "10.0.0.50",
			SystemLogging: true,
			AuthLogging:   true,
		},
	}
}

// BenchmarkSANSPlugin_RunChecks measures single-pass compliance evaluation.
// Locks in PERF-H1 (single-pass) and PERF-H2 (severityByID O(1) lookup).
func BenchmarkSANSPlugin_RunChecks(b *testing.B) {
	device := largeDeviceFixture(5000)
	sp := NewPlugin()

	b.ReportAllocs()
	b.ResetTimer()

	for b.Loop() {
		_, _, _ = sp.RunChecks(device) //nolint:errcheck // benchmark discards return
	}
}

// BenchmarkSANSPlugin_RunChecks_Small measures overhead on a tiny fixture.
func BenchmarkSANSPlugin_RunChecks_Small(b *testing.B) {
	device := largeDeviceFixture(10)
	sp := NewPlugin()

	b.ReportAllocs()
	b.ResetTimer()

	for b.Loop() {
		_, _, _ = sp.RunChecks(device) //nolint:errcheck // benchmark discards return
	}
}

// BenchmarkSANSPlugin_DoublePassEmulation mimics the historical pre-refactor
// behavior where RunChecks was paired with a separate EvaluatedControlIDs
// call. Comparison with BenchmarkSANSPlugin_RunChecks quantifies the PERF-H1
// improvement.
func BenchmarkSANSPlugin_DoublePassEmulation(b *testing.B) {
	device := largeDeviceFixture(5000)
	sp := NewPlugin()

	b.ReportAllocs()
	b.ResetTimer()

	for b.Loop() {
		_, _, _ = sp.RunChecks(device) //nolint:errcheck // benchmark discards return
		for _, entry := range sp.sansChecks() {
			_ = entry.checkFn(device)
		}
	}
}

// TestSANSPlugin_RunChecksSinglePass_NoDuplicateDispatch is the call-count
// regression for PERF-H1. The single-pass contract requires that each control
// appear in the evaluated slice at most once per RunChecks call. If a future
// change reintroduces a second pass (e.g., re-iterates sansChecks()), every
// control with Known=true will be appended to evaluated twice — this test
// will then detect the duplicate and fail.
//
// An earlier version of this test tried to "count invocations" by iterating
// entry.checkFn in a local loop and asserting counter==1 — that assertion was
// tautological (the test loop itself guaranteed count==1 regardless of what
// RunChecks did). The dup-check on evaluated is the only observable we have,
// without refactoring the plugin to accept an injected/instrumented table,
// that genuinely fails on a double-dispatch regression.
func TestSANSPlugin_RunChecksSinglePass_NoDuplicateDispatch(t *testing.T) {
	t.Parallel()

	sp := NewPlugin()
	device := largeDeviceFixture(50)

	_, evaluated, err := sp.RunChecks(device)
	if err != nil {
		t.Fatalf("unexpected RunChecks error: %v", err)
	}

	if len(evaluated) == 0 {
		t.Fatal("evaluated slice is empty — RunChecks did not evaluate any controls")
	}

	seen := make(map[string]struct{}, len(evaluated))

	for _, id := range evaluated {
		if _, dup := seen[id]; dup {
			t.Errorf("control %s appears more than once in evaluated — indicates double dispatch", id)
		}

		seen[id] = struct{}{}
	}
}

// TestSANSPlugin_RunChecksProducesEvaluatedInOnePass asserts the single-pass
// contract: one RunChecks call returns both findings and a nonempty evaluated
// slice without requiring a separate traversal.
func TestSANSPlugin_RunChecksProducesEvaluatedInOnePass(t *testing.T) {
	t.Parallel()

	sp := NewPlugin()
	device := largeDeviceFixture(100)

	_, evaluated, err := sp.RunChecks(device)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(evaluated) == 0 {
		t.Fatal("evaluated slice is empty — RunChecks contract is violated")
	}
}

// TestSANSPlugin_SeverityByIDMap_PopulatedForEveryControl locks in PERF-H2.
func TestSANSPlugin_SeverityByIDMap_PopulatedForEveryControl(t *testing.T) {
	t.Parallel()

	sp := NewPlugin()
	if len(sp.severityByID) != len(sp.controls) {
		t.Fatalf("severityByID size %d != controls size %d",
			len(sp.severityByID), len(sp.controls))
	}

	for _, c := range sp.controls {
		got, ok := sp.severityByID[c.ID]
		if !ok {
			t.Errorf("severityByID missing entry for %s", c.ID)

			continue
		}

		if got != c.Severity {
			t.Errorf("severityByID[%s] = %q; want %q", c.ID, got, c.Severity)
		}
	}
}
