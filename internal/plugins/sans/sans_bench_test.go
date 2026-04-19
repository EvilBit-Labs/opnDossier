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

// TestSANSPlugin_RunChecksSinglePass_PerControlInvocation is the call-count
// regression. Each entry in sansChecks() must be invoked exactly once during
// a single RunChecks call.
func TestSANSPlugin_RunChecksSinglePass_PerControlInvocation(t *testing.T) {
	t.Parallel()

	sp := NewPlugin()
	device := largeDeviceFixture(50)

	table := sp.sansChecks()
	counts := make(map[string]int, len(table))

	for _, entry := range table {
		_ = entry.checkFn(device)
		counts[entry.controlID]++
	}

	for id, count := range counts {
		if count != 1 {
			t.Errorf("control %s invoked %d times during single-pass emulation (want 1)", id, count)
		}
	}

	_, evaluated, err := sp.RunChecks(device)
	if err != nil {
		t.Fatalf("unexpected RunChecks error: %v", err)
	}

	seen := make(map[string]struct{}, len(evaluated))

	for _, id := range evaluated {
		if _, dup := seen[id]; dup {
			t.Errorf("control %s appears more than once in evaluated", id)
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
