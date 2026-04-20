// Package stig — benchmarks and call-count regression tests that lock in the
// single-pass RunChecks contract (see PERF-H1, PERF-H2, TEST-H4).
package stig

import (
	"fmt"
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/constants"
	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
)

// largeDeviceFixture builds a CommonDevice with ruleCount firewall rules and
// the services STIG checks inspect.
func largeDeviceFixture(ruleCount int) *common.CommonDevice {
	rules := make([]common.FirewallRule, 0, ruleCount+1)
	for i := range ruleCount {
		rules = append(rules, common.FirewallRule{
			UUID:        fmt.Sprintf("rule-%d", i),
			Type:        common.RuleTypePass,
			Description: fmt.Sprintf("stig benchmark rule %d", i),
			Interfaces:  []string{"wan"},
			Protocol:    "tcp",
			Source:      common.RuleEndpoint{Address: fmt.Sprintf("10.0.%d.0/24", i%256)},
			Destination: common.RuleEndpoint{Address: "192.168.1.10", Port: "443"},
			StateType:   "keep state",
		})
	}
	// Add one block rule to exercise default-deny detection.
	rules = append(rules, common.FirewallRule{
		Type:        common.RuleTypeBlock,
		Source:      common.RuleEndpoint{Address: constants.NetworkAny},
		Destination: common.RuleEndpoint{Address: constants.NetworkAny},
	})

	return &common.CommonDevice{
		System:        common.System{Hostname: "bench-stig"},
		FirewallRules: rules,
		Syslog: common.SyslogConfig{
			Enabled:       true,
			RemoteServer:  "10.0.0.50",
			SystemLogging: true,
			AuthLogging:   true,
		},
		IDS: &common.IDSConfig{Enabled: true},
	}
}

// BenchmarkSTIGPlugin_RunChecks measures single-pass compliance evaluation on
// a realistic device fixture.
func BenchmarkSTIGPlugin_RunChecks(b *testing.B) {
	device := largeDeviceFixture(5000)
	sp := NewPlugin()

	b.ReportAllocs()
	b.ResetTimer()

	for b.Loop() {
		_, _, _ = sp.RunChecks(device) //nolint:errcheck // benchmark discards return
	}
}

// BenchmarkSTIGPlugin_RunChecks_Small measures overhead on a tiny fixture.
func BenchmarkSTIGPlugin_RunChecks_Small(b *testing.B) {
	device := largeDeviceFixture(10)
	sp := NewPlugin()

	b.ReportAllocs()
	b.ResetTimer()

	for b.Loop() {
		_, _, _ = sp.RunChecks(device) //nolint:errcheck // benchmark discards return
	}
}

// BenchmarkSTIGPlugin_DoublePassEmulation mimics the pre-refactor behavior
// where RunChecks was paired with a separate EvaluatedControlIDs traversal.
// Comparison with BenchmarkSTIGPlugin_RunChecks quantifies the PERF-H1
// improvement. STIG's former EvaluatedControlIDs was O(len(controls))
// regardless of device; most of the cost was in the RunChecks helpers.
func BenchmarkSTIGPlugin_DoublePassEmulation(b *testing.B) {
	device := largeDeviceFixture(5000)
	sp := NewPlugin()

	b.ReportAllocs()
	b.ResetTimer()

	for b.Loop() {
		_, _, _ = sp.RunChecks(device) //nolint:errcheck // benchmark discards return
		// Emulate the old EvaluatedControlIDs linear scan.
		for _, c := range sp.controls {
			_ = c.ID
		}
	}
}

// TestSTIGPlugin_RunChecksSinglePass_NoDuplicateEvaluated is the call-count
// regression. After one RunChecks call, no control ID may appear twice in the
// evaluated slice — duplicates would indicate a reintroduced second pass.
func TestSTIGPlugin_RunChecksSinglePass_NoDuplicateEvaluated(t *testing.T) {
	t.Parallel()

	sp := NewPlugin()
	device := largeDeviceFixture(50)

	_, evaluated, err := sp.RunChecks(device)
	if err != nil {
		t.Fatalf("unexpected RunChecks error: %v", err)
	}

	// STIG evaluates every control unconditionally — so evaluated must exactly
	// match len(controls). A mismatch indicates either a regression in the
	// single-pass evaluator or an unintended change to control coverage.
	if len(evaluated) != len(sp.controls) {
		t.Errorf("evaluated len = %d, want %d (controls)",
			len(evaluated), len(sp.controls))
	}

	seen := make(map[string]struct{}, len(evaluated))

	for _, id := range evaluated {
		if _, dup := seen[id]; dup {
			t.Errorf("control %s appears more than once in evaluated", id)
		}

		seen[id] = struct{}{}
	}
}

// TestSTIGPlugin_RunChecksProducesEvaluatedInOnePass asserts the contract
// that RunChecks returns both findings and evaluated in a single call.
func TestSTIGPlugin_RunChecksProducesEvaluatedInOnePass(t *testing.T) {
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

// TestSTIGPlugin_SeverityByIDMap_PopulatedForEveryControl locks in PERF-H2.
func TestSTIGPlugin_SeverityByIDMap_PopulatedForEveryControl(t *testing.T) {
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
