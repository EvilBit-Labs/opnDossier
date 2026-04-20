// Package firewall — benchmarks and call-count regression tests that lock in
// the single-pass RunChecks contract established when the separate
// EvaluatedControlIDs method was removed. See PERF-H1/H2 and TEST-H4.
package firewall

import (
	"fmt"
	"testing"

	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
)

// largeDeviceFixture builds a CommonDevice populated with ruleCount firewall
// rules plus a representative set of other resources so every check in the
// plugin has non-trivial data to traverse. The fixture is deterministic and
// stable across runs.
func largeDeviceFixture(ruleCount int) *common.CommonDevice {
	const blockRuleCount = 10

	rules := make([]common.FirewallRule, 0, ruleCount+blockRuleCount)
	for i := range ruleCount {
		rules = append(rules, common.FirewallRule{
			UUID:        fmt.Sprintf("rule-%d", i),
			Type:        common.RuleTypePass,
			Description: fmt.Sprintf("benchmark rule %d", i),
			Interfaces:  []string{"wan"},
			Protocol:    "tcp",
			Source:      common.RuleEndpoint{Address: fmt.Sprintf("10.0.%d.0/24", i%256)},
			Destination: common.RuleEndpoint{Address: "192.168.1.10", Port: "443"},
			StateType:   "keep state",
		})
	}

	// Add a handful of block rules to exercise default-deny detection.
	for range blockRuleCount {
		rules = append(rules, common.FirewallRule{
			Type:        common.RuleTypeBlock,
			Source:      common.RuleEndpoint{Address: "any"},
			Destination: common.RuleEndpoint{Address: "any"},
		})
	}

	return &common.CommonDevice{
		System: common.System{
			Hostname:   "bench-fw",
			WebGUI:     common.WebGUI{Protocol: "https", SSLCertRef: "cert-1"},
			DNSServers: []string{"8.8.8.8", "1.1.1.1"},
		},
		Interfaces: []common.Interface{
			{Name: "wan", Enabled: true, BlockPrivate: true, BlockBogons: true},
			{Name: "lan", Enabled: true},
		},
		FirewallRules: rules,
		Sysctl: []common.SysctlItem{
			{Tunable: "net.inet.ip.sourceroute", Value: "0"},
			{Tunable: "net.inet.tcp.syncookies", Value: "1"},
		},
		Users: []common.User{
			{Name: "operator", Disabled: false},
		},
		Syslog: common.SyslogConfig{
			Enabled:       true,
			RemoteServer:  "10.0.0.50",
			SystemLogging: true,
			AuthLogging:   true,
		},
	}
}

// BenchmarkFirewallPlugin_RunChecks measures the full single-pass compliance
// evaluation over a realistic device. Locks in the improvement from
// PERF-H1 (single-pass RunChecks) and PERF-H2 (severityByID O(1) lookup).
//
// Historical baseline (pre-refactor): RunChecks + EvaluatedControlIDs ran the
// dispatch table twice, doubling wall-clock time on large fixtures.
func BenchmarkFirewallPlugin_RunChecks(b *testing.B) {
	device := largeDeviceFixture(5000)
	fp := NewPlugin()

	b.ReportAllocs()
	b.ResetTimer()

	for b.Loop() {
		_, _, _ = fp.RunChecks(device) //nolint:errcheck // benchmark discards return
	}
}

// BenchmarkFirewallPlugin_RunChecks_Small measures overhead on a tiny fixture
// where allocation and dispatch cost dominate — useful for catching
// regressions that don't show up at scale.
func BenchmarkFirewallPlugin_RunChecks_Small(b *testing.B) {
	device := largeDeviceFixture(10)
	fp := NewPlugin()

	b.ReportAllocs()
	b.ResetTimer()

	for b.Loop() {
		_, _, _ = fp.RunChecks(device) //nolint:errcheck // benchmark discards return
	}
}

// BenchmarkFirewallPlugin_DoublePassEmulation mimics the historical
// pre-refactor behavior where RunChecks was paired with a separate
// EvaluatedControlIDs call that re-ran every check. The comparison against
// BenchmarkFirewallPlugin_RunChecks quantifies the PERF-H1 improvement
// (single-pass compliance evaluation).
func BenchmarkFirewallPlugin_DoublePassEmulation(b *testing.B) {
	device := largeDeviceFixture(5000)
	fp := NewPlugin()

	b.ReportAllocs()
	b.ResetTimer()

	for b.Loop() {
		_, _, _ = fp.RunChecks(device) //nolint:errcheck // benchmark discards return
		// Simulate old EvaluatedControlIDs by re-running every checkFn once.
		for _, entry := range fp.newChecksTable() {
			_ = entry.checkFn(fp, device)
		}
	}
}

// TestFirewallPlugin_RunChecksSinglePass_NoDuplicateDispatch is the call-count
// regression for PERF-H1. The single-pass contract requires that each control
// appear in the evaluated slice at most once per RunChecks call. If a future
// change reintroduces a second pass (e.g., re-adds EvaluatedControlIDs and
// calls it from RunChecks, or iterates the dispatch table twice), every
// control with Known=true will be appended to evaluated twice — this test
// will then detect the duplicate and fail.
//
// An earlier version of this test tried to "count invocations" by iterating
// entry.checkFn in a local loop and asserting counter==1 — that assertion was
// tautological (the test loop itself guaranteed count==1 regardless of what
// RunChecks did). The dup-check on evaluated is the only observable we have,
// without refactoring the plugin to accept an injected/instrumented table,
// that genuinely fails on a double-dispatch regression.
func TestFirewallPlugin_RunChecksSinglePass_NoDuplicateDispatch(t *testing.T) {
	t.Parallel()

	fp := NewPlugin()
	device := largeDeviceFixture(50)

	_, evaluated, err := fp.RunChecks(device)
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

// TestFirewallPlugin_RunChecksProducesEvaluatedInOnePass asserts the contract
// that RunChecks returns a nonempty evaluated slice in the same call that
// produced findings. If this test fails, the caller is likely still trying to
// invoke a separate EvaluatedControlIDs method — which no longer exists on
// the interface.
func TestFirewallPlugin_RunChecksProducesEvaluatedInOnePass(t *testing.T) {
	t.Parallel()

	fp := NewPlugin()
	device := largeDeviceFixture(100)

	findings, evaluated, err := fp.RunChecks(device)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(evaluated) == 0 {
		t.Fatal("evaluated slice is empty — RunChecks contract is violated")
	}

	// At least one finding is expected on the benchmark fixture (DoS rate
	// limiting, undocumented port forwards, etc.). Zero findings suggests
	// checks are not running.
	if len(findings) == 0 {
		t.Fatal("findings slice is empty — checks did not execute")
	}
}

// TestFirewallPlugin_SeverityByIDMap_PopulatedForEveryControl locks in the
// PERF-H2 invariant: NewPlugin must populate severityByID for every control,
// so controlSeverity is always O(1). If a future change adds a control
// without registering it in the map, this test will fail.
func TestFirewallPlugin_SeverityByIDMap_PopulatedForEveryControl(t *testing.T) {
	t.Parallel()

	fp := NewPlugin()
	if len(fp.severityByID) != len(fp.controls) {
		t.Fatalf("severityByID size %d != controls size %d — map is missing entries",
			len(fp.severityByID), len(fp.controls))
	}

	for _, c := range fp.controls {
		got, ok := fp.severityByID[c.ID]
		if !ok {
			t.Errorf("severityByID missing entry for control %s", c.ID)

			continue
		}

		if got != c.Severity {
			t.Errorf("severityByID[%s] = %q; want %q", c.ID, got, c.Severity)
		}
	}
}
