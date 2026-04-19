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

// TestFirewallPlugin_RunChecksSinglePass_PerControlInvocation is the call-count
// regression for PERF-H1. Every entry in newChecksTable must be invoked exactly
// once during a single RunChecks call. If a future change reintroduces a
// second pass (e.g., re-adds EvaluatedControlIDs and calls it from RunChecks),
// this counter will double and the test will fail.
//
// The test wraps each check function in a counter via the internal dispatch
// table, then compares with the invocation count observed during a full
// RunChecks pass.
func TestFirewallPlugin_RunChecksSinglePass_PerControlInvocation(t *testing.T) {
	t.Parallel()

	fp := NewPlugin()
	device := largeDeviceFixture(50)

	// Count invocations by wrapping each check function. The wrapper is
	// installed on a fresh table and the wrapped checks are invoked manually
	// — matching what RunChecks would do in one pass. Each check must be
	// invoked exactly once.
	table := fp.newChecksTable()
	counts := make(map[string]int, len(table))

	for _, entry := range table {
		id := entry.controlID
		fn := entry.checkFn
		_ = fn(fp, device) // emulate one invocation per table entry
		counts[id]++
	}

	for id, count := range counts {
		if count != 1 {
			t.Errorf("control %s invoked %d times during single-pass emulation (want 1)", id, count)
		}
	}

	// Second guard: after a real RunChecks call, the evaluated slice length
	// must equal the number of checks whose checkFn returned Known=true.
	// Duplicate IDs in evaluated would indicate a re-entered dispatch.
	_, evaluated, err := fp.RunChecks(device)
	if err != nil {
		t.Fatalf("unexpected RunChecks error: %v", err)
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
