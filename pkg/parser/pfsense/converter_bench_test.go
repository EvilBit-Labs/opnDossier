package pfsense_test

import (
	"fmt"
	"runtime"
	"testing"

	"github.com/EvilBit-Labs/opnDossier/pkg/parser/pfsense"
	opnsense "github.com/EvilBit-Labs/opnDossier/pkg/schema/opnsense"
	pfsenseSchema "github.com/EvilBit-Labs/opnDossier/pkg/schema/pfsense"
)

// natHeavyRuleCount is the per-direction rule count for the NAT-heavy
// conversion benchmark. Chosen to comfortably exceed the "100+ rules"
// threshold the originating ticket (NATS-36 / GH#288) cites as the
// regime where redundant EffectiveAddress() calls would matter at
// runtime, so a future regression that reintroduced redundant calls
// would surface as a measurable slowdown in this benchmark.
//
// Keep in sync with the sibling const in
// pkg/parser/opnsense/converter_bench_test.go so OPNsense and pfSense
// regression baselines stay directly comparable.
const natHeavyRuleCount = 200

// generateNATHeavyPfSenseDocument returns a *pfsenseSchema.Document
// with only NAT populated — natHeavyRuleCount outbound rules
// (opnsense.NATRule, since pfSense reuses the OPNsense outbound type)
// and the same number of pfsense.InboundRule entries. Source/Destination
// shapes rotate across three of the four EffectiveAddress() branches
// (Network, Address, IsAny). The empty-fallthrough branch is
// intentionally not exercised because the converter's empty-check
// guard would short-circuit those rules; correctness coverage of the
// empty branch lives in pkg/schema/opnsense/security_test.go.
func generateNATHeavyPfSenseDocument(b *testing.B) *pfsenseSchema.Document {
	b.Helper()

	doc := pfsenseSchema.NewDocument()

	// Reuse a non-nil pointer for the Any-presence flag without leaking
	// a per-rule allocation into the loop body.
	anyEmpty := ""

	outbound := make([]opnsense.NATRule, 0, natHeavyRuleCount)
	for i := range natHeavyRuleCount {
		src, dst := buildPfSenseNATRuleEndpoints(i, &anyEmpty)
		outbound = append(outbound, opnsense.NATRule{
			UUID:        fmt.Sprintf("out-%04d", i),
			Interface:   opnsense.InterfaceList{"wan"},
			IPProtocol:  "inet",
			Protocol:    "tcp",
			Source:      src,
			Destination: dst,
			Target:      "10.0.0.1",
			Descr:       fmt.Sprintf("outbound rule %d", i),
		})
	}
	doc.Nat.Outbound.Rule = outbound

	inbound := make([]pfsenseSchema.InboundRule, 0, natHeavyRuleCount)
	for i := range natHeavyRuleCount {
		src, dst := buildPfSenseNATRuleEndpoints(i, &anyEmpty)
		inbound = append(inbound, pfsenseSchema.InboundRule{
			UUID:         fmt.Sprintf("in-%04d", i),
			Interface:    opnsense.InterfaceList{"wan"},
			IPProtocol:   "inet",
			Protocol:     "tcp",
			Source:       src,
			Destination:  dst,
			Target:       "192.168.1.10",
			InternalPort: "80",
			Descr:        fmt.Sprintf("inbound rule %d", i),
		})
	}
	doc.Nat.Inbound = inbound

	return doc
}

// buildPfSenseNATRuleEndpoints rotates Source and Destination across
// three of the four EffectiveAddress() resolution branches (Network,
// Address, IsAny) so the benchmark sees each non-empty priority path
// under load. pfSense Source/Destination types are reused from the
// opnsense schema package, so the shape mirrors the OPNsense benchmark
// exactly.
func buildPfSenseNATRuleEndpoints(i int, anyPresent *string) (opnsense.Source, opnsense.Destination) {
	switch i % 4 {
	case 0:
		return opnsense.Source{
				Network: fmt.Sprintf("10.%d.0.0/24", i%256),
				Port:    "1024",
			}, opnsense.Destination{
				Network: fmt.Sprintf("172.16.%d.0/24", i%256),
				Port:    "443",
			}
	case 1:
		return opnsense.Source{
				Address: fmt.Sprintf("203.0.113.%d", i%256),
				Port:    "32768",
			}, opnsense.Destination{
				Address: fmt.Sprintf("198.51.100.%d", i%256),
				Port:    "80",
			}
	case 2:
		return opnsense.Source{
				Any: anyPresent,
			}, opnsense.Destination{
				Network: fmt.Sprintf("10.%d.1.0/24", i%256),
				Port:    "53",
			}
	default:
		return opnsense.Source{
				Network: fmt.Sprintf("10.%d.2.0/24", i%256),
			}, opnsense.Destination{
				Any: anyPresent,
			}
	}
}

// BenchmarkConverter_PfSense_NATHeavy exercises ConvertDocument against
// a fixture loaded only with NAT (200 outbound + 200 inbound rules),
// covering three of the four EffectiveAddress() resolution branches
// (Network, Address, IsAny). The pfSense converter caches each
// endpoint's resolved address into common.RuleEndpoint.Address during
// conversion (single EffectiveAddress() call per endpoint per rule);
// this benchmark locks in that characteristic so a future regression
// that reintroduced redundant calls would surface as a measurable
// slowdown.
//
// Run: go test -bench=BenchmarkConverter_PfSense_NATHeavy -benchmem -count=3 -run=^$ ./pkg/parser/pfsense/
//
// Refs: NATS-36, GH#288, NATS-103 perf epic.
func BenchmarkConverter_PfSense_NATHeavy(b *testing.B) {
	doc := generateNATHeavyPfSenseDocument(b)

	// Sanity-check the conversion shape ONCE before timing starts so a
	// regression that silently dropped NAT rules wouldn't show as a
	// "fast" run. Doing this inside the timed loop would inflate
	// allocs/op via testify's reflect path and ns/op via the assertion
	// overhead, contaminating the regression-detection signal.
	device, _, err := pfsense.ConvertDocument(doc)
	if err != nil {
		b.Fatal(err)
	}
	if device == nil {
		b.Fatal("device is nil")
	}
	if got := len(device.NAT.OutboundRules); got != natHeavyRuleCount {
		b.Fatalf("OutboundRules: got %d, want %d", got, natHeavyRuleCount)
	}
	if got := len(device.NAT.InboundRules); got != natHeavyRuleCount {
		b.Fatalf("InboundRules: got %d, want %d", got, natHeavyRuleCount)
	}

	// runtime.GC() before ResetTimer pushes the heap into a known-clean
	// state so per-iteration allocation jitter doesn't dominate the
	// observed variance band. SetBytes normalizes throughput to MB/s
	// across iterations, which is more stable across runs than ns/op
	// alone for regression comparison.
	b.ReportAllocs()
	b.SetBytes(int64(natHeavyRuleCount) * 2)
	runtime.GC()
	b.ResetTimer()

	for b.Loop() {
		_, _, err := pfsense.ConvertDocument(doc)
		if err != nil {
			b.Fatal(err)
		}
	}
}
