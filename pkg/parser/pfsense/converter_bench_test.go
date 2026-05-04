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
// intentionally not exercised because (a) it's the cheapest path and
// would not move the regression-detection signal, and (b) correctness
// coverage of the empty branch lives in
// pkg/schema/opnsense/security_test.go.
//
// Note: NAT rule conversion does NOT short-circuit on empty
// EffectiveAddress() — convertOutboundNATRules and convertInboundNATRules
// store RuleEndpoint.Address = "" silently, unlike convertFirewallRules
// which emits an empty-source/empty-destination warning at
// pkg/parser/pfsense/converter_security.go:28,36. The empty branch is
// reachable on the NAT path; we just don't exercise it here.
func generateNATHeavyPfSenseDocument() *pfsenseSchema.Document {
	doc := pfsenseSchema.NewDocument()

	// Reuse a single non-nil pointer for the Any-presence flag so the
	// fixture builder doesn't allocate one *string per rule. SHARED
	// READ-ONLY SENTINEL — do not mutate *anyEmpty; downstream code
	// relies on Source.Any pointer-presence semantics, not value.
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
// exactly. anyPresent must be a non-nil *string; its value is
// irrelevant — only the pointer's non-nil-ness drives Source.IsAny()
// and Destination.IsAny().
func buildPfSenseNATRuleEndpoints(i int, anyPresent *string) (opnsense.Source, opnsense.Destination) {
	switch i % 4 {
	case 0:
		return opnsense.Source{
				Network: fmt.Sprintf("10.%d.0.0/24", i),
				Port:    "1024",
			}, opnsense.Destination{
				Network: fmt.Sprintf("172.16.%d.0/24", i),
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
				Network: fmt.Sprintf("10.%d.1.0/24", i),
				Port:    "53",
			}
	default:
		return opnsense.Source{
				Network: fmt.Sprintf("10.%d.2.0/24", i),
			}, opnsense.Destination{
				Any: anyPresent,
			}
	}
}

// BenchmarkConverter_PfSense_NATHeavy exercises ConvertDocument against
// a fixture loaded only with NAT (200 outbound + 200 inbound rules),
// covering three of the four EffectiveAddress() resolution branches
// (Network, Address, IsAny). The pfSense converter populates each
// endpoint's resolved address into common.RuleEndpoint.Address with a
// single EffectiveAddress() call per endpoint per rule (see
// convertOutboundNATRules / convertInboundNATRules in
// converter_security.go); this benchmark locks in that characteristic
// so a future regression that reintroduced redundant calls per
// endpoint would surface as a measurable slowdown.
//
// pfSense's allocs/op runs higher than OPNsense's because every
// ConvertDocument invocation emits the always-on pfsenseKnownGaps
// warning slice (one entry per known gap, ~18 entries). That
// allocation cost is per-invocation, NOT per-NAT-rule, so a regression
// in NAT conversion would still show as a clean delta against this
// constant baseline.
//
// Run: go test -bench=BenchmarkConverter_PfSense_NATHeavy -benchmem -count=3 -run=^$ ./pkg/parser/pfsense/
//
// Refs: NATS-36, GH#288, NATS-103 perf epic.
func BenchmarkConverter_PfSense_NATHeavy(b *testing.B) {
	doc := generateNATHeavyPfSenseDocument()

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
	// Spot-check that EffectiveAddress() priority resolution matches
	// the fixture rotation. A regression that swapped Network/Address
	// priority would pass the length checks above but produce wrong
	// addresses here. Index 0 uses case 0 (Network priority).
	if got, want := device.NAT.OutboundRules[0].Source.Address, "10.0.0.0/24"; got != want {
		b.Fatalf("OutboundRules[0].Source.Address: got %q, want %q (priority resolution regressed)", got, want)
	}

	// runtime.GC() before ResetTimer pushes the heap into a known-clean
	// state so per-iteration allocation jitter doesn't dominate the
	// observed variance band.
	b.ReportAllocs()
	runtime.GC()
	b.ResetTimer()

	for b.Loop() {
		_, _, err := pfsense.ConvertDocument(doc)
		if err != nil {
			b.Fatal(err)
		}
	}
}
