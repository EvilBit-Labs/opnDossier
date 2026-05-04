package pfsense_test

import (
	"fmt"
	"testing"

	"github.com/EvilBit-Labs/opnDossier/pkg/parser/pfsense"
	opnsense "github.com/EvilBit-Labs/opnDossier/pkg/schema/opnsense"
	pfsenseSchema "github.com/EvilBit-Labs/opnDossier/pkg/schema/pfsense"
	"github.com/stretchr/testify/require"
)

// natHeavyRuleCount is the per-direction rule count for the NAT-heavy
// conversion benchmark. Chosen to comfortably exceed the "100+ rules"
// threshold the originating ticket (NATS-36 / GH#288) cites as the
// regime where redundant EffectiveAddress() calls would matter at
// runtime, so a future regression that reintroduced redundant calls
// would surface as a measurable slowdown in this benchmark.
const natHeavyRuleCount = 200

// generateNATHeavyPfSenseDocument returns a *pfsenseSchema.Document
// with only NAT populated — natHeavyRuleCount outbound rules
// (opnsense.NATRule, since pfSense reuses the OPNsense outbound type)
// and the same number of pfsense.InboundRule entries. Source/Destination
// shapes rotate across every branch of EffectiveAddress() so the
// benchmark exercises each priority-resolution path.
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
// the four EffectiveAddress() resolution branches so the benchmark
// sees each priority path under load. pfSense Source/Destination types
// are reused from the opnsense schema package, so the shape mirrors
// the OPNsense benchmark exactly.
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
// covering every EffectiveAddress() resolution branch. The pfSense
// converter caches each endpoint's resolved address into
// common.RuleEndpoint.Address during conversion (single
// EffectiveAddress() call per endpoint per rule); this benchmark locks
// in that characteristic so a future regression that reintroduced
// redundant calls would surface as a measurable slowdown.
//
// Run: go test -bench=BenchmarkConverter_PfSense_NATHeavy -benchmem -count=3 -run=^$ ./pkg/parser/pfsense/
//
// See plan: docs/plans/2026-05-03-002-perf-nat-effectiveaddress-bench-plan.md
// Refs: NATS-36, GH#288, NATS-103 perf epic.
func BenchmarkConverter_PfSense_NATHeavy(b *testing.B) {
	doc := generateNATHeavyPfSenseDocument(b)

	b.ReportAllocs()
	b.ResetTimer()

	for b.Loop() {
		device, _, err := pfsense.ConvertDocument(doc)
		if err != nil {
			b.Fatal(err)
		}
		// Sanity-check the conversion produced the expected shape so a
		// regression that silently dropped NAT rules wouldn't show as a
		// "fast" run.
		if device == nil {
			b.Fatal("device is nil")
		}
		require.Len(b, device.NAT.OutboundRules, natHeavyRuleCount)
		require.Len(b, device.NAT.InboundRules, natHeavyRuleCount)
	}
}
