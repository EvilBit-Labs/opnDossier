package opnsense_test

import (
	"fmt"
	"testing"

	"github.com/EvilBit-Labs/opnDossier/pkg/parser/opnsense"
	schema "github.com/EvilBit-Labs/opnDossier/pkg/schema/opnsense"
	"github.com/stretchr/testify/require"
)

// natHeavyRuleCount is the per-direction rule count for the NAT-heavy
// conversion benchmark. Chosen to comfortably exceed the "100+ rules"
// threshold the originating ticket (NATS-36 / GH#288) cites as the
// regime where redundant EffectiveAddress() calls would matter at
// runtime, so a future regression that reintroduced redundant calls
// would surface as a measurable slowdown in this benchmark.
const natHeavyRuleCount = 200

// generateNATHeavyOPNsenseDocument returns an *schema.OpnSenseDocument
// with only NAT populated — natHeavyRuleCount outbound rules and the
// same number of inbound rules, with Source/Destination shapes rotated
// across every branch of EffectiveAddress() (Network > Address > IsAny
// > empty) so the benchmark exercises each priority-resolution path.
func generateNATHeavyOPNsenseDocument(b *testing.B) *schema.OpnSenseDocument {
	b.Helper()

	doc := schema.NewOpnSenseDocument()

	// Reuse a non-nil pointer for the Any-presence flag without leaking
	// a per-rule allocation into the loop body.
	anyEmpty := ""

	outbound := make([]schema.NATRule, 0, natHeavyRuleCount)
	for i := range natHeavyRuleCount {
		src, dst := buildNATRuleEndpoints(i, &anyEmpty)
		outbound = append(outbound, schema.NATRule{
			UUID:        fmt.Sprintf("out-%04d", i),
			Interface:   schema.InterfaceList{"wan"},
			IPProtocol:  "inet",
			Protocol:    "tcp",
			Source:      src,
			Destination: dst,
			Target:      "10.0.0.1",
			Descr:       fmt.Sprintf("outbound rule %d", i),
		})
	}
	doc.Nat.Outbound.Rule = outbound

	inbound := make([]schema.InboundRule, 0, natHeavyRuleCount)
	for i := range natHeavyRuleCount {
		src, dst := buildNATRuleEndpoints(i, &anyEmpty)
		inbound = append(inbound, schema.InboundRule{
			UUID:         fmt.Sprintf("in-%04d", i),
			Interface:    schema.InterfaceList{"wan"},
			IPProtocol:   "inet",
			Protocol:     "tcp",
			Source:       src,
			Destination:  dst,
			InternalIP:   "192.168.1.10",
			InternalPort: "80",
			Descr:        fmt.Sprintf("inbound rule %d", i),
		})
	}
	doc.Nat.Inbound = inbound

	return doc
}

// buildNATRuleEndpoints rotates Source and Destination across the four
// EffectiveAddress() resolution branches so the benchmark sees each
// priority path under load.
func buildNATRuleEndpoints(i int, anyPresent *string) (schema.Source, schema.Destination) {
	switch i % 4 {
	case 0:
		return schema.Source{
				Network: fmt.Sprintf("10.%d.0.0/24", i%256),
				Port:    "1024",
			}, schema.Destination{
				Network: fmt.Sprintf("172.16.%d.0/24", i%256),
				Port:    "443",
			}
	case 1:
		return schema.Source{
				Address: fmt.Sprintf("203.0.113.%d", i%256),
				Port:    "32768",
			}, schema.Destination{
				Address: fmt.Sprintf("198.51.100.%d", i%256),
				Port:    "80",
			}
	case 2:
		return schema.Source{
				Any: anyPresent,
			}, schema.Destination{
				Network: fmt.Sprintf("10.%d.1.0/24", i%256),
				Port:    "53",
			}
	default:
		return schema.Source{
				Network: fmt.Sprintf("10.%d.2.0/24", i%256),
			}, schema.Destination{
				Any: anyPresent,
			}
	}
}

// BenchmarkConverter_OPNsense_NATHeavy exercises ConvertDocument against
// a fixture loaded only with NAT (200 outbound + 200 inbound rules),
// covering every EffectiveAddress() resolution branch. The OPNsense
// converter caches each endpoint's resolved address into
// common.RuleEndpoint.Address during conversion (single
// EffectiveAddress() call per endpoint per rule); this benchmark locks
// in that characteristic so a future regression that reintroduced
// redundant calls would surface as a measurable slowdown.
//
// Run: go test -bench=BenchmarkConverter_OPNsense_NATHeavy -benchmem -count=3 -run=^$ ./pkg/parser/opnsense/
//
// See plan: docs/plans/2026-05-03-002-perf-nat-effectiveaddress-bench-plan.md
// Refs: NATS-36, GH#288, NATS-103 perf epic.
func BenchmarkConverter_OPNsense_NATHeavy(b *testing.B) {
	doc := generateNATHeavyOPNsenseDocument(b)

	b.ReportAllocs()
	b.ResetTimer()

	for b.Loop() {
		device, _, err := opnsense.ConvertDocument(doc)
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
