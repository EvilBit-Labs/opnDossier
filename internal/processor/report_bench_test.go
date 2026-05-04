// Benchmarks for processor.Report construction.
//
// BenchmarkNewReport pins the empty-report allocation cost so a future
// contributor does not re-introduce per-severity capacity hints on the
// Findings slices.
//
// History: NATS-38 considered hints of 4/8/16/32/16 to amortize early
// AddFinding appends. Bench measurement showed the opposite — make([]T,
// 0) is a zero-allocation zero-cap slice in Go, while make([]T, 0, N)
// forces an N*sizeof(Finding) heap allocation up front. Pre-sizing 76
// finding slots eagerly cost 6 allocs/op + 14688 B/op vs the
// no-capacity baseline of 1 alloc/op + 288 B/op. Most reports surface
// 0-3 findings per severity, so the hints would over-allocate on every
// call.
package processor

import (
	"testing"

	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
)

func BenchmarkNewReport(b *testing.B) {
	cfg := &common.CommonDevice{
		Version:    "test",
		DeviceType: common.DeviceTypeOPNsense,
	}
	cfg.System.Hostname = "bench"
	cfg.System.Domain = "example.com"

	pc := Config{EnableStats: false}

	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		_ = NewReport(cfg, pc)
	}
}
