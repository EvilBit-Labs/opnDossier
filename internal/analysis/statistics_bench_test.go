// Benchmarks for ComputeStatistics.
//
// BenchmarkComputeStatistics covers the two map-allocation paths — the
// early return for nil cfg (no maps populated) and a populated path
// with realistic interface and firewall-rule counts.
//
// History: NATS-38 considered pre-sizing the per-statistic maps via
// len(cfg.Interfaces) and small-cardinality enum constants. Bench
// measurements with the hint added showed:
//
//   - 100-fixture (10 interfaces, 100 rules): 19 -> 20 allocs/op
//     (+1, regression). The iface-derived hint (10) crossed Go's
//     bucketCnt threshold of 8, forcing an immediate separate
//     bucket-array allocation that the no-hint path avoided entirely.
//   - 500-fixture (50 interfaces, 500 rules): 25 -> 22 allocs/op
//     (-3, win). The hint avoided three rehash-grow cycles.
//   - nil cfg: 6 -> 6 allocs/op (no change).
//
// Real-world opnsense/pfSense configurations sit in the 3-30 interface
// range, where the 100-fixture regression dominates the 500-fixture
// win. The ticket's premise (pre-size maps to known element counts)
// only pays off for unusually-interface-rich configurations, so the
// hints were not landed. The bench file stays so a future contributor
// does not retry the experiment without seeing this result.
package analysis

import (
	"fmt"
	"strconv"
	"testing"

	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
)

func generateStatsFixture(interfaceCount, ruleCount int) *common.CommonDevice {
	cfg := &common.CommonDevice{}
	cfg.Interfaces = make([]common.Interface, 0, interfaceCount)
	for i := range interfaceCount {
		cfg.Interfaces = append(cfg.Interfaces, common.Interface{
			Name:    fmt.Sprintf("iface%d", i),
			Type:    "static",
			Enabled: true,
		})
	}

	cfg.FirewallRules = make([]common.FirewallRule, 0, ruleCount)
	for i := range ruleCount {
		cfg.FirewallRules = append(cfg.FirewallRules, common.FirewallRule{
			Type:        common.RuleTypePass,
			Interfaces:  []string{fmt.Sprintf("iface%d", i%interfaceCount)},
			Description: "rule " + strconv.Itoa(i),
		})
	}

	cfg.Users = []common.User{
		{Name: "admin", Scope: "system"},
		{Name: "user1", Scope: "user"},
	}
	cfg.Groups = []common.Group{
		{Name: "admins", Scope: "system"},
	}

	return cfg
}

func BenchmarkComputeStatistics(b *testing.B) {
	for _, size := range []int{100, 500} {
		cfg := generateStatsFixture(size/10, size)
		b.Run(strconv.Itoa(size), func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				_ = ComputeStatistics(cfg)
			}
		})
	}
}

func BenchmarkComputeStatisticsNil(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		_ = ComputeStatistics(nil)
	}
}
