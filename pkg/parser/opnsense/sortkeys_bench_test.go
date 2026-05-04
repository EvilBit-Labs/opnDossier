// Focused micro-benchmark for the converter "sorted map keys" idiom.
//
// NATS-38 finding 4 proposes replacing slices.Sorted(maps.Keys(items))
// with the single-allocation make([]K, 0, len(items)) + range +
// slices.Sort pattern at three converter call sites. The ticket itself
// flags this as marginal at typical map sizes; this bench is the
// arbiter that decides whether to land it.
package opnsense

import (
	"fmt"
	"maps"
	"slices"
	"strconv"
	"testing"
)

func makeKeyMap(n int) map[string]int {
	m := make(map[string]int, n)
	for i := range n {
		m[fmt.Sprintf("iface%03d", i)] = i
	}
	return m
}

func BenchmarkSortedMapKeys_Sorted(b *testing.B) {
	for _, size := range []int{8, 32, 128} {
		m := makeKeyMap(size)
		b.Run(strconv.Itoa(size), func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				for range slices.Sorted(maps.Keys(m)) { //nolint:revive // benchmark consumes the iterator
				}
			}
		})
	}
}

func BenchmarkSortedMapKeys_PreallocSort(b *testing.B) {
	for _, size := range []int{8, 32, 128} {
		m := makeKeyMap(size)
		b.Run(strconv.Itoa(size), func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				keys := make([]string, 0, len(m))
				for k := range m {
					keys = append(keys, k)
				}
				slices.Sort(keys)
				for range keys { //nolint:revive // benchmark consumes the slice
				}
			}
		})
	}
}
