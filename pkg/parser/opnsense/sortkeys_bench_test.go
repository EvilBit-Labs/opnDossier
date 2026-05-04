// Focused micro-benchmark for the converter "sorted map keys" idiom.
//
// NATS-38 finding 4 proposes replacing slices.Sorted(maps.Keys(items))
// with the single-allocation make([]K, 0, len(items)) + range +
// slices.Sort pattern at the converter call sites. The ticket itself
// flags this as marginal at typical map sizes; this bench is the
// arbiter that decided to land it across opnsense convertInterfaces,
// opnsense convertDHCP, opnsense Kea reservation orphan check,
// pfsense convertInterfaces, and pfsense convertDHCP.
package opnsense_test

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
			for b.Loop() {
				//nolint:revive // benchmark consumes the iterator with no per-element work
				for range slices.Sorted(maps.Keys(m)) {
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
			for b.Loop() {
				keys := make([]string, 0, len(m))
				for k := range m {
					keys = append(keys, k)
				}
				slices.Sort(keys)
				//nolint:revive // benchmark consumes the slice with no per-element work
				for range keys {
				}
			}
		})
	}
}
