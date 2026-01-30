//go:build stress

package pool

import (
	"runtime"
	"sync"
	"testing"
)

// TestBytesBufferPoolStress tests the buffer pool under concurrent access.
func TestBytesBufferPoolStress(t *testing.T) {
	const numGoroutines = 100
	const iterationsPerGoroutine = 1000
	const dataSize = 4096

	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()

			for j := 0; j < iterationsPerGoroutine; j++ {
				buf := GetBytesBuffer()

				// Write data
				data := make([]byte, dataSize)
				for k := range data {
					data[k] = byte(k % 256)
				}
				buf.Write(data)

				// Verify data
				if buf.Len() != dataSize {
					t.Errorf("buffer length mismatch: expected %d, got %d", dataSize, buf.Len())
				}

				PutBytesBuffer(buf)
			}
		}()
	}

	wg.Wait()
}

// TestStringsBuilderPoolStress tests the strings builder pool under concurrent access.
func TestStringsBuilderPoolStress(t *testing.T) {
	const numGoroutines = 100
	const iterationsPerGoroutine = 1000
	const stringLen = 100

	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()

			for j := 0; j < iterationsPerGoroutine; j++ {
				sb := GetStringBuilder()

				// Write strings
				for k := 0; k < stringLen; k++ {
					sb.WriteString("test")
				}

				// Verify length
				if sb.Len() != stringLen*4 {
					t.Errorf("builder length mismatch: expected %d, got %d", stringLen*4, sb.Len())
				}

				PutStringBuilder(sb)
			}
		}()
	}

	wg.Wait()
}

// TestPoolMemoryStability tests that pool memory usage remains stable.
func TestPoolMemoryStability(t *testing.T) {
	// Force GC before test
	runtime.GC()
	var memBefore runtime.MemStats
	runtime.ReadMemStats(&memBefore)

	const iterations = 10000

	for i := 0; i < iterations; i++ {
		buf := GetBytesBuffer()
		buf.WriteString("test data for stress testing memory stability")
		PutBytesBuffer(buf)
	}

	// Force GC after test
	runtime.GC()
	var memAfter runtime.MemStats
	runtime.ReadMemStats(&memAfter)

	// Memory increase should be minimal due to pooling
	// Allow for some overhead, but flag significant leaks
	const maxAllowedIncrease = 10 * 1024 * 1024 // 10MB

	// Handle the case where memory decreased (GC freed memory)
	var memDiff int64
	if memAfter.HeapAlloc > memBefore.HeapAlloc {
		memDiff = int64(memAfter.HeapAlloc - memBefore.HeapAlloc)
	} else {
		memDiff = -int64(memBefore.HeapAlloc - memAfter.HeapAlloc)
	}

	if memDiff > maxAllowedIncrease {
		t.Errorf("excessive memory growth: before=%d, after=%d, diff=%d",
			memBefore.HeapAlloc, memAfter.HeapAlloc, memDiff)
	}
}

// TestPoolConcurrentGetPut tests rapid concurrent get/put operations.
func TestPoolConcurrentGetPut(t *testing.T) {
	const numGoroutines = 50
	const iterations = 5000

	var wg sync.WaitGroup
	wg.Add(numGoroutines * 2) // Half use bytes.Buffer, half use strings.Builder

	// Test BytesBufferPool
	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				buf := GetBytesBuffer()
				buf.WriteString("concurrent test")
				PutBytesBuffer(buf)
			}
		}()
	}

	// Test StringsBuilderPool
	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				sb := GetStringBuilder()
				sb.WriteString("concurrent test")
				PutStringBuilder(sb)
			}
		}()
	}

	wg.Wait()
}

// BenchmarkPoolStress benchmarks pool performance under stress.
func BenchmarkPoolStress(b *testing.B) {
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			buf := GetBytesBuffer()
			buf.WriteString("benchmark stress test data")
			PutBytesBuffer(buf)
		}
	})
}
