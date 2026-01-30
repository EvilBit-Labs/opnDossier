package pool

import (
	"bytes"
	"strings"
	"sync"
	"testing"
)

// Test string constants to avoid goconst warnings.
const (
	testStr      = "test"
	benchmarkStr = "benchmark"
)

func TestGetBytesBuffer(t *testing.T) {
	t.Parallel()

	buf := GetBytesBuffer()
	if buf == nil {
		t.Fatal("GetBytesBuffer returned nil")
	}

	// Buffer should be empty and ready to use
	if buf.Len() != 0 {
		t.Errorf("expected empty buffer, got length %d", buf.Len())
	}

	// Write something
	buf.WriteString(testStr)
	if buf.String() != testStr {
		t.Errorf("expected %q, got %q", testStr, buf.String())
	}

	PutBytesBuffer(buf)
}

func TestGetBytesBufferReset(t *testing.T) {
	t.Parallel()

	// Get a buffer, write to it, return it
	buf1 := GetBytesBuffer()
	buf1.WriteString("first buffer content")
	PutBytesBuffer(buf1)

	// Get another buffer - it should be reset
	buf2 := GetBytesBuffer()
	if buf2.Len() != 0 {
		t.Errorf("expected reset buffer, got length %d with content %q", buf2.Len(), buf2.String())
	}
	PutBytesBuffer(buf2)
}

func TestGetStringBuilder(t *testing.T) {
	t.Parallel()

	sb := GetStringBuilder()
	if sb == nil {
		t.Fatal("GetStringBuilder returned nil")
	}

	// Builder should be empty and ready to use
	if sb.Len() != 0 {
		t.Errorf("expected empty builder, got length %d", sb.Len())
	}

	// Write something
	sb.WriteString(testStr)
	if sb.String() != testStr {
		t.Errorf("expected %q, got %q", testStr, sb.String())
	}

	PutStringBuilder(sb)
}

func TestGetStringBuilderReset(t *testing.T) {
	t.Parallel()

	// Get a builder, write to it, return it
	sb1 := GetStringBuilder()
	sb1.WriteString("first builder content")
	PutStringBuilder(sb1)

	// Get another builder - it should be reset
	sb2 := GetStringBuilder()
	if sb2.Len() != 0 {
		t.Errorf("expected reset builder, got length %d with content %q", sb2.Len(), sb2.String())
	}
	PutStringBuilder(sb2)
}

func TestGetSmallByteSlice(t *testing.T) {
	t.Parallel()

	slice := GetSmallByteSlice()
	if len(slice) != SmallBufferSize {
		t.Errorf("expected length %d, got %d", SmallBufferSize, len(slice))
	}

	// Should be usable
	copy(slice, testStr)
	if string(slice[:4]) != testStr {
		t.Errorf("expected %q, got %q", testStr, string(slice[:4]))
	}

	PutSmallByteSlice(slice)
}

func TestGetLargeByteSlice(t *testing.T) {
	t.Parallel()

	slice := GetLargeByteSlice()
	if len(slice) != LargeBufferSize {
		t.Errorf("expected length %d, got %d", LargeBufferSize, len(slice))
	}

	// Should be usable
	copy(slice, testStr)
	if string(slice[:4]) != testStr {
		t.Errorf("expected %q, got %q", testStr, string(slice[:4]))
	}

	PutLargeByteSlice(slice)
}

func TestPutBytesBufferNil(t *testing.T) {
	t.Parallel()

	// Should not panic
	PutBytesBuffer(nil)
}

func TestPutStringBuilderNil(t *testing.T) {
	t.Parallel()

	// Should not panic
	PutStringBuilder(nil)
}

func TestWithBytesBuffer(t *testing.T) {
	t.Parallel()

	var result string
	WithBytesBuffer(func(buf *bytes.Buffer) {
		buf.WriteString("hello")
		result = buf.String()
	})

	if result != "hello" {
		t.Errorf("expected 'hello', got %q", result)
	}
}

func TestWithStringBuilder(t *testing.T) {
	t.Parallel()

	var result string
	WithStringBuilder(func(sb *strings.Builder) {
		sb.WriteString("world")
		result = sb.String()
	})

	if result != "world" {
		t.Errorf("expected 'world', got %q", result)
	}
}

func TestConcurrentBytesBufferAccess(t *testing.T) {
	t.Parallel()

	const goroutines = 100
	const iterations = 1000

	var wg sync.WaitGroup
	wg.Add(goroutines)

	for range goroutines {
		go func() {
			defer wg.Done()
			for range iterations {
				buf := GetBytesBuffer()
				buf.WriteString("concurrent test")
				_ = buf.String()
				PutBytesBuffer(buf)
			}
		}()
	}

	wg.Wait()
}

func TestConcurrentStringBuilderAccess(t *testing.T) {
	t.Parallel()

	const goroutines = 100
	const iterations = 1000

	var wg sync.WaitGroup
	wg.Add(goroutines)

	for range goroutines {
		go func() {
			defer wg.Done()
			for range iterations {
				sb := GetStringBuilder()
				sb.WriteString("concurrent test")
				_ = sb.String()
				PutStringBuilder(sb)
			}
		}()
	}

	wg.Wait()
}

// Benchmark tests

func BenchmarkBytesBufferPool(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		buf := GetBytesBuffer()
		buf.WriteString("benchmark test content")
		_ = buf.String()
		PutBytesBuffer(buf)
	}
}

func BenchmarkBytesBufferNoPool(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		buf := bytes.NewBuffer(make([]byte, 0, MediumBufferSize))
		buf.WriteString("benchmark test content")
		_ = buf.String()
	}
}

func BenchmarkStringBuilderPool(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		sb := GetStringBuilder()
		sb.WriteString("benchmark test content")
		_ = sb.String()
		PutStringBuilder(sb)
	}
}

func BenchmarkStringBuilderNoPool(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		sb := &strings.Builder{}
		sb.Grow(MediumBufferSize)
		sb.WriteString("benchmark test content")
		_ = sb.String()
	}
}

func BenchmarkByteSlicePool(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		slice := GetSmallByteSlice()
		copy(slice, benchmarkStr)
		PutSmallByteSlice(slice)
	}
}

func BenchmarkByteSliceNoPool(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		slice := make([]byte, SmallBufferSize)
		copy(slice, benchmarkStr)
		_ = slice
	}
}

func BenchmarkParallelBytesBufferPool(b *testing.B) {
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			buf := GetBytesBuffer()
			buf.WriteString("parallel benchmark test")
			_ = buf.String()
			PutBytesBuffer(buf)
		}
	})
}
