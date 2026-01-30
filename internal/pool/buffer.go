// Package pool provides memory pooling utilities for efficient buffer reuse.
// It reduces garbage collection pressure in hot paths by reusing allocated buffers.
package pool

import (
	"bytes"
	"strings"
	"sync"
)

// Buffer pool sizes for different use cases.
const (
	// SmallBufferSize is used for small strings and error messages.
	SmallBufferSize = 256
	// MediumBufferSize is used for typical text processing.
	MediumBufferSize = 4096
	// LargeBufferSize is used for report generation and file content.
	LargeBufferSize = 65536
)

// BytesBufferPool provides pooled bytes.Buffer instances.
var BytesBufferPool = sync.Pool{ //nolint:gochecknoglobals // Intended global pool
	New: func() any {
		return bytes.NewBuffer(make([]byte, 0, MediumBufferSize))
	},
}

// StringBuilderPool provides pooled strings.Builder instances.
var StringBuilderPool = sync.Pool{ //nolint:gochecknoglobals // Intended global pool
	New: func() any {
		b := &strings.Builder{}
		b.Grow(MediumBufferSize)
		return b
	},
}

// SmallByteSlicePool provides pooled small byte slices.
var SmallByteSlicePool = sync.Pool{ //nolint:gochecknoglobals // Intended global pool
	New: func() any {
		b := make([]byte, SmallBufferSize)
		return &b
	},
}

// LargeByteSlicePool provides pooled large byte slices.
var LargeByteSlicePool = sync.Pool{ //nolint:gochecknoglobals // Intended global pool
	New: func() any {
		b := make([]byte, LargeBufferSize)
		return &b
	},
}

// GetBytesBuffer returns a bytes.Buffer from the pool.
// The buffer is reset before being returned.
// Call PutBytesBuffer when done to return it to the pool.
func GetBytesBuffer() *bytes.Buffer {
	//nolint:errcheck // Type assertion always succeeds; pool.New guarantees *bytes.Buffer
	buf := BytesBufferPool.Get().(*bytes.Buffer)
	buf.Reset()
	return buf
}

// PutBytesBuffer returns a bytes.Buffer to the pool.
// The buffer should not be used after calling this function.
func PutBytesBuffer(buf *bytes.Buffer) {
	if buf == nil {
		return
	}
	// Only return buffers that aren't too large to prevent memory bloat
	if buf.Cap() <= LargeBufferSize*2 {
		buf.Reset()
		BytesBufferPool.Put(buf)
	}
}

// GetStringBuilder returns a strings.Builder from the pool.
// The builder is reset before being returned.
// Call PutStringBuilder when done to return it to the pool.
func GetStringBuilder() *strings.Builder {
	//nolint:errcheck // Type assertion always succeeds; pool.New guarantees *strings.Builder
	sb := StringBuilderPool.Get().(*strings.Builder)
	sb.Reset()
	return sb
}

// PutStringBuilder returns a strings.Builder to the pool.
// The builder should not be used after calling this function.
func PutStringBuilder(sb *strings.Builder) {
	if sb == nil {
		return
	}
	// Only return builders that aren't too large to prevent memory bloat
	if sb.Cap() <= LargeBufferSize*2 {
		sb.Reset()
		StringBuilderPool.Put(sb)
	}
}

// GetSmallByteSlice returns a small byte slice from the pool.
// Call PutSmallByteSlice when done to return it to the pool.
func GetSmallByteSlice() []byte {
	//nolint:errcheck // Type assertion always succeeds; pool.New guarantees *[]byte
	return *SmallByteSlicePool.Get().(*[]byte)
}

// PutSmallByteSlice returns a small byte slice to the pool.
// The slice should not be used after calling this function.
func PutSmallByteSlice(b []byte) {
	if len(b) == SmallBufferSize {
		SmallByteSlicePool.Put(&b)
	}
}

// GetLargeByteSlice returns a large byte slice from the pool.
// Call PutLargeByteSlice when done to return it to the pool.
func GetLargeByteSlice() []byte {
	//nolint:errcheck // Type assertion always succeeds; pool.New guarantees *[]byte
	return *LargeByteSlicePool.Get().(*[]byte)
}

// PutLargeByteSlice returns a large byte slice to the pool.
// The slice should not be used after calling this function.
func PutLargeByteSlice(b []byte) {
	if len(b) == LargeBufferSize {
		LargeByteSlicePool.Put(&b)
	}
}

// WithBytesBuffer executes a function with a pooled bytes.Buffer.
// The buffer is automatically returned to the pool after the function completes.
// This is the preferred way to use pooled buffers for simple use cases.
func WithBytesBuffer(fn func(*bytes.Buffer)) {
	buf := GetBytesBuffer()
	defer PutBytesBuffer(buf)
	fn(buf)
}

// WithStringBuilder executes a function with a pooled strings.Builder.
// The builder is automatically returned to the pool after the function completes.
// This is the preferred way to use pooled builders for simple use cases.
func WithStringBuilder(fn func(*strings.Builder)) {
	sb := GetStringBuilder()
	defer PutStringBuilder(sb)
	fn(sb)
}
