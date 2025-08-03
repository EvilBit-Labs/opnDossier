//go:build legacy_bench
// +build legacy_bench

// Package parser provides functionality to parse OPNsense configuration files.
// This file contains legacy benchmark implementations for comparison purposes.
package parser

import (
	"bytes"
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"runtime"
	"testing"
	"time"

	"github.com/EvilBit-Labs/opnDossier/internal/model"
)

// LegacyXMLParser represents the old DOM-based parsing approach
type LegacyXMLParser struct {
	MaxInputSize int64
}

// NewLegacyXMLParser creates a legacy parser that uses full DOM loading
func NewLegacyXMLParser() *LegacyXMLParser {
	return &LegacyXMLParser{
		MaxInputSize: 200 * 1024 * 1024, // 200 MB limit for benchmarking
	}
}

// Parse implements the old approach: load entire XML into memory at once
func (p *LegacyXMLParser) Parse(_ context.Context, r io.Reader) (*model.OpnSenseDocument, error) {
	// Legacy approach: read entire file into memory first
	limitedReader := io.LimitReader(r, p.MaxInputSize)
	data, err := io.ReadAll(limitedReader)
	if err != nil {
		return nil, fmt.Errorf("failed to read XML data: %w", err)
	}

	// Parse the entire document at once (traditional DOM approach)
	var doc model.OpnSenseDocument
	if err := xml.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("failed to unmarshal XML: %w", err)
	}

	return &doc, nil
}

// generateLargeConfigStream generates a large XML configuration for memory testing
// Target size: 50-100 MB for proper benchmarking
func generateLargeConfigStream(targetSizeMB int) *bytes.Buffer {
	var buffer bytes.Buffer

	// Start with XML declaration and root element
	buffer.WriteString(`<?xml version="1.0" encoding="UTF-8"?>`)
	buffer.WriteString(`<opnsense>`)

	// Add basic system info
	buffer.WriteString(`<system>`)
	buffer.WriteString(`<hostname>benchmark-host</hostname>`)
	buffer.WriteString(`<domain>example.com</domain>`)
	buffer.WriteString(`<version>22.1</version>`)
	buffer.WriteString(`</system>`)

	// Generate a large sysctl section to reach target size
	buffer.WriteString(`<sysctl>`)

	// Each item is approximately 350-400 bytes
	// For 75 MB target: ~200,000 items
	targetBytes := targetSizeMB * 1024 * 1024
	itemCount := 0

	for buffer.Len() < targetBytes-10000 { // Leave some buffer for closing tags
		buffer.WriteString(`<item>`)
		buffer.WriteString(fmt.Sprintf(`<tunable>net.inet.ip.forwarding.benchmark.test.item_%d</tunable>`, itemCount))
		buffer.WriteString(fmt.Sprintf(`<value>%d</value>`, itemCount%2))
		buffer.WriteString(
			fmt.Sprintf(
				`<descr><![CDATA[Large sysctl description for benchmarking memory usage item %d. This description contains additional text to increase the size of each XML element and test the streaming parser's memory efficiency compared to traditional DOM parsing approaches. The streaming approach should maintain constant memory usage regardless of file size.]]></descr>`,
				itemCount,
			),
		)
		buffer.WriteString(`</item>`)
		itemCount++
	}

	buffer.WriteString(`</sysctl>`)

	// Add some additional sections for completeness
	buffer.WriteString(`<interfaces>`)
	buffer.WriteString(`<lan>`)
	buffer.WriteString(`<if>em0</if>`)
	buffer.WriteString(`<enable/>`)
	buffer.WriteString(`<ipaddr>192.168.1.1</ipaddr>`)
	buffer.WriteString(`<subnet>24</subnet>`)
	buffer.WriteString(`</lan>`)
	buffer.WriteString(`</interfaces>`)

	buffer.WriteString(`</opnsense>`)

	return &buffer
}

// BenchmarkXMLParser_ParseLarge_Legacy benchmarks the legacy DOM-based parsing approach
// This demonstrates O(n) memory growth compared to the streaming approach
func BenchmarkXMLParser_ParseLarge_Legacy(b *testing.B) {
	const targetSizeMB = 51 // Target 51 MB to ensure we hit the 50MB minimum

	// Generate large config once
	buffer := generateLargeConfigStream(targetSizeMB)
	data := buffer.Bytes()

	// Report actual size
	actualSizeMB := float64(len(data)) / (1024 * 1024)
	b.Logf("Generated config size: %.2f MB", actualSizeMB)

	// Ensure we're in the 50-100 MB range as requested
	if actualSizeMB < 50 || actualSizeMB > 100 {
		b.Fatalf("Config size %.2f MB is outside required range 50-100 MB", actualSizeMB)
	}

	parser := NewLegacyXMLParser()

	// Test memory allocation behavior using testing.AllocsPerRun
	allocs := testing.AllocsPerRun(5, func() {
		_, err := parser.Parse(context.Background(), bytes.NewReader(data))
		if err != nil {
			b.Fatal(err)
		}
		runtime.GC() // Force GC to clean up between runs
	})

	b.Logf("Legacy allocations per run: %.0f", allocs)

	// Record baseline memory stats
	var memBefore, memAfter runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&memBefore)

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		start := time.Now()
		_, err := parser.Parse(context.Background(), bytes.NewReader(data))
		duration := time.Since(start)

		if err != nil {
			b.Fatal(err)
		}

		// Legacy approach may take longer due to memory allocation
		if duration > 5*time.Second {
			b.Errorf("Parse took %v, expected < 5s", duration)
		}

		// Check memory growth every 5 iterations (less frequent due to higher memory usage)
		if i%5 == 4 {
			runtime.GC()
			runtime.ReadMemStats(&memAfter)

			// Handle potential underflow
			var memGrowthMB float64
			if memAfter.Alloc >= memBefore.Alloc {
				memGrowthMB = float64(memAfter.Alloc-memBefore.Alloc) / (1024 * 1024)
			} else {
				memGrowthMB = 0
			}

			// Legacy approach will show O(n) memory growth - expect significant memory usage
			b.Logf("Legacy memory grew by %.2f MB after %d iterations", memGrowthMB, i+1)
		}
	}

	b.StopTimer()

	// Final memory measurement
	runtime.GC()
	runtime.ReadMemStats(&memAfter)

	// Handle potential underflow in final calculation
	var memGrowthMB float64
	if memAfter.Alloc >= memBefore.Alloc {
		memGrowthMB = float64(memAfter.Alloc-memBefore.Alloc) / (1024 * 1024)
	} else {
		memGrowthMB = 0
	}
	peakMemMB := float64(memAfter.Alloc) / (1024 * 1024)

	b.Logf("Legacy final memory growth: %.2f MB", memGrowthMB)
	b.Logf("Legacy peak memory usage: %.2f MB", peakMemMB)

	// Report metrics
	b.ReportMetric(actualSizeMB, "config_size_MB")
	b.ReportMetric(memGrowthMB, "memory_growth_MB")
	b.ReportMetric(peakMemMB, "peak_memory_MB")
	b.ReportMetric(allocs, "allocs_per_run")
}

// BenchmarkParse_Legacy provides the legacy implementation for comparison
func BenchmarkParse_Legacy(b *testing.B) {
	const synthSizeMB = 50

	// Create a synthetic XML file of approximately 50 MB
	var buffer bytes.Buffer
	buffer.WriteString("<opnsense>")

	// Create repeating sysctl items for large file
	for buffer.Len() < synthSizeMB*1024*1024 {
		buffer.WriteString("<sysctl>")
		for i := 0; i < 100; i++ { // Add many items per sysctl section
			buffer.WriteString(
				"<item><descr><![CDATA[Large description for memory usage testing. This adds bulk to test streaming performance improvements over the traditional full DOM parsing approach. Streaming XML processing should use significantly less memory than loading the entire document into memory at once.]]></descr><tunable>test.tunable." + fmt.Sprintf(
					"%d",
					i,
				) + "</tunable><value>testvalue</value></item>",
			)
		}
		buffer.WriteString("</sysctl>")
	}
	buffer.WriteString("</opnsense>")

	parser := NewLegacyXMLParser()

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := parser.Parse(context.Background(), bytes.NewReader(buffer.Bytes()))
		if err != nil {
			b.Fatal(err)
		}

		// Force garbage collection after each parse cycle
		runtime.GC()
	}
}
