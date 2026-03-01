//go:build !legacy_bench

// Package cfgparser provides functionality to parse OPNsense configuration files.
package cfgparser

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"runtime"
	"testing"
	"time"
)

// BenchmarkParse benchmarks the parsing performance of the XML parser with a 50 MB synthetic file.
func BenchmarkParse(b *testing.B) {
	const synthSizeMB = 50

	// Create a synthetic XML file of approximately 50 MB using proper structure
	buffer := generateLargeConfigStream(synthSizeMB)
	data := buffer.Bytes()

	parser := NewXMLParser()
	// Increase max size to handle large benchmark file
	parser.MaxInputSize = 200 * 1024 * 1024 // 200 MB limit

	for b.Loop() {
		_, err := parser.Parse(context.Background(), bytes.NewReader(data))
		if err != nil {
			b.Fatal(err)
		}

		// Force garbage collection after each parse cycle
		runtime.GC()
	}
}

// BenchmarkParseConfigSample benchmarks parsing the config.xml.sample file.
func BenchmarkParseConfigSample(b *testing.B) {
	parser := NewXMLParser()

	// Read the config.xml.sample file once
	file, err := os.Open("testdata/config.xml.sample")
	if err != nil {
		b.Skip("config.xml.sample not found")
	}

	defer func() {
		if err := file.Close(); err != nil {
			b.Logf("Warning: failed to close file: %v", err)
		}
	}()

	data, err := io.ReadAll(file)
	if err != nil {
		b.Fatal(err)
	}

	for b.Loop() {
		_, err := parser.Parse(context.Background(), bytes.NewReader(data))
		if err != nil {
			b.Fatal(err)
		}

		// Force garbage collection to measure memory cleanup
		runtime.GC()
	}
}

// generateLargeConfigStream generates a large XML configuration for memory testing
// Target size: 50-100 MB for proper benchmarking.
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
		fmt.Fprintf(&buffer, `<tunable>net.inet.ip.forwarding.benchmark.test.item_%d</tunable>`, itemCount)
		fmt.Fprintf(&buffer, `<value>%d</value>`, itemCount%2)
		fmt.Fprintf(
			&buffer,
			`<descr><![CDATA[Large sysctl description for benchmarking memory usage item %d. This description contains additional text to increase the size of each XML element and test the streaming parser's memory efficiency compared to traditional DOM parsing approaches. The streaming approach should maintain constant memory usage regardless of file size.]]></descr>`,
			itemCount,
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

// BenchmarkXMLParser_ParseLarge benchmarks parsing of large XML configurations (50-100 MB)
// Uses testing.AllocsPerRun to confirm O(1) memory growth for streaming parser.
func BenchmarkXMLParser_ParseLarge(b *testing.B) {
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

	parser := NewXMLParser()
	// Increase max size to handle large benchmark file
	parser.MaxInputSize = 200 * 1024 * 1024 // 200 MB limit

	// Test memory allocation behavior using testing.AllocsPerRun
	allocs := testing.AllocsPerRun(5, func() {
		_, err := parser.Parse(context.Background(), bytes.NewReader(data))
		if err != nil {
			b.Fatal(err)
		}

		runtime.GC() // Force GC to clean up between runs
	})

	b.Logf("Allocations per run: %.0f", allocs)

	// Record baseline memory stats
	var memBefore, memAfter runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&memBefore)

	for i := 0; b.Loop(); i++ {
		start := time.Now()
		_, err := parser.Parse(context.Background(), bytes.NewReader(data))
		duration := time.Since(start)

		if err != nil {
			b.Fatal(err)
		}

		// Ensure each parse completes in reasonable time (target < 2s as specified)
		if duration > 2*time.Second {
			b.Errorf("Parse took %v, expected < 2s", duration)
		}

		// Check memory growth every 10 iterations
		if i%10 == 9 {
			runtime.GC()
			runtime.ReadMemStats(&memAfter)

			// Handle potential underflow by checking if memAfter.Alloc >= memBefore.Alloc
			var memGrowthMB float64
			if memAfter.Alloc >= memBefore.Alloc {
				memGrowthMB = float64(memAfter.Alloc-memBefore.Alloc) / (1024 * 1024)
			} else {
				// Memory actually decreased (GC cleaned up)
				memGrowthMB = 0
			}

			// Memory growth should be minimal (O(1)) - allow max 10 MB growth
			if memGrowthMB > 10 {
				b.Errorf("Memory grew by %.2f MB, expected O(1) growth (< 10 MB)", memGrowthMB)
			}
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
		// Memory actually decreased (GC cleaned up)
		memGrowthMB = 0
	}

	peakMemMB := float64(memAfter.Alloc) / (1024 * 1024)

	b.Logf("Final memory growth: %.2f MB", memGrowthMB)
	b.Logf("Peak memory usage: %.2f MB", peakMemMB)

	// Report metrics
	b.ReportMetric(actualSizeMB, "config_size_MB")
	b.ReportMetric(memGrowthMB, "memory_growth_MB")
	b.ReportMetric(peakMemMB, "peak_memory_MB")
	b.ReportMetric(allocs, "allocs_per_run")
}
