package converter

import (
	"context"
	"encoding/xml"
	"os"
	"path/filepath"
	"testing"

	"github.com/unclesp1d3r/opnFocus/internal/model"
)

func BenchmarkMarkdownConverter_ToMarkdown(b *testing.B) {
	// Load a medium-sized config.xml for realistic testing
	xmlPath := filepath.Join("..", "..", "testdata", "config.xml")
	xmlData, err := os.ReadFile(xmlPath)
	if err != nil {
		b.Fatalf("Failed to read testdata XML file: %v", err)
	}

	var opnsense model.Opnsense
	err = xml.Unmarshal(xmlData, &opnsense)
	if err != nil {
		b.Fatalf("XML unmarshalling failed: %v", err)
	}

	converter := NewMarkdownConverter()
	ctx := context.Background()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, err := converter.ToMarkdown(ctx, &opnsense)
		if err != nil {
			b.Fatalf("ToMarkdown failed: %v", err)
		}
	}
}

func BenchmarkMarkdownConverter_ToMarkdown_Large(b *testing.B) {
	// Use the larger sample config for stress testing
	xmlPath := filepath.Join("..", "..", "testdata", "sample.config.2.xml")
	xmlData, err := os.ReadFile(xmlPath)
	if err != nil {
		b.Fatalf("Failed to read large testdata XML file: %v", err)
	}

	var opnsense model.Opnsense
	err = xml.Unmarshal(xmlData, &opnsense)
	if err != nil {
		b.Fatalf("XML unmarshalling failed: %v", err)
	}

	converter := NewMarkdownConverter()
	ctx := context.Background()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, err := converter.ToMarkdown(ctx, &opnsense)
		if err != nil {
			b.Fatalf("ToMarkdown failed: %v", err)
		}
	}
}
