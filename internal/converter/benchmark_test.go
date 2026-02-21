package converter

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/model"
)

func BenchmarkMarkdownConverter_ToMarkdown(b *testing.B) {
	// Load a medium-sized config.xml for realistic testing
	xmlPath := filepath.Join("..", "..", "testdata", "sample.config.1.xml")

	xmlData, err := os.ReadFile(xmlPath)
	if err != nil {
		b.Fatalf("Failed to read testdata XML file: %v", err)
	}

	// Parse using the parser factory
	factory := model.NewParserFactory()
	device, err := factory.CreateDevice(context.Background(), strings.NewReader(string(xmlData)), "", false)
	if err != nil {
		b.Fatalf("XML parsing failed: %v", err)
	}

	converter := NewMarkdownConverter()
	ctx := context.Background()

	b.ReportAllocs()

	for b.Loop() {
		_, err := converter.ToMarkdown(ctx, device)
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

	// Parse using the parser factory
	factory := model.NewParserFactory()
	device, err := factory.CreateDevice(context.Background(), strings.NewReader(string(xmlData)), "", false)
	if err != nil {
		b.Fatalf("XML parsing failed: %v", err)
	}

	converter := NewMarkdownConverter()
	ctx := context.Background()

	b.ReportAllocs()

	for b.Loop() {
		_, err := converter.ToMarkdown(ctx, device)
		if err != nil {
			b.Fatalf("ToMarkdown failed: %v", err)
		}
	}
}
