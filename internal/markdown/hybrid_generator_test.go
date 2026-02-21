package markdown

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/converter"
	"github.com/EvilBit-Labs/opnDossier/internal/converter/builder"
	"github.com/EvilBit-Labs/opnDossier/internal/logging"
	"github.com/EvilBit-Labs/opnDossier/internal/model/common"
)

func TestNewHybridGenerator(t *testing.T) {
	reportBuilder := builder.NewMarkdownBuilder()
	logger, err := logging.New(logging.Config{})
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}

	// Test with nil logger
	gen, err := NewHybridGenerator(reportBuilder, nil)
	if err != nil {
		t.Fatalf("NewHybridGenerator failed: %v", err)
	}
	if gen == nil {
		t.Fatal("NewHybridGenerator returned nil")
	}
	// Note: Internal fields are now unexported for proper encapsulation

	// Test with logger
	gen, err = NewHybridGenerator(reportBuilder, logger)
	if err != nil {
		t.Fatalf("NewHybridGenerator failed: %v", err)
	}
	if gen == nil {
		t.Fatal("NewHybridGenerator returned nil")
	}
	// Note: Internal fields are now unexported for proper encapsulation
}

func TestHybridGenerator_Generate_Programmatic(t *testing.T) {
	reportBuilder := builder.NewMarkdownBuilder()
	logger, err := logging.New(logging.Config{})
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}
	gen, err := NewHybridGenerator(reportBuilder, logger)
	if err != nil {
		t.Fatalf("Failed to create hybrid generator: %v", err)
	}

	// Create test data
	data := &common.CommonDevice{
		System: common.System{
			Hostname: "test-firewall",
			Domain:   "example.com",
		},
	}

	opts := DefaultOptions()

	// Test programmatic generation (default)
	output, err := gen.Generate(context.Background(), data, opts)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	if output == "" {
		t.Error("Generated output is empty")
	}

	// Verify it contains expected content
	if !strings.Contains(output, "test-firewall") {
		t.Error("Generated output does not contain hostname")
	}
	if !strings.Contains(output, "example.com") {
		t.Error("Generated output does not contain domain")
	}
}

func TestHybridGenerator_Generate_Comprehensive(t *testing.T) {
	reportBuilder := builder.NewMarkdownBuilder()
	logger, err := logging.New(logging.Config{})
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}
	gen, err := NewHybridGenerator(reportBuilder, logger)
	if err != nil {
		t.Fatalf("Failed to create hybrid generator: %v", err)
	}

	// Create test data
	data := &common.CommonDevice{
		System: common.System{
			Hostname: "test-firewall",
			Domain:   "example.com",
		},
	}

	opts := DefaultOptions()
	opts.Comprehensive = true

	// Test comprehensive programmatic generation
	output, err := gen.Generate(context.Background(), data, opts)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	if output == "" {
		t.Error("Generated output is empty")
	}

	// Verify it contains expected content
	if !strings.Contains(output, "test-firewall") {
		t.Error("Generated output does not contain hostname")
	}
	if !strings.Contains(output, "example.com") {
		t.Error("Generated output does not contain domain")
	}
}

func TestHybridGenerator_Generate_NilData(t *testing.T) {
	reportBuilder := builder.NewMarkdownBuilder()
	logger, loggerErr := logging.New(logging.Config{})
	if loggerErr != nil {
		t.Fatalf("Failed to create logger: %v", loggerErr)
	}
	gen, err := NewHybridGenerator(reportBuilder, logger)
	if err != nil {
		t.Fatalf("Failed to create hybrid generator: %v", err)
	}

	opts := DefaultOptions()

	// Test with nil data
	_, generateErr := gen.Generate(context.Background(), nil, opts)
	if generateErr == nil {
		t.Error("Expected error for nil data")
	}
	if !errors.Is(generateErr, converter.ErrNilDevice) {
		t.Errorf("Expected ErrNilDevice, got %v", generateErr)
	}
}

func TestHybridGenerator_Generate_NoBuilder(t *testing.T) {
	logger, loggerErr := logging.New(logging.Config{})
	if loggerErr != nil {
		t.Fatalf("Failed to create logger: %v", loggerErr)
	}
	gen, genErr := NewHybridGenerator(nil, logger)
	if genErr != nil {
		t.Fatalf("Failed to create hybrid generator: %v", genErr)
	}

	data := &common.CommonDevice{
		System: common.System{
			Hostname: "test-firewall",
		},
	}

	opts := DefaultOptions()

	// Test with no builder
	_, err := gen.Generate(context.Background(), data, opts)
	if err == nil {
		t.Error("Expected error for no builder")
	}
	if !strings.Contains(err.Error(), "no report builder available") {
		t.Errorf("Expected error about missing builder, got %v", err)
	}
}

func TestHybridGenerator_SetAndGetBuilder(t *testing.T) {
	reportBuilder := builder.NewMarkdownBuilder()
	logger, loggerErr := logging.New(logging.Config{})
	if loggerErr != nil {
		t.Fatalf("Failed to create logger: %v", loggerErr)
	}
	gen, genErr := NewHybridGenerator(nil, logger)
	if genErr != nil {
		t.Fatalf("Failed to create hybrid generator: %v", genErr)
	}

	// Test initial state
	if gen.GetBuilder() != nil {
		t.Error("Initial builder should be nil")
	}

	// Set builder
	gen.SetBuilder(reportBuilder)

	// Test get builder
	if gen.GetBuilder() != reportBuilder {
		t.Error("Builder not set correctly")
	}
}
