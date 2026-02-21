package converter

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	builderPkg "github.com/EvilBit-Labs/opnDossier/internal/converter/builder"
	"github.com/EvilBit-Labs/opnDossier/internal/model/common"
)

// BenchmarkMarkdownBuilder_CompleteReport benchmarks report generation with complete data.
func BenchmarkMarkdownBuilder_CompleteReport(b *testing.B) {
	testData := loadBenchmarkData(b)
	builder := NewMarkdownBuilder()

	b.ResetTimer()
	for b.Loop() {
		_, err := builder.BuildStandardReport(testData)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkMarkdownBuilder_ComprehensiveReport benchmarks comprehensive report generation.
func BenchmarkMarkdownBuilder_ComprehensiveReport(b *testing.B) {
	testData := loadBenchmarkData(b)
	builder := NewMarkdownBuilder()

	b.ResetTimer()
	for b.Loop() {
		_, err := builder.BuildComprehensiveReport(testData)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkMarkdownBuilder_SystemSection benchmarks system section generation.
func BenchmarkMarkdownBuilder_SystemSection(b *testing.B) {
	testData := loadBenchmarkData(b)
	builder := NewMarkdownBuilder()

	b.ResetTimer()
	for b.Loop() {
		_ = builder.BuildSystemSection(testData)
	}
}

// BenchmarkMarkdownBuilder_NetworkSection benchmarks network section generation.
func BenchmarkMarkdownBuilder_NetworkSection(b *testing.B) {
	testData := loadBenchmarkData(b)
	builder := NewMarkdownBuilder()

	b.ResetTimer()
	for b.Loop() {
		_ = builder.BuildNetworkSection(testData)
	}
}

// BenchmarkMarkdownBuilder_SecuritySection benchmarks security section generation.
func BenchmarkMarkdownBuilder_SecuritySection(b *testing.B) {
	testData := loadBenchmarkData(b)
	builder := NewMarkdownBuilder()

	b.ResetTimer()
	for b.Loop() {
		_ = builder.BuildSecuritySection(testData)
	}
}

// BenchmarkMarkdownBuilder_ServicesSection benchmarks services section generation.
func BenchmarkMarkdownBuilder_ServicesSection(b *testing.B) {
	testData := loadBenchmarkData(b)
	builder := NewMarkdownBuilder()

	b.ResetTimer()
	for b.Loop() {
		_ = builder.BuildServicesSection(testData)
	}
}

// BenchmarkMarkdownBuilder_FirewallRulesTable benchmarks firewall rules table generation.
func BenchmarkMarkdownBuilder_FirewallRulesTable(b *testing.B) {
	testData := loadBenchmarkData(b)

	b.ResetTimer()
	for b.Loop() {
		_ = builderPkg.BuildFirewallRulesTableSet(testData.FirewallRules)
	}
}

// BenchmarkMarkdownBuilder_InterfaceTable benchmarks interface table generation.
func BenchmarkMarkdownBuilder_InterfaceTable(b *testing.B) {
	testData := loadBenchmarkData(b)

	b.ResetTimer()
	for b.Loop() {
		_ = builderPkg.BuildInterfaceTableSet(testData.Interfaces)
	}
}

// BenchmarkMarkdownBuilder_UserTable benchmarks user table generation.
func BenchmarkMarkdownBuilder_UserTable(b *testing.B) {
	testData := loadBenchmarkData(b)

	b.ResetTimer()
	for b.Loop() {
		_ = builderPkg.BuildUserTableSet(testData.Users)
	}
}

// BenchmarkMarkdownBuilder_SysctlTable benchmarks sysctl table generation.
func BenchmarkMarkdownBuilder_SysctlTable(b *testing.B) {
	testData := loadBenchmarkData(b)

	b.ResetTimer()
	for b.Loop() {
		_ = builderPkg.BuildSysctlTableSet(testData.Sysctl)
	}
}

// BenchmarkMarkdownBuilder_LargeDataset benchmarks with large synthetic dataset.
func BenchmarkMarkdownBuilder_LargeDataset(b *testing.B) {
	testData := generateLargeBenchmarkData(b)
	builder := NewMarkdownBuilder()

	b.ResetTimer()
	for b.Loop() {
		_, err := builder.BuildStandardReport(testData)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkMarkdownBuilder_MemoryUsage measures memory allocations.
func BenchmarkMarkdownBuilder_MemoryUsage(b *testing.B) {
	testData := loadBenchmarkData(b)
	builder := NewMarkdownBuilder()

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		_, err := builder.BuildStandardReport(testData)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkMarkdownBuilder_UtilityFunctions benchmarks utility functions.
func BenchmarkMarkdownBuilder_UtilityFunctions(b *testing.B) {
	builder := NewMarkdownBuilder()
	testContent := "This is a test | with pipes | and \n newlines \t tabs for benchmarking"

	b.Run("EscapeTableContent", func(b *testing.B) {
		for b.Loop() {
			builder.EscapeTableContent(testContent)
		}
	})

	b.Run("TruncateDescription", func(b *testing.B) {
		for b.Loop() {
			builder.TruncateDescription(testContent, 50)
		}
	})

	b.Run("SanitizeID", func(b *testing.B) {
		for b.Loop() {
			builder.SanitizeID(testContent)
		}
	})

	b.Run("IsEmpty", func(b *testing.B) {
		testValues := []any{
			"", "hello", 0, 42, []string{}, []string{"item"}, nil,
		}
		for b.Loop() {
			for _, v := range testValues {
				builder.IsEmpty(v)
			}
		}
	})
}

// BenchmarkMarkdownBuilder_SecurityAssessment benchmarks security assessment functions.
func BenchmarkMarkdownBuilder_SecurityAssessment(b *testing.B) {
	testData := loadBenchmarkData(b)
	builder := NewMarkdownBuilder()

	b.Run("CalculateSecurityScore", func(b *testing.B) {
		for b.Loop() {
			builder.CalculateSecurityScore(testData)
		}
	})

	b.Run("AssessRiskLevel", func(b *testing.B) {
		riskLevels := []string{"critical", "high", "medium", "low", "info", "unknown"}
		for b.Loop() {
			for _, level := range riskLevels {
				builder.AssessRiskLevel(level)
			}
		}
	})

	b.Run("AssessServiceRisk", func(b *testing.B) {
		services := []string{
			"telnet",
			"ftp",
			"ssh",
			"https",
			"unknown",
		}
		for b.Loop() {
			for _, service := range services {
				builder.AssessServiceRisk(service)
			}
		}
	})
}

// BenchmarkMarkdownBuilder_DataTransformers benchmarks data transformation functions.
func BenchmarkMarkdownBuilder_DataTransformers(b *testing.B) {
	testData := loadBenchmarkData(b)
	builder := NewMarkdownBuilder()

	b.Run("FilterSystemTunables", func(b *testing.B) {
		for b.Loop() {
			builder.FilterSystemTunables(testData.Sysctl, false)
		}
	})

	b.Run("FilterRulesByType", func(b *testing.B) {
		for b.Loop() {
			builder.FilterRulesByType(testData.FirewallRules, "pass")
		}
	})

	b.Run("ExtractUniqueValues", func(b *testing.B) {
		values := []string{"a", "b", "a", "c", "b", "d", "a", "e", "f", "c"}
		for b.Loop() {
			builder.ExtractUniqueValues(values)
		}
	})
}

// BenchmarkOldVsNewConverter compares performance of old vs new converter.
func BenchmarkOldVsNewConverter(b *testing.B) {
	testData := loadBenchmarkData(b)

	b.Run("NewMarkdownBuilder", func(b *testing.B) {
		builder := NewMarkdownBuilder()
		for b.Loop() {
			_, err := builder.BuildStandardReport(testData)
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("OldMarkdownConverter", func(b *testing.B) {
		converter := NewMarkdownConverter()
		for b.Loop() {
			_, err := converter.ToMarkdown(context.Background(), testData)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

// Helper functions for benchmarks

func loadBenchmarkData(b *testing.B) *common.CommonDevice {
	b.Helper()

	path := filepath.Join("testdata", "complete.json")
	data, err := os.ReadFile(path)
	if err != nil {
		b.Fatalf("Failed to read benchmark data file: %v", err)
	}

	var doc common.CommonDevice
	err = json.Unmarshal(data, &doc)
	if err != nil {
		b.Fatalf("Failed to unmarshal benchmark data: %v", err)
	}

	return &doc
}

// makeLargeDataset creates a large synthetic dataset for testing and benchmarking.
// This helper function generates consistent test data with:
// - 50 interfaces with IP addresses in 10.x.x.x range
// - 1000 firewall rules with varied configurations
// - 50 users with different groups and scopes
// - 200 sysctl items with tunable values.
func makeLargeDataset() *common.CommonDevice {
	doc := &common.CommonDevice{
		System: common.System{
			Hostname: "benchmark-host",
			Domain:   "benchmark.local",
			Firmware: common.Firmware{
				Version: "24.1.2",
			},
		},
		Interfaces:    make([]common.Interface, 0, 50),
		FirewallRules: make([]common.FirewallRule, 0, 1000),
		Sysctl:        make([]common.SysctlItem, 0, 200),
	}

	// Generate 50 interfaces
	for i := range 50 {
		name := fmt.Sprintf("if%d", i)
		doc.Interfaces = append(doc.Interfaces, common.Interface{
			Name:        name,
			PhysicalIf:  fmt.Sprintf("em%d", i),
			Enabled:     true,
			IPAddress:   fmt.Sprintf("10.%d.%d.1", i/255, i%255),
			Subnet:      "24",
			Description: fmt.Sprintf("Benchmark Interface %d", i),
		})
	}

	// Generate 1000 firewall rules
	for i := range 1000 {
		rule := common.FirewallRule{
			Type:        []string{"pass", "block", "reject"}[i%3],
			Description: fmt.Sprintf("Benchmark Rule %d", i+1),
			Interfaces:  []string{fmt.Sprintf("if%d", i%50)},
			IPProtocol:  []string{"inet", "inet6"}[i%2],
			Protocol:    []string{"tcp", "udp", "any"}[i%3],
			Source: common.RuleEndpoint{
				Address: []string{"any", "lan", "wan"}[i%3],
			},
			Destination: common.RuleEndpoint{
				Address: []string{"any", "lan", "wan"}[i%3],
			},
		}
		doc.FirewallRules = append(doc.FirewallRules, rule)
	}

	// Generate 50 users
	for i := range 50 {
		user := common.User{
			Name:        fmt.Sprintf("benchuser%d", i),
			Description: fmt.Sprintf("Benchmark User %d", i),
			GroupName:   []string{"wheel", "users", "admin"}[i%3],
			Scope:       []string{"system", "local"}[i%2],
		}
		doc.Users = append(doc.Users, user)
	}

	// Generate 200 sysctl items
	for i := range 200 {
		sysctl := common.SysctlItem{
			Tunable:     fmt.Sprintf("benchmark.sysctl.item%d", i),
			Value:       strconv.Itoa(i % 10),
			Description: fmt.Sprintf("Benchmark sysctl item %d", i),
		}
		doc.Sysctl = append(doc.Sysctl, sysctl)
	}

	return doc
}

func generateLargeBenchmarkData(b *testing.B) *common.CommonDevice {
	b.Helper()
	return makeLargeDataset()
}

// TestPerformanceBaselines validates that all operations meet the established performance baselines.
func TestPerformanceBaselines(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping performance baseline tests in short mode")
	}

	// Load test data
	testData := loadTestDataForPerformance(t)
	builder := NewMarkdownBuilder()

	t.Run("StandardReportGeneration", func(t *testing.T) {
		// Target: <3ms for standard configurations (accounts for CI environment variability)
		result := testing.Benchmark(func(b *testing.B) { //nolint:thelper // This is an inline benchmark function
			for b.Loop() {
				_, err := builder.BuildStandardReport(testData)
				if err != nil {
					b.Fatal(err)
				}
			}
		})

		avgTimeNs := result.NsPerOp()
		avgTimeMs := float64(avgTimeNs) / 1_000_000

		if avgTimeMs >= 3.0 {
			t.Errorf("Standard report generation took %.2fms, expected <3ms", avgTimeMs)
		}
		t.Logf("Standard report generation: %.2fμs (target: <3000μs)", float64(avgTimeNs)/1_000)
	})

	t.Run("SystemSectionGeneration", func(t *testing.T) {
		// Target: <500μs for system information (accounts for CI environment variability)
		result := testing.Benchmark(func(b *testing.B) { //nolint:thelper // This is an inline benchmark function
			for b.Loop() {
				_ = builder.BuildSystemSection(testData)
			}
		})

		avgTimeNs := result.NsPerOp()
		avgTimeUs := float64(avgTimeNs) / 1_000

		if avgTimeUs >= 500 {
			t.Errorf("System section generation took %.2fμs, expected <500μs", avgTimeUs)
		}
		t.Logf("System section generation: %.2fμs (target: <500μs)", avgTimeUs)
	})

	t.Run("NetworkSectionGeneration", func(t *testing.T) {
		// Target: <200μs for network configuration (accounts for CI environment variability)
		result := testing.Benchmark(func(b *testing.B) { //nolint:thelper // This is an inline benchmark function
			for b.Loop() {
				_ = builder.BuildNetworkSection(testData)
			}
		})

		avgTimeNs := result.NsPerOp()
		avgTimeUs := float64(avgTimeNs) / 1_000

		if avgTimeUs >= 200 {
			t.Errorf("Network section generation took %.2fμs, expected <200μs", avgTimeUs)
		}
		t.Logf("Network section generation: %.2fμs (target: <200μs)", avgTimeUs)
	})

	t.Run("SecuritySectionGeneration", func(t *testing.T) {
		// Target: <1ms for security assessment (accounts for CI environment variability)
		result := testing.Benchmark(func(b *testing.B) { //nolint:thelper // This is an inline benchmark function
			for b.Loop() {
				_ = builder.BuildSecuritySection(testData)
			}
		})

		avgTimeNs := result.NsPerOp()
		avgTimeUs := float64(avgTimeNs) / 1_000

		if avgTimeUs >= 1000 {
			t.Errorf("Security section generation took %.2fμs, expected <1000μs", avgTimeUs)
		}
		t.Logf("Security section generation: %.2fμs (target: <1000μs)", avgTimeUs)
	})

	t.Run("ServicesSection", func(t *testing.T) {
		// Target: <250μs for service configuration (with tolerance for CI environments)
		result := testing.Benchmark(func(b *testing.B) { //nolint:thelper // This is an inline benchmark function
			for b.Loop() {
				_ = builder.BuildServicesSection(testData)
			}
		})

		avgTimeNs := result.NsPerOp()
		avgTimeUs := float64(avgTimeNs) / 1_000

		if avgTimeUs >= 250 {
			t.Errorf("Services section generation took %.2fμs, expected <250μs", avgTimeUs)
		}
		t.Logf("Services section generation: %.2fμs (target: <250μs)", avgTimeUs)
	})

	t.Run("LargeDatasetProcessing", func(t *testing.T) {
		// Target: <100ms for enterprise configurations (large datasets with 1000+ rules, 50+ interfaces)
		largeData := createLargeTestDataset(t)

		result := testing.Benchmark(func(b *testing.B) { //nolint:thelper // This is an inline benchmark function
			for b.Loop() {
				_, err := builder.BuildComprehensiveReport(largeData)
				if err != nil {
					b.Fatal(err)
				}
			}
		})

		avgTimeNs := result.NsPerOp()
		avgTimeMs := float64(avgTimeNs) / 1_000_000

		if avgTimeMs >= 100.0 {
			t.Errorf("Large dataset processing took %.2fms, expected <100ms", avgTimeMs)
		}
		t.Logf("Large dataset processing: %.2fms (target: <100ms)", avgTimeMs)
	})
}

// loadTestDataForPerformance loads data appropriate for performance testing.
func loadTestDataForPerformance(t *testing.T) *common.CommonDevice {
	t.Helper()

	// Try to load from testdata first
	testdataPath := filepath.Join("testdata", "complete.json")
	if data, err := os.ReadFile(testdataPath); err == nil {
		var doc common.CommonDevice
		if err := json.Unmarshal(data, &doc); err == nil {
			return &doc
		}
	}

	// Fall back to creating synthetic data
	return createLargeTestDataset(t)
}

// createLargeTestDataset creates a large dataset for performance testing.
func createLargeTestDataset(t *testing.T) *common.CommonDevice {
	t.Helper()
	return makeLargeDataset()
}
