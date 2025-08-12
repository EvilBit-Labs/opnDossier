package converter

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/model"
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
	builder := NewMarkdownBuilder()

	b.ResetTimer()
	for b.Loop() {
		_ = builder.BuildFirewallRulesTable(testData.Filter.Rule)
	}
}

// BenchmarkMarkdownBuilder_InterfaceTable benchmarks interface table generation.
func BenchmarkMarkdownBuilder_InterfaceTable(b *testing.B) {
	testData := loadBenchmarkData(b)
	builder := NewMarkdownBuilder()

	b.ResetTimer()
	for b.Loop() {
		_ = builder.BuildInterfaceTable(testData.Interfaces)
	}
}

// BenchmarkMarkdownBuilder_UserTable benchmarks user table generation.
func BenchmarkMarkdownBuilder_UserTable(b *testing.B) {
	testData := loadBenchmarkData(b)
	builder := NewMarkdownBuilder()

	b.ResetTimer()
	for b.Loop() {
		_ = builder.BuildUserTable(testData.System.User)
	}
}

// BenchmarkMarkdownBuilder_SysctlTable benchmarks sysctl table generation.
func BenchmarkMarkdownBuilder_SysctlTable(b *testing.B) {
	testData := loadBenchmarkData(b)
	builder := NewMarkdownBuilder()

	b.ResetTimer()
	for b.Loop() {
		_ = builder.BuildSysctlTable(testData.Sysctl)
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
		services := []model.Service{
			{Name: "telnet"},
			{Name: "ftp"},
			{Name: "ssh"},
			{Name: "https"},
			{Name: "unknown"},
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

	b.Run("GroupServicesByStatus", func(b *testing.B) {
		services := []model.Service{
			{Name: "apache", Status: "running"},
			{Name: "nginx", Status: "stopped"},
			{Name: "mysql", Status: "running"},
			{Name: "redis", Status: "disabled"},
		}
		for b.Loop() {
			builder.GroupServicesByStatus(services)
		}
	})

	b.Run("FilterRulesByType", func(b *testing.B) {
		for b.Loop() {
			builder.FilterRulesByType(testData.Filter.Rule, "pass")
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

func loadBenchmarkData(b *testing.B) *model.OpnSenseDocument {
	b.Helper()

	path := filepath.Join("testdata", "complete.json")
	data, err := os.ReadFile(path)
	if err != nil {
		b.Fatalf("Failed to read benchmark data file: %v", err)
	}

	var doc model.OpnSenseDocument
	err = json.Unmarshal(data, &doc) //nolint:musttag // JSON tags not required for test data
	if err != nil {
		b.Fatalf("Failed to unmarshal benchmark data: %v", err)
	}

	return &doc
}

func generateLargeBenchmarkData(b *testing.B) *model.OpnSenseDocument {
	b.Helper()

	doc := &model.OpnSenseDocument{
		System: model.System{
			Hostname: "benchmark-host",
			Domain:   "benchmark.local",
			Firmware: model.Firmware{
				Version: "24.1.2",
			},
		},
		Interfaces: model.Interfaces{
			Items: make(map[string]model.Interface),
		},
		Filter: model.Filter{
			Rule: make([]model.Rule, 0, 1000),
		},
		Sysctl: make([]model.SysctlItem, 0, 200),
	}

	// Generate 50 interfaces
	for i := range 50 {
		name := fmt.Sprintf("if%d", i)
		doc.Interfaces.Items[name] = model.Interface{
			If:     fmt.Sprintf("em%d", i),
			Enable: "1",
			IPAddr: fmt.Sprintf("10.%d.%d.1", i/255, i%255),
			Subnet: "24",
			Descr:  fmt.Sprintf("Benchmark Interface %d", i),
		}
	}

	// Generate 1000 firewall rules
	for i := range 1000 {
		rule := model.Rule{
			Type:       []string{"pass", "block", "reject"}[i%3],
			Descr:      fmt.Sprintf("Benchmark Rule %d", i+1),
			Interface:  model.InterfaceList{fmt.Sprintf("if%d", i%50)},
			IPProtocol: []string{"inet", "inet6"}[i%2],
			Protocol:   []string{"tcp", "udp", "any"}[i%3],
			Source: model.Source{
				Network: []string{"any", "lan", "wan"}[i%3],
			},
			Destination: model.Destination{
				Network: []string{"any", "lan", "wan"}[i%3],
			},
		}
		doc.Filter.Rule = append(doc.Filter.Rule, rule)
	}

	// Generate 50 users
	for i := range 50 {
		user := model.User{
			Name:      fmt.Sprintf("benchuser%d", i),
			Descr:     fmt.Sprintf("Benchmark User %d", i),
			Groupname: []string{"wheel", "users", "admin"}[i%3],
			Scope:     []string{"system", "local"}[i%2],
		}
		doc.System.User = append(doc.System.User, user)
	}

	// Generate 200 sysctl items
	for i := range 200 {
		sysctl := model.SysctlItem{
			Tunable: fmt.Sprintf("benchmark.sysctl.item%d", i),
			Value:   strconv.Itoa(i % 10),
			Descr:   fmt.Sprintf("Benchmark sysctl item %d", i),
		}
		doc.Sysctl = append(doc.Sysctl, sysctl)
	}

	return doc
}
