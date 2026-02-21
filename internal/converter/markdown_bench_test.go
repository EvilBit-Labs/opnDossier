package converter

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/model"
	"github.com/EvilBit-Labs/opnDossier/internal/model/common"
)

// loadTestData loads test configuration data by parsing an XML file and converting
// to CommonDevice format via the ParserFactory.
func loadTestData(filename string) *common.CommonDevice {
	// Map test data size indicators to actual test files
	var xmlFile string
	switch filename {
	case "testdata/minimal.json":
		xmlFile = filepath.Join("..", "..", "testdata", "sample.config.1.xml") // ~12KB
	case "testdata/complete.json":
		xmlFile = filepath.Join("..", "..", "testdata", "sample.config.2.xml") // ~17KB
	case "testdata/large.json":
		xmlFile = filepath.Join("..", "..", "testdata", "sample.config.6.xml") // ~119KB
	default:
		// Default to medium size
		xmlFile = filepath.Join("..", "..", "testdata", "sample.config.2.xml")
	}

	xmlData, err := os.ReadFile(xmlFile)
	if err != nil {
		panic("Failed to read test XML file: " + err.Error())
	}

	factory := model.NewParserFactory()
	device, err := factory.CreateDevice(
		context.Background(),
		strings.NewReader(string(xmlData)),
		"opnsense",
		false,
	)
	if err != nil {
		panic("XML parsing/conversion failed: " + err.Error())
	}

	return device
}

// loadCompleteTestData loads a complete test dataset for individual method testing.
func loadCompleteTestData() *common.CommonDevice {
	return loadTestData("testdata/complete.json")
}

// loadLargeTestData loads a large test dataset for memory usage testing.
func loadLargeTestData() *common.CommonDevice {
	return loadTestData("testdata/large.json")
}

// BenchmarkReportGeneration benchmarks report generation comparing original vs programmatic approaches.
func BenchmarkReportGeneration(b *testing.B) {
	small := loadTestData("testdata/minimal.json")
	medium := loadTestData("testdata/complete.json")
	large := loadTestData("testdata/large.json")

	// Define the context once for reuse
	ctx := context.Background()

	b.Run("Small/Programmatic", func(b *testing.B) {
		builder := NewMarkdownBuilder()
		b.ResetTimer()
		for b.Loop() {
			if _, err := builder.BuildStandardReport(small); err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("Small/Original", func(b *testing.B) {
		converter := NewMarkdownConverter()
		b.ResetTimer()
		for b.Loop() {
			if _, err := converter.ToMarkdown(ctx, small); err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("Medium/Programmatic", func(b *testing.B) {
		builder := NewMarkdownBuilder()
		b.ResetTimer()
		for b.Loop() {
			if _, err := builder.BuildStandardReport(medium); err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("Medium/Original", func(b *testing.B) {
		converter := NewMarkdownConverter()
		b.ResetTimer()
		for b.Loop() {
			if _, err := converter.ToMarkdown(ctx, medium); err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("Large/Programmatic", func(b *testing.B) {
		builder := NewMarkdownBuilder()
		b.ResetTimer()
		for b.Loop() {
			if _, err := builder.BuildStandardReport(large); err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("Large/Original", func(b *testing.B) {
		converter := NewMarkdownConverter()
		b.ResetTimer()
		for b.Loop() {
			if _, err := converter.ToMarkdown(ctx, large); err != nil {
				b.Fatal(err)
			}
		}
	})
}

// BenchmarkIndividualMethods benchmarks individual transformation methods.
func BenchmarkIndividualMethods(b *testing.B) {
	builder := NewMarkdownBuilder()
	testData := loadCompleteTestData()

	b.Run("AssessRiskLevel", func(b *testing.B) {
		for b.Loop() {
			_ = builder.AssessRiskLevel("high")
		}
	})

	b.Run("FilterSystemTunables", func(b *testing.B) {
		tunables := testData.Sysctl
		b.ResetTimer()
		for b.Loop() {
			_ = builder.FilterSystemTunables(tunables, false)
		}
	})

	b.Run("CalculateSecurityScore", func(b *testing.B) {
		for b.Loop() {
			_ = builder.CalculateSecurityScore(testData)
		}
	})

	b.Run("BuildSystemSection", func(b *testing.B) {
		for b.Loop() {
			_ = builder.BuildSystemSection(testData)
		}
	})

	b.Run("BuildNetworkSection", func(b *testing.B) {
		for b.Loop() {
			_ = builder.BuildNetworkSection(testData)
		}
	})

	b.Run("BuildSecuritySection", func(b *testing.B) {
		for b.Loop() {
			_ = builder.BuildSecuritySection(testData)
		}
	})

	b.Run("BuildServicesSection", func(b *testing.B) {
		for b.Loop() {
			_ = builder.BuildServicesSection(testData)
		}
	})
}

// BenchmarkMemoryUsage benchmarks memory allocation patterns.
func BenchmarkMemoryUsage(b *testing.B) {
	data := loadLargeTestData()
	ctx := context.Background()

	b.Run("Programmatic", func(b *testing.B) {
		builder := NewMarkdownBuilder()
		b.ReportAllocs()
		b.ResetTimer()
		for b.Loop() {
			if _, err := builder.BuildStandardReport(data); err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("Original", func(b *testing.B) {
		converter := NewMarkdownConverter()
		b.ReportAllocs()
		b.ResetTimer()
		for b.Loop() {
			if _, err := converter.ToMarkdown(ctx, data); err != nil {
				b.Fatal(err)
			}
		}
	})
}

// BenchmarkThroughput measures reports generated per second.
func BenchmarkThroughput(b *testing.B) {
	medium := loadTestData("testdata/complete.json")
	ctx := context.Background()

	b.Run("Programmatic_Throughput", func(b *testing.B) {
		builder := NewMarkdownBuilder()
		b.ResetTimer()
		for b.Loop() {
			if _, err := builder.BuildStandardReport(medium); err != nil {
				b.Fatal(err)
			}
		}
		// Calculate and report throughput
		throughput := float64(b.N) / b.Elapsed().Seconds()
		b.ReportMetric(throughput, "reports/sec")
	})

	b.Run("Original_Throughput", func(b *testing.B) {
		converter := NewMarkdownConverter()
		b.ResetTimer()
		for b.Loop() {
			if _, err := converter.ToMarkdown(ctx, medium); err != nil {
				b.Fatal(err)
			}
		}
		// Calculate and report throughput
		throughput := float64(b.N) / b.Elapsed().Seconds()
		b.ReportMetric(throughput, "reports/sec")
	})
}

// BenchmarkConcurrentGeneration tests performance under concurrent load.
func BenchmarkConcurrentGeneration(b *testing.B) {
	medium := loadTestData("testdata/complete.json")
	ctx := context.Background()

	b.Run("Programmatic_Concurrent", func(b *testing.B) {
		b.RunParallel(func(pb *testing.PB) {
			builder := NewMarkdownBuilder()
			for pb.Next() {
				if _, err := builder.BuildStandardReport(medium); err != nil {
					b.Error(err)
				}
			}
		})
	})

	b.Run("Original_Concurrent", func(b *testing.B) {
		b.RunParallel(func(pb *testing.PB) {
			converter := NewMarkdownConverter()
			for pb.Next() {
				if _, err := converter.ToMarkdown(ctx, medium); err != nil {
					b.Error(err)
				}
			}
		})
	})
}
