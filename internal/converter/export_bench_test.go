package converter

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/cfgparser"
	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
	"github.com/EvilBit-Labs/opnDossier/pkg/parser"
	_ "github.com/EvilBit-Labs/opnDossier/pkg/parser/opnsense" // self-registers OPNsense parser via init()
)

// loadTestData loads test configuration data by parsing an XML file and converting
// to CommonDevice format via the Factory.
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

	factory := parser.NewFactory(cfgparser.NewXMLParser())
	device, _, err := factory.CreateDevice(
		context.Background(),
		strings.NewReader(string(xmlData)),
		common.DeviceTypeOPNsense,
		false,
	)
	if err != nil {
		panic("XML parsing/conversion failed: " + err.Error())
	}

	return device
}

// loadLargeTestData loads a large test dataset for memory usage testing.
func loadLargeTestData() *common.CommonDevice {
	return loadTestData("testdata/large.json")
}

func BenchmarkJSONConverter_ToJSON(b *testing.B) {
	ctx := context.Background()
	converter := NewJSONConverter()
	device := loadLargeTestData()

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if _, err := converter.ToJSON(ctx, device, false); err != nil {
			b.Fatalf("ToJSON failed: %v", err)
		}
	}
}

func BenchmarkYAMLConverter_ToYAML(b *testing.B) {
	ctx := context.Background()
	converter := NewYAMLConverter()
	device := loadLargeTestData()

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if _, err := converter.ToYAML(ctx, device, false); err != nil {
			b.Fatalf("ToYAML failed: %v", err)
		}
	}
}

// BenchmarkEnterpriseScaleExport_10kRules_500KiB locks in the NATS-39
// enterprise-scale fixture: at least 10,000 firewall rules and at least 500 KiB
// of serialized configuration. It runs JSON and YAML export paths to verify
// linear scaling of the serialization hot paths under a large realistic rule set.
func BenchmarkEnterpriseScaleExport_10kRules_500KiB(b *testing.B) {
	const (
		ruleCount = 10_000
		minSize   = 500 * 1024
	)

	ctx := context.Background()
	device := makeEnterpriseExportDataset(ruleCount)
	if got := len(device.FirewallRules); got != ruleCount {
		b.Fatalf("FirewallRules: got %d, want %d", got, ruleCount)
	}

	jsonConverter := NewJSONConverter()
	yamlConverter := NewYAMLConverter()

	jsonOut, err := jsonConverter.ToJSON(ctx, device, false)
	if err != nil {
		b.Fatalf("ToJSON sanity check failed: %v", err)
	}
	if len(jsonOut) < minSize {
		b.Fatalf("JSON enterprise fixture is %d bytes, want at least %d", len(jsonOut), minSize)
	}

	yamlOut, err := yamlConverter.ToYAML(ctx, device, false)
	if err != nil {
		b.Fatalf("ToYAML sanity check failed: %v", err)
	}
	if len(yamlOut) < minSize {
		b.Fatalf("YAML enterprise fixture is %d bytes, want at least %d", len(yamlOut), minSize)
	}

	b.Run("json", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			if _, err := jsonConverter.ToJSON(ctx, device, false); err != nil {
				b.Fatalf("ToJSON failed: %v", err)
			}
		}
	})

	b.Run("yaml", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			if _, err := yamlConverter.ToYAML(ctx, device, false); err != nil {
				b.Fatalf("ToYAML failed: %v", err)
			}
		}
	})
}

func makeEnterpriseExportDataset(ruleCount int) *common.CommonDevice {
	device := makeLargeDataset()
	device.FirewallRules = make([]common.FirewallRule, 0, ruleCount)

	for i := range ruleCount {
		device.FirewallRules = append(device.FirewallRules, common.FirewallRule{
			UUID:       fmt.Sprintf("enterprise-rule-%05d", i),
			Type:       []common.FirewallRuleType{common.RuleTypePass, common.RuleTypeBlock, common.RuleTypeReject}[i%3],
			IPProtocol: []common.IPProtocol{common.IPProtocolInet, common.IPProtocolInet6}[i%2],
			Protocol:   []string{"tcp", "udp", "icmp"}[i%3],
			Interfaces: []string{fmt.Sprintf("if%d", i%50)},
			Source:     common.RuleEndpoint{Address: fmt.Sprintf("10.%d.%d.0/24", (i/256)%256, i%256), Port: "any"},
			Destination: common.RuleEndpoint{
				Address: fmt.Sprintf("172.16.%d.%d", (i/256)%256, i%256),
				Port:    strconv.Itoa(1024 + (i % 64512)),
			},
			Description: fmt.Sprintf("enterprise benchmark rule %05d for linear scaling verification", i),
			Disabled:    i%17 == 0,
			Log:         i%5 == 0,
		})
	}

	return device
}
