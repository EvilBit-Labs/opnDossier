package processor

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/cfgparser"
	"github.com/EvilBit-Labs/opnDossier/internal/model"
)

func TestGatewayGroupsInReports(t *testing.T) {
	// Load test configuration from external file
	xmlData, err := os.ReadFile("testdata/gateway_groups_basic.xml")
	if err != nil {
		t.Fatalf("Failed to read test data file: %v", err)
	}
	xmlConfig := string(xmlData)

	// Parse the configuration
	xmlParser := cfgparser.NewXMLParser()
	cfg, err := xmlParser.Parse(context.Background(), strings.NewReader(xmlConfig))
	if err != nil {
		t.Fatalf("Failed to parse XML configuration: %v", err)
	}

	// Create a report
	processorConfig := Config{EnableStats: true}
	report := NewReport(cfg, processorConfig)

	// Test that gateway groups are included in statistics
	if report.Statistics.TotalGateways != 2 {
		t.Errorf("Expected 2 gateways, got %d", report.Statistics.TotalGateways)
	}

	if report.Statistics.TotalGatewayGroups != 2 {
		t.Errorf("Expected 2 gateway groups, got %d", report.Statistics.TotalGatewayGroups)
	}

	// Test that gateway groups are included in total config items
	expectedTotalItems := 2 + 2 + 1 + 1 + 1 // interfaces + gateways + gateway groups + firewall rules + nat
	if report.Statistics.Summary.TotalConfigItems < expectedTotalItems {
		t.Errorf(
			"Expected at least %d total config items, got %d",
			expectedTotalItems,
			report.Statistics.Summary.TotalConfigItems,
		)
	}

	// Test that gateway groups are included in complexity calculation
	if report.Statistics.Summary.ConfigComplexity == 0 {
		t.Error("Expected non-zero config complexity when gateway groups are present")
	}

	// Test that the configuration has the expected gateway groups
	if len(cfg.Gateways.Groups) != 2 {
		t.Errorf("Expected 2 gateway groups in configuration, got %d", len(cfg.Gateways.Groups))
	}

	// Test the first gateway group
	if cfg.Gateways.Groups[0].Name != "WAN_FAILOVER" {
		t.Errorf("Expected first gateway group name to be 'WAN_FAILOVER', got '%s'", cfg.Gateways.Groups[0].Name)
	}

	if cfg.Gateways.Groups[0].Descr != "WAN Failover Group" {
		t.Errorf(
			"Expected first gateway group description to be 'WAN Failover Group', got '%s'",
			cfg.Gateways.Groups[0].Descr,
		)
	}

	if len(cfg.Gateways.Groups[0].Item) != 2 {
		t.Errorf("Expected first gateway group to have 2 items, got %d", len(cfg.Gateways.Groups[0].Item))
	}

	if cfg.Gateways.Groups[0].Trigger != "member" {
		t.Errorf("Expected first gateway group trigger to be 'member', got '%s'", cfg.Gateways.Groups[0].Trigger)
	}

	// Test the second gateway group
	if cfg.Gateways.Groups[1].Name != "WAN_LOADBALANCE" {
		t.Errorf("Expected second gateway group name to be 'WAN_LOADBALANCE', got '%s'", cfg.Gateways.Groups[1].Name)
	}

	if cfg.Gateways.Groups[1].Descr != "WAN Load Balancing Group" {
		t.Errorf(
			"Expected second gateway group description to be 'WAN Load Balancing Group', got '%s'",
			cfg.Gateways.Groups[1].Descr,
		)
	}

	if len(cfg.Gateways.Groups[1].Item) != 2 {
		t.Errorf("Expected second gateway group to have 2 items, got %d", len(cfg.Gateways.Groups[1].Item))
	}

	if cfg.Gateways.Groups[1].Trigger != "down" {
		t.Errorf("Expected second gateway group trigger to be 'down', got '%s'", cfg.Gateways.Groups[1].Trigger)
	}
}

func TestGatewayGroupsInEnrichedDocument(t *testing.T) {
	// Load test configuration from external file
	xmlData, err := os.ReadFile("testdata/gateway_groups_enriched.xml")
	if err != nil {
		t.Fatalf("Failed to read test data file: %v", err)
	}
	xmlConfig := string(xmlData)

	// Parse the configuration
	xmlParser := cfgparser.NewXMLParser()
	cfg, err := xmlParser.Parse(context.Background(), strings.NewReader(xmlConfig))
	if err != nil {
		t.Fatalf("Failed to parse XML configuration: %v", err)
	}

	// Create enriched document
	enriched := model.EnrichDocument(cfg)
	if enriched == nil {
		t.Fatal("Failed to create enriched document")
	}

	// Test that gateway groups are included in enriched statistics
	if enriched.Statistics.TotalGateways != 1 {
		t.Errorf("Expected 1 gateway, got %d", enriched.Statistics.TotalGateways)
	}

	if enriched.Statistics.TotalGatewayGroups != 1 {
		t.Errorf("Expected 1 gateway group, got %d", enriched.Statistics.TotalGatewayGroups)
	}

	// Test that gateway groups are included in total config items
	expectedTotalItems := 2 + 1 + 1 + 1 // interfaces + gateways + gateway groups + firewall rules
	t.Logf("Total config items: %d", enriched.Statistics.Summary.TotalConfigItems)
	t.Logf("Interfaces: %d", enriched.Statistics.TotalInterfaces)
	t.Logf("Gateways: %d", enriched.Statistics.TotalGateways)
	t.Logf("Gateway Groups: %d", enriched.Statistics.TotalGatewayGroups)
	t.Logf("Firewall Rules: %d", enriched.Statistics.TotalFirewallRules)
	t.Logf("Services: %d", enriched.Statistics.TotalServices)
	if enriched.Statistics.Summary.TotalConfigItems < expectedTotalItems {
		t.Errorf(
			"Expected at least %d total config items, got %d",
			expectedTotalItems,
			enriched.Statistics.Summary.TotalConfigItems,
		)
	}

	// Test that gateway groups are included in complexity calculation
	if enriched.Statistics.Summary.ConfigComplexity == 0 {
		t.Error("Expected non-zero config complexity when gateway groups are present")
	}
}
