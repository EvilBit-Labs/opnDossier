package processor

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/model"
)

func TestGatewayGroupsInReports(t *testing.T) {
	// Load test configuration from external file
	xmlData, err := os.ReadFile("testdata/gateway_groups_basic.xml")
	if err != nil {
		t.Fatalf("Failed to read test data file: %v", err)
	}
	xmlConfig := string(xmlData)

	// Parse the configuration via factory
	factory := model.NewParserFactory()
	cfg, err := factory.CreateDevice(context.Background(), strings.NewReader(xmlConfig), "", false)
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
	if len(cfg.Routing.GatewayGroups) != 2 {
		t.Errorf("Expected 2 gateway groups in configuration, got %d", len(cfg.Routing.GatewayGroups))
	}

	// Test the first gateway group
	if cfg.Routing.GatewayGroups[0].Name != "WAN_FAILOVER" {
		t.Errorf("Expected first gateway group name to be 'WAN_FAILOVER', got '%s'", cfg.Routing.GatewayGroups[0].Name)
	}

	if cfg.Routing.GatewayGroups[0].Description != "WAN Failover Group" {
		t.Errorf(
			"Expected first gateway group description to be 'WAN Failover Group', got '%s'",
			cfg.Routing.GatewayGroups[0].Description,
		)
	}

	if len(cfg.Routing.GatewayGroups[0].Items) != 2 {
		t.Errorf("Expected first gateway group to have 2 items, got %d", len(cfg.Routing.GatewayGroups[0].Items))
	}

	if cfg.Routing.GatewayGroups[0].Trigger != "member" {
		t.Errorf("Expected first gateway group trigger to be 'member', got '%s'", cfg.Routing.GatewayGroups[0].Trigger)
	}

	// Test the second gateway group
	if cfg.Routing.GatewayGroups[1].Name != "WAN_LOADBALANCE" {
		t.Errorf(
			"Expected second gateway group name to be 'WAN_LOADBALANCE', got '%s'",
			cfg.Routing.GatewayGroups[1].Name,
		)
	}

	if cfg.Routing.GatewayGroups[1].Description != "WAN Load Balancing Group" {
		t.Errorf(
			"Expected second gateway group description to be 'WAN Load Balancing Group', got '%s'",
			cfg.Routing.GatewayGroups[1].Description,
		)
	}

	if len(cfg.Routing.GatewayGroups[1].Items) != 2 {
		t.Errorf("Expected second gateway group to have 2 items, got %d", len(cfg.Routing.GatewayGroups[1].Items))
	}

	if cfg.Routing.GatewayGroups[1].Trigger != "down" {
		t.Errorf("Expected second gateway group trigger to be 'down', got '%s'", cfg.Routing.GatewayGroups[1].Trigger)
	}
}
