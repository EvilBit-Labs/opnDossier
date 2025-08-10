package processor

import (
	"context"
	"strings"
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/model"
	"github.com/EvilBit-Labs/opnDossier/internal/parser"
)

func TestGatewayGroupsInReports(t *testing.T) {
	// Test configuration with gateway groups
	xmlConfig := `<?xml version="1.0"?>
<opnsense>
  <version>24.1.3</version>
  <system>
    <hostname>test-firewall</hostname>
    <domain>example.com</domain>
    <timezone>UTC</timezone>
    <webgui>
      <protocol>https</protocol>
    </webgui>
  </system>
  <interfaces>
    <wan>
      <enable>1</enable>
      <if>em0</if>
      <ipaddr>192.0.2.1</ipaddr>
      <subnet>24</subnet>
      <gateway>192.0.2.254</gateway>
    </wan>
    <lan>
      <enable>1</enable>
      <if>em1</if>
      <ipaddr>10.0.1.1</ipaddr>
      <subnet>24</subnet>
    </lan>
  </interfaces>
  <gateways>
    <gateway_item>
      <name>WAN_GW</name>
      <descr>WAN Gateway</descr>
      <interface>wan</interface>
      <gateway>192.0.2.254</gateway>
      <ipprotocol>inet</ipprotocol>
      <defaultgw>1</defaultgw>
      <monitor_disable>0</monitor_disable>
      <interval>1</interval>
      <weight>1</weight>
      <fargw>0</fargw>
    </gateway_item>
    <gateway_item>
      <name>WAN_GW2</name>
      <descr>WAN Gateway 2</descr>
      <interface>wan</interface>
      <gateway>192.0.2.253</gateway>
      <ipprotocol>inet</ipprotocol>
      <defaultgw>0</defaultgw>
      <monitor_disable>0</monitor_disable>
      <interval>1</interval>
      <weight>1</weight>
      <fargw>0</fargw>
    </gateway_item>
    <gateway_group>
      <name>WAN_FAILOVER</name>
      <descr>WAN Failover Group</descr>
      <item>WAN_GW</item>
      <item>WAN_GW2</item>
      <trigger>member</trigger>
    </gateway_group>
    <gateway_group>
      <name>WAN_LOADBALANCE</name>
      <descr>WAN Load Balancing Group</descr>
      <item>WAN_GW</item>
      <item>WAN_GW2</item>
      <trigger>down</trigger>
    </gateway_group>
  </gateways>
  <filter>
    <rule>
      <type>pass</type>
      <interface>wan</interface>
      <ipprotocol>inet</ipprotocol>
      <descr>Allow WAN traffic</descr>
    </rule>
  </filter>
  <nat>
    <outbound>
      <mode>automatic</mode>
    </outbound>
  </nat>
  <revision>
    <time>1753586994.3946</time>
    <description>Test configuration with gateway groups</description>
  </revision>
</opnsense>`

	// Parse the configuration
	xmlParser := parser.NewXMLParser()
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
	// Test configuration with gateway groups
	xmlConfig := `<?xml version="1.0"?>
<opnsense>
  <version>24.1.3</version>
  <system>
    <hostname>test-firewall</hostname>
    <domain>example.com</domain>
    <timezone>UTC</timezone>
    <webgui>
      <protocol>https</protocol>
    </webgui>
  </system>
  <interfaces>
    <wan>
      <enable>1</enable>
      <if>em0</if>
      <ipaddr>192.0.2.1</ipaddr>
      <subnet>24</subnet>
      <gateway>192.0.2.254</gateway>
    </wan>
    <lan>
      <enable>1</enable>
      <if>em1</if>
      <ipaddr>10.0.1.1</ipaddr>
      <subnet>24</subnet>
    </lan>
  </interfaces>
  <gateways>
    <gateway_item>
      <name>WAN_GW</name>
      <descr>WAN Gateway</descr>
      <interface>wan</interface>
      <gateway>192.0.2.254</gateway>
      <ipprotocol>inet</ipprotocol>
      <defaultgw>1</defaultgw>
      <monitor_disable>0</monitor_disable>
      <interval>1</interval>
      <weight>1</weight>
      <fargw>0</fargw>
    </gateway_item>
    <gateway_group>
      <name>WAN_FAILOVER</name>
      <descr>WAN Failover Group</descr>
      <item>WAN_GW</item>
      <trigger>member</trigger>
    </gateway_group>
  </gateways>
  <filter>
    <rule>
      <type>pass</type>
      <interface>wan</interface>
      <ipprotocol>inet</ipprotocol>
      <descr>Allow WAN traffic</descr>
    </rule>
  </filter>
  <nat>
    <outbound>
      <mode>automatic</mode>
    </outbound>
  </nat>
  <revision>
    <time>1753586994.3946</time>
    <description>Test configuration with gateway groups</description>
  </revision>
</opnsense>`

	// Parse the configuration
	xmlParser := parser.NewXMLParser()
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
