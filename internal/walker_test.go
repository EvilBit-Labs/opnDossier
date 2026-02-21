package internal

import (
	"strings"
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/model/common"
)

func TestWalk_BasicStructure(t *testing.T) {
	device := common.CommonDevice{
		Version: "24.7",
		System: common.System{
			Hostname: "firewall.local",
			Domain:   "example.com",
		},
	}

	result := Walk(device)

	if result.Level != 1 {
		t.Errorf("Expected root level 1, got %d", result.Level)
	}

	if result.Title != "# Device Configuration" {
		t.Errorf("Expected root title '# Device Configuration', got '%s'", result.Title)
	}

	if !strings.Contains(result.Body, "Version: 24.7") {
		t.Errorf("Expected Version in body, got: %s", result.Body)
	}

	found := false

	for _, child := range result.Children {
		if !strings.Contains(child.Title, "System") {
			continue
		}

		found = true

		if child.Level != 2 {
			t.Errorf("Expected System child level 2, got %d", child.Level)
		}

		if !strings.Contains(child.Body, "Hostname: firewall.local") {
			t.Errorf("Expected Hostname in System body, got: %s", child.Body)
		}

		if !strings.Contains(child.Body, "Domain: example.com") {
			t.Errorf("Expected Domain in System body, got: %s", child.Body)
		}

		break
	}

	if !found {
		t.Error("Expected System child node not found")
	}
}

func TestWalk_DepthLimiting(t *testing.T) {
	device := common.CommonDevice{
		System: common.System{
			WebGUI: common.WebGUI{Protocol: "https"},
		},
	}

	result := Walk(device)

	var findMaxLevel func(node MDNode) int

	findMaxLevel = func(node MDNode) int {
		maxLevel := node.Level
		for _, child := range node.Children {
			childMaxLevel := findMaxLevel(child)
			if childMaxLevel > maxLevel {
				maxLevel = childMaxLevel
			}
		}

		return maxLevel
	}

	maxLevel := findMaxLevel(result)
	if maxLevel > 6 {
		t.Errorf("Expected maximum level 6, got %d", maxLevel)
	}
}

func TestWalk_BoolFieldHandling(t *testing.T) {
	device := common.CommonDevice{
		System: common.System{
			Hostname:           "test.local",
			Domain:             "test.com",
			DisableConsoleMenu: true,
			IPv6Allow:          true,
		},
	}

	result := Walk(device)

	var systemNode *MDNode

	for _, child := range result.Children {
		if strings.Contains(child.Title, "System") {
			systemNode = &child
			break
		}
	}

	if systemNode == nil {
		t.Fatal("System node not found")
	}

	if !strings.Contains(systemNode.Body, "Disable Console Menu: enabled") {
		t.Errorf("Expected 'Disable Console Menu: enabled' in body, got: %s", systemNode.Body)
	}

	if !strings.Contains(systemNode.Body, "IPv6 Allow: enabled") {
		t.Errorf("Expected 'IPv6 Allow: enabled' in body, got: %s", systemNode.Body)
	}
}

func TestWalk_SliceHandling(t *testing.T) {
	device := common.CommonDevice{
		Sysctl: []common.SysctlItem{
			{
				Tunable:     "net.inet.tcp.rfc3390",
				Value:       "1",
				Description: "TCP RFC 3390",
			},
			{
				Tunable:     "kern.ipc.maxsockbuf",
				Value:       "16777216",
				Description: "Maximum socket buffer size",
			},
		},
	}

	result := Walk(device)

	var sysctlNode *MDNode

	for _, child := range result.Children {
		if strings.Contains(child.Title, "Sysctl") {
			sysctlNode = &child
			break
		}
	}

	if sysctlNode == nil {
		t.Fatal("Sysctl node not found")
	}

	if len(sysctlNode.Children) != 2 {
		t.Errorf("Expected 2 Sysctl children, got %d", len(sysctlNode.Children))
	}

	firstItem := sysctlNode.Children[0]
	if !strings.Contains(firstItem.Title, "[0]") {
		t.Errorf("Expected first item to contain '[0]', got: %s", firstItem.Title)
	}

	if !strings.Contains(firstItem.Body, "net.inet.tcp.rfc3390") {
		t.Errorf("Expected tunable in first item body, got: %s", firstItem.Body)
	}
}

func TestWalk_InterfaceSliceHandling(t *testing.T) {
	device := common.CommonDevice{
		Interfaces: []common.Interface{
			{
				Name:       "wan",
				PhysicalIf: "em0",
				IPAddress:  "192.168.1.100",
				Subnet:     "24",
				Enabled:    true,
			},
			{
				Name:       "lan",
				PhysicalIf: "em1",
				IPAddress:  "10.0.0.1",
				Subnet:     "24",
				Enabled:    true,
			},
		},
	}

	result := Walk(device)

	var interfacesNode *MDNode

	for _, child := range result.Children {
		if strings.Contains(child.Title, "Interfaces") {
			interfacesNode = &child
			break
		}
	}

	if interfacesNode == nil {
		t.Fatal("Interfaces node not found")
	}

	if len(interfacesNode.Children) != 2 {
		t.Errorf("Expected 2 interface items, got %d", len(interfacesNode.Children))
	}

	firstItem := interfacesNode.Children[0]
	if !strings.Contains(firstItem.Body, "192.168.1.100") {
		t.Errorf("Expected WAN IP in body, got: %s", firstItem.Body)
	}
}

func TestWalk_FirewallRuleHandling(t *testing.T) {
	device := common.CommonDevice{
		FirewallRules: []common.FirewallRule{
			{
				Type:        "pass",
				IPProtocol:  "inet",
				Description: "Allow LAN to any rule",
				Interfaces:  []string{"lan"},
				Protocol:    "tcp",
				Source:      common.RuleEndpoint{Address: "any"},
				Destination: common.RuleEndpoint{Address: "10.0.0.0/24", Port: "443"},
				Log:         true,
			},
		},
	}

	result := Walk(device)

	var rulesNode *MDNode

	for _, child := range result.Children {
		if strings.Contains(child.Title, "Firewall Rules") {
			rulesNode = &child
			break
		}
	}

	if rulesNode == nil {
		t.Fatal("Firewall Rules node not found")
	}

	if len(rulesNode.Children) != 1 {
		t.Errorf("Expected 1 rule child, got %d", len(rulesNode.Children))
	}

	ruleItem := rulesNode.Children[0]
	if !strings.Contains(ruleItem.Title, "[0]") {
		t.Errorf("Expected rule item to contain '[0]', got: %s", ruleItem.Title)
	}

	if !strings.Contains(ruleItem.Body, "Type: pass") {
		t.Errorf("Expected Type: pass in rule body, got: %s", ruleItem.Body)
	}
}

func TestWalk_MapDeterministicOrdering(t *testing.T) {
	// Use enrichment fields with map types to exercise walkMap.
	device := common.CommonDevice{
		Statistics: &common.Statistics{
			InterfacesByType: map[string]int{
				"dhcp":   2,
				"static": 3,
				"none":   1,
			},
		},
	}

	// Run Walk multiple times and verify the map keys always appear in sorted order.
	for range 10 {
		result := Walk(device)

		var statsNode *MDNode
		for _, child := range result.Children {
			if strings.Contains(child.Title, "Statistics") {
				statsNode = &child
				break
			}
		}
		if statsNode == nil {
			t.Fatal("Statistics node not found")
		}

		// Find InterfacesByType child.
		var mapNode *MDNode
		for _, child := range statsNode.Children {
			if strings.Contains(child.Title, "Interfaces By Type") {
				mapNode = &child
				break
			}
		}
		if mapNode == nil {
			t.Fatal("InterfacesByType node not found")
		}

		if len(mapNode.Children) != 3 {
			t.Fatalf("Expected 3 map children, got %d", len(mapNode.Children))
		}

		// Keys must be sorted: dhcp, none, static.
		if !strings.Contains(mapNode.Children[0].Title, "dhcp") {
			t.Errorf("Expected first key 'dhcp', got: %s", mapNode.Children[0].Title)
		}
		if !strings.Contains(mapNode.Children[1].Title, "none") {
			t.Errorf("Expected second key 'none', got: %s", mapNode.Children[1].Title)
		}
		if !strings.Contains(mapNode.Children[2].Title, "static") {
			t.Errorf("Expected third key 'static', got: %s", mapNode.Children[2].Title)
		}
	}
}

func TestFormatFieldName(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"Hostname", "Hostname"},
		{"IPAddress", "IPAddress"},
		{"DisableConsoleMenu", "Disable Console Menu"},
		{"IPv6Allow", "IPv6 Allow"},
		{"XMLName", "XMLName"},
		{"DisableVLANHWFilter", "Disable VLANHWFilter"},
	}

	for _, test := range tests {
		result := formatFieldName(test.input)
		if result != test.expected {
			t.Errorf("formatFieldName(%s) = %s, expected %s", test.input, result, test.expected)
		}
	}
}

func TestFormatIndex(t *testing.T) {
	tests := []struct {
		input    int
		expected string
	}{
		{0, "[0]"},
		{1, "[1]"},
		{10, "[10]"},
		{99, "[99]"},
	}

	for _, test := range tests {
		result := formatIndex(test.input)
		if result != test.expected {
			t.Errorf("formatIndex(%d) = %s, expected %s", test.input, result, test.expected)
		}
	}
}
