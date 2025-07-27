package internal

import (
	"encoding/xml"
	"strings"
	"testing"

	"github.com/unclesp1d3r/opnFocus/internal/model"
)

func TestWalk_BasicStructure(t *testing.T) {
	// Create a minimal OPNsense configuration
	opnsense := model.Opnsense{
		Version: "1.0",
		System: model.System{
			Hostname: "firewall.local",
			Domain:   "example.com",
		},
	}

	result := Walk(opnsense)

	// Test root node
	if result.Level != 1 {
		t.Errorf("Expected root level 1, got %d", result.Level)
	}
	if result.Title != "# OPNsense Configuration" {
		t.Errorf("Expected root title '# OPNsense Configuration', got '%s'", result.Title)
	}

	// Test that version is in the body
	if !strings.Contains(result.Body, "Version: 1.0") {
		t.Errorf("Expected Version in body, got: %s", result.Body)
	}

	// Test that System is a child node
	found := false
	for _, child := range result.Children {
		if strings.Contains(child.Title, "System") {
			found = true
			// Test system child properties
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
	}
	if !found {
		t.Error("Expected System child node not found")
	}
}

func TestWalk_DepthLimiting(t *testing.T) {
	// Create a structure that would go beyond level 6
	opnsense := model.Opnsense{
		System: model.System{
			Webgui: model.Webgui{
				Protocol: "https",
			},
		},
	}

	result := Walk(opnsense)

	// Find the deepest node and verify it doesn't exceed level 6
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

func TestWalk_EmptyStructHandling(t *testing.T) {
	// Create OPNsense config with empty struct fields
	opnsense := model.Opnsense{
		System: model.System{
			Hostname:           "test.local",
			Domain:             "test.com",
			DisableConsoleMenu: struct{}{}, // Empty struct should be treated as "enabled"
			IPv6Allow:          struct{}{}, // Another empty struct
		},
	}

	result := Walk(opnsense)

	// Find System child
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

	// Check that empty structs are handled as "enabled" flags
	if !strings.Contains(systemNode.Body, "Disable Console Menu: enabled") {
		t.Errorf("Expected 'Disable Console Menu: enabled' in body, got: %s", systemNode.Body)
	}
	if !strings.Contains(systemNode.Body, "IPv6 Allow: enabled") {
		t.Errorf("Expected 'IPv6 Allow: enabled' in body, got: %s", systemNode.Body)
	}
}

func TestWalk_SliceHandling(t *testing.T) {
	// Create OPNsense config with slice fields
	opnsense := model.Opnsense{
		Sysctl: []model.SysctlItem{
			{
				Tunable: "net.inet.tcp.rfc3390",
				Value:   "1",
				Descr:   "TCP RFC 3390",
			},
			{
				Tunable: "kern.ipc.maxsockbuf",
				Value:   "16777216",
				Descr:   "Maximum socket buffer size",
			},
		},
	}

	result := Walk(opnsense)

	// Find Sysctl child
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

	// Check that slice items are properly indexed
	if len(sysctlNode.Children) != 2 {
		t.Errorf("Expected 2 Sysctl children, got %d", len(sysctlNode.Children))
	}

	// Check first item
	firstItem := sysctlNode.Children[0]
	if !strings.Contains(firstItem.Title, "[0]") {
		t.Errorf("Expected first item to contain '[0]', got: %s", firstItem.Title)
	}
	if !strings.Contains(firstItem.Body, "net.inet.tcp.rfc3390") {
		t.Errorf("Expected tunable in first item body, got: %s", firstItem.Body)
	}
}

func TestWalk_MapHandling(t *testing.T) {
	// Create OPNsense config with map-like structures (Interfaces)
	opnsense := model.Opnsense{
		Interfaces: model.Interfaces{
			Items: map[string]model.Interface{
				"wan": {
					If:     "em0",
					IPAddr: "192.168.1.100",
					Subnet: "24",
				},
				"lan": {
					If:     "em1",
					IPAddr: "10.0.0.1",
					Subnet: "24",
				},
			},
		},
	}

	result := Walk(opnsense)

	// Find Interfaces child
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

	// Find Items child under Interfaces
	var itemsNode *MDNode
	for _, child := range interfacesNode.Children {
		if strings.Contains(child.Title, "Items") {
			itemsNode = &child
			break
		}
	}

	if itemsNode == nil {
		t.Fatal("Items node not found")
	}

	// Check that map entries are present
	if len(itemsNode.Children) != 2 {
		t.Errorf("Expected 2 interface items, got %d", len(itemsNode.Children))
	}

	// Verify interface entries exist
	foundWan := false
	foundLan := false
	for _, child := range itemsNode.Children {
		if strings.Contains(child.Title, "wan") {
			foundWan = true
			if !strings.Contains(child.Body, "IPAddr: 192.168.1.100") {
				t.Errorf("Expected WAN IP in body, got: %s", child.Body)
			}
		}
		if strings.Contains(child.Title, "lan") {
			foundLan = true
			if !strings.Contains(child.Body, "IPAddr: 10.0.0.1") {
				t.Errorf("Expected LAN IP in body, got: %s", child.Body)
			}
		}
	}

	if !foundWan {
		t.Error("WAN interface not found")
	}
	if !foundLan {
		t.Error("LAN interface not found")
	}
}

func TestWalk_XMLNameSkipping(t *testing.T) {
	// Create OPNsense config to test that XMLName fields are skipped
	opnsense := model.Opnsense{
		XMLName: xml.Name{Local: "opnsense"},
		Version: "1.0",
		System: model.System{
			Hostname: "test.local",
			Domain:   "test.com",
		},
	}

	result := Walk(opnsense)

	// Check that XMLName is not present in the body or children
	bodyStr := result.Body
	if strings.Contains(bodyStr, "XMLName") {
		t.Errorf("XMLName should be skipped, but found in body: %s", bodyStr)
	}

	// Check children don't contain XMLName
	for _, child := range result.Children {
		if strings.Contains(child.Title, "XMLName") {
			t.Error("XMLName should be skipped in children")
		}
	}
}

func TestFormatFieldName(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"Hostname", "Hostname"},
		{"IPAddr", "IPAddr"},
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

func TestWalk_SyntheticXMLFragment(t *testing.T) {
	// Test with a synthetic XML structure that mimics real OPNsense config
	xmlData := `<opnsense version="1.0">
		<version>1.0</version>
		<trigger_initial_wizard />
		<system>
			<hostname>test-firewall</hostname>
			<domain>example.org</domain>
			<optimization>normal</optimization>
			<webgui>
				<protocol>https</protocol>
			</webgui>
		</system>
		<interfaces>
			<wan>
				<if>em0</if>
				<ipaddr>dhcp</ipaddr>
			</wan>
			<lan>
				<if>em1</if>
				<ipaddr>192.168.1.1</ipaddr>
				<subnet>24</subnet>
			</lan>
		</interfaces>
		<filter>
			<rule>
				<type>pass</type>
				<ipprotocol>inet</ipprotocol>
				<descr>Allow LAN to any rule</descr>
				<interface>lan</interface>
			</rule>
		</filter>
	</opnsense>`

	var opnsense model.Opnsense
	err := xml.Unmarshal([]byte(xmlData), &opnsense)
	if err != nil {
		t.Fatalf("Failed to unmarshal XML: %v", err)
	}

	result := Walk(opnsense)

	// Verify structure depth and hierarchy
	if result.Level != 1 {
		t.Errorf("Expected root level 1, got %d", result.Level)
	}

	// Check version is in body
	if !strings.Contains(result.Body, "Version: 1.0") {
		t.Errorf("Expected version in root body, got: %s", result.Body)
	}

	// Find and verify system node
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

	if systemNode.Level != 2 {
		t.Errorf("Expected System level 2, got %d", systemNode.Level)
	}

	// Verify system has webgui child
	foundWebgui := false
	for _, child := range systemNode.Children {
		if strings.Contains(child.Title, "Webgui") {
			foundWebgui = true
			if child.Level != 3 {
				t.Errorf("Expected Webgui level 3, got %d", child.Level)
			}
			if !strings.Contains(child.Body, "Protocol: https") {
				t.Errorf("Expected protocol in webgui body, got: %s", child.Body)
			}
			break
		}
	}
	if !foundWebgui {
		t.Error("Webgui child not found under System")
	}

	// Verify filter rules are handled properly
	var filterNode *MDNode
	for _, child := range result.Children {
		if strings.Contains(child.Title, "Filter") {
			filterNode = &child
			break
		}
	}

	if filterNode == nil {
		t.Fatal("Filter node not found")
	}

	// Find Rule slice
	var ruleNode *MDNode
	for _, child := range filterNode.Children {
		if strings.Contains(child.Title, "Rule") {
			ruleNode = &child
			break
		}
	}

	if ruleNode == nil {
		t.Fatal("Rule node not found")
	}

	// Check that rule has indexed children
	if len(ruleNode.Children) != 1 {
		t.Errorf("Expected 1 rule child, got %d", len(ruleNode.Children))
	}

	ruleItem := ruleNode.Children[0]
	if !strings.Contains(ruleItem.Title, "[0]") {
		t.Errorf("Expected rule item to contain '[0]', got: %s", ruleItem.Title)
	}
}
