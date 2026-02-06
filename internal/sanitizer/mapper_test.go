package sanitizer

import (
	"encoding/json"
	"strings"
	"testing"
)

// Test constants for expected redaction values.
const (
	expectedPublicIP1 = "[REDACTED-PUBLIC-IP-1]"
	expectedPublicIP2 = "[REDACTED-PUBLIC-IP-2]"
)

func TestNewMapper(t *testing.T) {
	m := NewMapper()
	if m == nil {
		t.Fatal("NewMapper() returned nil")
	}
	if m.ipMappings == nil {
		t.Error("ipMappings map not initialized")
	}
	if m.hostnameMappings == nil {
		t.Error("hostnameMappings map not initialized")
	}
	if m.usernameMappings == nil {
		t.Error("usernameMappings map not initialized")
	}
	if m.domainMappings == nil {
		t.Error("domainMappings map not initialized")
	}
	if m.macMappings == nil {
		t.Error("macMappings map not initialized")
	}
	if m.emailMappings == nil {
		t.Error("emailMappings map not initialized")
	}
	if m.genericMappings == nil {
		t.Error("genericMappings map not initialized")
	}
}

func TestMapPublicIP(t *testing.T) {
	m := NewMapper()

	// First mapping
	result1 := m.MapPublicIP("8.8.8.8")
	if result1 != expectedPublicIP1 {
		t.Errorf("MapPublicIP(8.8.8.8) = %q, want %q", result1, expectedPublicIP1)
	}

	// Same IP should return same mapping
	result2 := m.MapPublicIP("8.8.8.8")
	if result2 != result1 {
		t.Errorf("MapPublicIP(8.8.8.8) second call = %q, want %q", result2, result1)
	}

	// Different IP should return different mapping
	result3 := m.MapPublicIP("1.1.1.1")
	if result3 != expectedPublicIP2 {
		t.Errorf("MapPublicIP(1.1.1.1) = %q, want %q", result3, expectedPublicIP2)
	}
}

func TestMapPrivateIP(t *testing.T) {
	m := NewMapper()

	// Without structure preservation
	result1 := m.MapPrivateIP("192.168.1.100", false)
	if result1 != "10.0.0.1" {
		t.Errorf("MapPrivateIP without structure = %q, want %q", result1, "10.0.0.1")
	}

	// Same IP should return same mapping
	result2 := m.MapPrivateIP("192.168.1.100", false)
	if result2 != result1 {
		t.Errorf("MapPrivateIP second call = %q, want %q", result2, result1)
	}

	// Different IP without structure
	result3 := m.MapPrivateIP("10.0.0.50", false)
	if result3 != "10.0.0.2" {
		t.Errorf("MapPrivateIP different IP = %q, want %q", result3, "10.0.0.2")
	}
}

func TestMapPrivateIP_PreserveStructure(t *testing.T) {
	m := NewMapper()

	// With structure preservation
	result := m.MapPrivateIP("192.168.1.100", true)
	if result != "192.168.X.1" {
		t.Errorf("MapPrivateIP with structure = %q, want %q", result, "192.168.X.1")
	}

	// Different network should preserve its structure
	result2 := m.MapPrivateIP("172.16.5.20", true)
	if result2 != "172.16.X.2" {
		t.Errorf("MapPrivateIP different network = %q, want %q", result2, "172.16.X.2")
	}
}

func TestMapHostname(t *testing.T) {
	m := NewMapper()

	result1 := m.MapHostname("firewall.example.com")
	if result1 != "host-001.example.com" {
		t.Errorf("MapHostname() = %q, want %q", result1, "host-001.example.com")
	}

	// Same hostname should return same mapping
	result2 := m.MapHostname("firewall.example.com")
	if result2 != result1 {
		t.Errorf("MapHostname second call = %q, want %q", result2, result1)
	}

	// Different hostname
	result3 := m.MapHostname("server.internal.local")
	if result3 != "host-002.example.com" {
		t.Errorf("MapHostname different = %q, want %q", result3, "host-002.example.com")
	}
}

func TestMapUsername(t *testing.T) {
	m := NewMapper()

	result1 := m.MapUsername("admin")
	if result1 != "user-001" {
		t.Errorf("MapUsername(admin) = %q, want %q", result1, "user-001")
	}

	// Same username should return same mapping
	result2 := m.MapUsername("admin")
	if result2 != result1 {
		t.Errorf("MapUsername second call = %q, want %q", result2, result1)
	}

	// Different username
	result3 := m.MapUsername("root")
	if result3 != "user-002" {
		t.Errorf("MapUsername(root) = %q, want %q", result3, "user-002")
	}
}

func TestMapDomain(t *testing.T) {
	m := NewMapper()

	// First domain gets example.com
	result1 := m.MapDomain("mycompany.com")
	if result1 != "example.com" {
		t.Errorf("MapDomain first = %q, want %q", result1, "example.com")
	}

	// Same domain should return same mapping
	result2 := m.MapDomain("mycompany.com")
	if result2 != result1 {
		t.Errorf("MapDomain second call = %q, want %q", result2, result1)
	}

	// Second unique domain
	result3 := m.MapDomain("othercompany.org")
	if result3 != "example2.com" {
		t.Errorf("MapDomain second = %q, want %q", result3, "example2.com")
	}
}

func TestMapMAC(t *testing.T) {
	m := NewMapper()

	result1 := m.MapMAC("00:11:22:33:44:55")
	if result1 != "XX:XX:XX:XX:XX:01" {
		t.Errorf("MapMAC() = %q, want %q", result1, "XX:XX:XX:XX:XX:01")
	}

	// Same MAC should return same mapping
	result2 := m.MapMAC("00:11:22:33:44:55")
	if result2 != result1 {
		t.Errorf("MapMAC second call = %q, want %q", result2, result1)
	}

	// Different MAC
	result3 := m.MapMAC("AA:BB:CC:DD:EE:FF")
	if result3 != "XX:XX:XX:XX:XX:02" {
		t.Errorf("MapMAC different = %q, want %q", result3, "XX:XX:XX:XX:XX:02")
	}
}

func TestMapEmail(t *testing.T) {
	m := NewMapper()

	result1 := m.MapEmail("admin@mycompany.com")
	if result1 != "user1@example.com" {
		t.Errorf("MapEmail() = %q, want %q", result1, "user1@example.com")
	}

	// Same email should return same mapping
	result2 := m.MapEmail("admin@mycompany.com")
	if result2 != result1 {
		t.Errorf("MapEmail second call = %q, want %q", result2, result1)
	}

	// Different email
	result3 := m.MapEmail("support@othercompany.org")
	if result3 != "user2@example.com" {
		t.Errorf("MapEmail different = %q, want %q", result3, "user2@example.com")
	}
}

func TestMapGeneric(t *testing.T) {
	m := NewMapper()

	result1 := m.MapGeneric("mysecret123", "PASSWORD")
	if result1 != "[PASSWORD-REDACTED]" {
		t.Errorf("MapGeneric() = %q, want %q", result1, "[PASSWORD-REDACTED]")
	}

	// Same value and category should return same mapping
	result2 := m.MapGeneric("mysecret123", "PASSWORD")
	if result2 != result1 {
		t.Errorf("MapGeneric second call = %q, want %q", result2, result1)
	}

	// Same value but different category
	result3 := m.MapGeneric("mysecret123", "APIKEY")
	if result3 != "[APIKEY-REDACTED]" {
		t.Errorf("MapGeneric different category = %q, want %q", result3, "[APIKEY-REDACTED]")
	}
}

func TestReset(t *testing.T) {
	m := NewMapper()

	// Add some mappings
	m.MapPublicIP("8.8.8.8")
	m.MapHostname("test.example.com")
	m.MapUsername("admin")

	// Reset
	m.Reset()

	// Counters should be reset, so new mappings start from 1
	result := m.MapPublicIP("1.1.1.1")
	if result != expectedPublicIP1 {
		t.Errorf("After Reset, MapPublicIP = %q, want %q", result, expectedPublicIP1)
	}

	// Same IP as before reset should get new mapping
	result2 := m.MapPublicIP("8.8.8.8")
	if result2 != expectedPublicIP2 {
		t.Errorf("After Reset, previously mapped IP = %q, want %q", result2, expectedPublicIP2)
	}
}

func TestGenerateReport(t *testing.T) {
	m := NewMapper()

	// Add various mappings
	m.MapPublicIP("8.8.8.8")
	m.MapPrivateIP("192.168.1.1", false)
	m.MapHostname("firewall.example.com")
	m.MapUsername("admin")
	m.MapDomain("mycompany.com")
	m.MapMAC("00:11:22:33:44:55")
	m.MapEmail("admin@mycompany.com")
	m.MapGeneric("secret", "PASSWORD")

	report := m.GenerateReport("aggressive")

	if report.Version != "1.0" {
		t.Errorf("report.Version = %q, want %q", report.Version, "1.0")
	}

	if report.Mode != "aggressive" {
		t.Errorf("report.Mode = %q, want %q", report.Mode, "aggressive")
	}

	if report.Timestamp == "" {
		t.Error("report.Timestamp should not be empty")
	}

	// Check mappings
	if len(report.Mappings.IPAddresses) != 2 {
		t.Errorf("report.Mappings.IPAddresses has %d entries, want 2", len(report.Mappings.IPAddresses))
	}

	if len(report.Mappings.Hostnames) != 1 {
		t.Errorf("report.Mappings.Hostnames has %d entries, want 1", len(report.Mappings.Hostnames))
	}

	if len(report.Mappings.Usernames) != 1 {
		t.Errorf("report.Mappings.Usernames has %d entries, want 1", len(report.Mappings.Usernames))
	}
}

func TestToJSON(t *testing.T) {
	m := NewMapper()
	m.MapPublicIP("8.8.8.8")
	m.MapHostname("test.example.com")

	jsonBytes, err := m.ToJSON("moderate")
	if err != nil {
		t.Fatalf("ToJSON() error = %v", err)
	}

	// Verify it's valid JSON
	var report MappingReport
	if err := json.Unmarshal(jsonBytes, &report); err != nil {
		t.Fatalf("Failed to unmarshal JSON: %v", err)
	}

	if report.Mode != "moderate" {
		t.Errorf("report.Mode = %q, want %q", report.Mode, "moderate")
	}

	// Verify pretty printing (should have indentation)
	jsonStr := string(jsonBytes)
	if !strings.Contains(jsonStr, "\n") {
		t.Error("JSON should be pretty-printed with newlines")
	}
}

func TestExtractOctets(t *testing.T) {
	tests := []struct {
		input string
		want  []string
	}{
		{"192.168.1.1", []string{"192", "168", "1", "1"}},
		{"10.0.0.1", []string{"10", "0", "0", "1"}},
		{"255.255.255.255", []string{"255", "255", "255", "255"}},
		{"1.2.3", []string{"1", "2", "3"}},
		{"", []string{}},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := extractOctets(tt.input)
			if len(got) != len(tt.want) {
				t.Errorf("extractOctets(%q) returned %d octets, want %d", tt.input, len(got), len(tt.want))
				return
			}
			for i, octet := range got {
				if octet != tt.want[i] {
					t.Errorf("extractOctets(%q)[%d] = %q, want %q", tt.input, i, octet, tt.want[i])
				}
			}
		})
	}
}

func TestCopyMap(t *testing.T) {
	// Test with nil/empty map
	result := copyMap(nil)
	if result != nil {
		t.Error("copyMap(nil) should return nil")
	}

	result = copyMap(map[string]string{})
	if result != nil {
		t.Error("copyMap(empty) should return nil")
	}

	// Test with populated map
	original := map[string]string{
		"key1": "value1",
		"key2": "value2",
	}
	copied := copyMap(original)

	if len(copied) != len(original) {
		t.Errorf("copyMap() returned map with %d entries, want %d", len(copied), len(original))
	}

	// Verify values are copied
	for k, v := range original {
		if copied[k] != v {
			t.Errorf("copyMap()[%q] = %q, want %q", k, copied[k], v)
		}
	}

	// Verify it's a true copy (modifying original doesn't affect copy)
	original["key3"] = "value3"
	if _, exists := copied["key3"]; exists {
		t.Error("copyMap() should create independent copy")
	}
}
