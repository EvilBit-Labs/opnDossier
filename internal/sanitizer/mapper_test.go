package sanitizer

import (
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"testing"
)

// Test constants for expected redaction values.
const (
	expectedPublicIP1                = "[REDACTED-PUBLIC-IP-1]"
	expectedPublicIP2                = "[REDACTED-PUBLIC-IP-2]"
	expectedMappedMAC1               = "XX:XX:XX:XX:XX:01"
	expectedMappedMAC2               = "XX:XX:XX:XX:XX:02"
	expectedPrivateIP1               = "[REDACTED-PRIVATE-IP-1]"
	expectedAuthServerName1          = "authserver-001"
	expectedAuthServerHost1          = "ldap-001.example.invalid"
	expectedAuthServerPort1          = "55001"
	expectedAuthServerBaseDN1        = "dc=auth001,dc=example,dc=invalid"
	expectedAuthServerAuthCN1        = "cn=auth-search-001,ou=ldap,dc=example,dc=invalid"
	expectedAuthServerExtendedQuery1 = "(&(objectClass=person)(uid=redacted-001))"
	expectedAuthServerAttrUser1      = "opndossierUserAttr001"
	expectedAuthServerBindDN1        = "cn=bind-user-001,ou=svc,dc=example,dc=invalid"

	//nolint:gosec // G101: expected pseudonymized bind password used in tests, not a real credential.
	expectedAuthServerBindPW1 = "BindPw-001-NotReal!"

	expectedAuthServerSyncMemberOfGroups1 = "cn=memberof-sync-001,ou=groups,dc=example,dc=invalid"
	expectedAuthServerSyncDefaultGroups1  = "cn=default-sync-001,ou=groups,dc=example,dc=invalid"
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
	if m.macMappings == nil {
		t.Error("macMappings map not initialized")
	}
	if m.emailMappings == nil {
		t.Error("emailMappings map not initialized")
	}
	if m.authServerCounters == nil {
		t.Error("authServerCounters map not initialized")
	}
	if m.authServerMappings == nil {
		t.Error("authServerMappings map not initialized")
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

	result1 := m.MapPrivateIP("192.168.1.100")
	if result1 != expectedPrivateIP1 {
		t.Errorf("MapPrivateIP = %q, want %q", result1, expectedPrivateIP1)
	}

	// Referential integrity: the same address maps to the same replacement.
	result2 := m.MapPrivateIP("192.168.1.100")
	if result2 != result1 {
		t.Errorf("MapPrivateIP second call = %q, want %q", result2, result1)
	}

	// A different address gets a distinct replacement.
	result3 := m.MapPrivateIP("10.0.0.50")
	if result3 != "[REDACTED-PRIVATE-IP-2]" {
		t.Errorf("MapPrivateIP different IP = %q, want %q", result3, "[REDACTED-PRIVATE-IP-2]")
	}
}

// TestMapPrivateIP_ReplacementIsNeverAnAddress is the regression test for the
// two defects in the previous 10.0.0.N scheme.
//
// It numbered replacements into 10.0.0.0/24, so past 255 distinct inputs it
// emitted invalid octets, and because the replacement space overlapped the
// RFC1918 input space a replacement could be a real address from the same
// file. A marker cannot do either.
func TestMapPrivateIP_ReplacementIsNeverAnAddress(t *testing.T) {
	m := NewMapper()

	// Well past the 255 boundary that used to produce "10.0.0.256".
	const count = 300

	seen := make(map[string]struct{}, count)
	inputs := make(map[string]struct{}, count)

	for i := range count {
		original := fmt.Sprintf("172.16.%d.%d", i/250, i%250+1)
		inputs[original] = struct{}{}

		replacement := m.MapPrivateIP(original)

		if net.ParseIP(replacement) != nil {
			t.Fatalf("replacement %q for %q parses as an IP address; a real address can be "+
				"mistaken for genuine data or collide with another host in the same file",
				replacement, original)
		}

		if _, collides := inputs[replacement]; collides {
			t.Fatalf("replacement %q for %q is an address that appears in the input",
				replacement, original)
		}

		if _, dup := seen[replacement]; dup {
			t.Fatalf("replacement %q issued twice", replacement)
		}

		seen[replacement] = struct{}{}
	}

	if len(seen) != count {
		t.Errorf("got %d distinct replacements, want %d", len(seen), count)
	}
}

// TestMapPrivateIP_NoSelfMapping pins the specific ordering that previously
// produced a replacement identical to a real address in the same document:
// 10.0.0.5 mapped to "10.0.0.1" while the genuine 10.0.0.1 was still present.
func TestMapPrivateIP_NoSelfMapping(t *testing.T) {
	m := NewMapper()

	first := m.MapPrivateIP("10.0.0.5")
	second := m.MapPrivateIP("10.0.0.1")

	for original, replacement := range map[string]string{"10.0.0.5": first, "10.0.0.1": second} {
		if replacement == original {
			t.Errorf("%q maps to itself, which is not a redaction", original)
		}

		if replacement == "10.0.0.1" || replacement == "10.0.0.5" {
			t.Errorf("%q maps to %q, an address present in the input", original, replacement)
		}
	}
}

func TestMapHostname(t *testing.T) {
	m := NewMapper()

	result1 := m.MapHostname("firewall.example.com")
	if result1 != expectedMappedHostname1 {
		t.Errorf("MapHostname() = %q, want %q", result1, expectedMappedHostname1)
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

func TestMapMAC(t *testing.T) {
	m := NewMapper()

	result1 := m.MapMAC("00:11:22:33:44:55")
	if result1 != expectedMappedMAC1 {
		t.Errorf("MapMAC() = %q, want %q", result1, expectedMappedMAC1)
	}

	// Same MAC should return same mapping
	result2 := m.MapMAC("00:11:22:33:44:55")
	if result2 != result1 {
		t.Errorf("MapMAC second call = %q, want %q", result2, result1)
	}

	// Different MAC
	result3 := m.MapMAC("AA:BB:CC:DD:EE:FF")
	if result3 != expectedMappedMAC2 {
		t.Errorf("MapMAC different = %q, want %q", result3, expectedMappedMAC2)
	}
}

func TestMapEmail(t *testing.T) {
	m := NewMapper()

	result1 := m.MapEmail("admin@mycompany.com")
	if result1 != expectedMappedEmail1 {
		t.Errorf("MapEmail() = %q, want %q", result1, expectedMappedEmail1)
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

func TestMapAuthServerValue(t *testing.T) {
	m := NewMapper()

	result1 := m.MapAuthServerValue(authServerFieldLDAPBaseDN, "dc=corp,dc=example,dc=com")
	if result1 != expectedAuthServerBaseDN1 {
		t.Errorf("MapAuthServerValue(ldap_basedn) = %q, want %q", result1, expectedAuthServerBaseDN1)
	}

	result2 := m.MapAuthServerValue(authServerFieldLDAPBaseDN, "dc=corp,dc=example,dc=com")
	if result2 != result1 {
		t.Errorf("MapAuthServerValue second call = %q, want %q", result2, result1)
	}

	result3 := m.MapAuthServerValue(authServerFieldLDAPBindDN, "cn=svc_bind,ou=svc,dc=corp,dc=example,dc=com")
	if result3 != expectedAuthServerBindDN1 {
		t.Errorf("MapAuthServerValue(ldap_binddn) = %q, want %q", result3, expectedAuthServerBindDN1)
	}

	result4 := m.MapAuthServerValue(authServerFieldLDAPBindPW, "supersecret123")
	if result4 != expectedAuthServerBindPW1 {
		t.Errorf("MapAuthServerValue(ldap_bindpw) = %q, want %q", result4, expectedAuthServerBindPW1)
	}
}

func TestMapAuthServerValue_UnknownField(t *testing.T) {
	m := NewMapper()

	// Unknown fields should produce a fail-closed sentinel, not leak the value.
	result := m.MapAuthServerValue("ldap_unknown_future_field", "sensitive-data")
	expected := "[AUTHSERVER-ldap_unknown_future_field-001]"
	if result != expected {
		t.Errorf("MapAuthServerValue(unknown) = %q, want %q", result, expected)
	}

	// Same value should return the same mapping (idempotent).
	result2 := m.MapAuthServerValue("ldap_unknown_future_field", "sensitive-data")
	if result2 != result {
		t.Errorf("MapAuthServerValue(unknown) second call = %q, want %q", result2, result)
	}

	// Different value for same unknown field should increment.
	result3 := m.MapAuthServerValue("ldap_unknown_future_field", "other-sensitive-data")
	expected3 := "[AUTHSERVER-ldap_unknown_future_field-002]"
	if result3 != expected3 {
		t.Errorf("MapAuthServerValue(unknown, different value) = %q, want %q", result3, expected3)
	}
}

func TestGenerateReport(t *testing.T) {
	m := NewMapper()

	// Add various mappings
	m.MapPublicIP("8.8.8.8")
	m.MapPrivateIP("192.168.1.1")
	m.MapHostname("firewall.example.com")
	m.MapUsername("admin")
	m.MapMAC("00:11:22:33:44:55")
	m.MapEmail("admin@mycompany.com")
	m.MapAuthServerValue(authServerFieldHost, "ldap.example.com")
	m.MapAuthServerValue(authServerFieldLDAPBindPW, "supersecret123")
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

	if report.Mappings.AuthServer == nil {
		t.Fatal("report.Mappings.AuthServer is nil")
	}
	if len(report.Mappings.AuthServer.Host) != 1 {
		t.Errorf("report.Mappings.AuthServer.Host has %d entries, want 1", len(report.Mappings.AuthServer.Host))
	}
	if report.Mappings.AuthServer.Host["ldap.example.com"] != expectedAuthServerHost1 {
		t.Errorf(
			"report.Mappings.AuthServer.Host[ldap.example.com] = %q, want %q",
			report.Mappings.AuthServer.Host["ldap.example.com"],
			expectedAuthServerHost1,
		)
	}
	if report.Mappings.AuthServer.LDAPBindPW["supersecret123"] != expectedAuthServerBindPW1 {
		t.Errorf(
			"report.Mappings.AuthServer.LDAPBindPW[supersecret123] = %q, want %q",
			report.Mappings.AuthServer.LDAPBindPW["supersecret123"],
			expectedAuthServerBindPW1,
		)
	}
}

func TestToJSON(t *testing.T) {
	m := NewMapper()
	m.MapPublicIP("8.8.8.8")
	m.MapHostname("test.example.com")
	m.MapAuthServerValue(authServerFieldName, "corp-ldap")

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
	if !strings.Contains(jsonStr, `"authserver"`) {
		t.Error("JSON should include authserver mappings")
	}
	if !strings.Contains(jsonStr, `"name"`) {
		t.Error("JSON should include authserver field names")
	}
}

func TestMapPrivateIP_MalformedInput(t *testing.T) {
	m := NewMapper()

	// The mapper does not parse its input, so a malformed value is still
	// replaced rather than passed through. That matters: the value reached the
	// mapper because a rule matched it, and echoing it would leak it.
	result := m.MapPrivateIP("127")
	if result != expectedPrivateIP1 {
		t.Errorf("MapPrivateIP malformed input = %q, want %q", result, expectedPrivateIP1)
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
