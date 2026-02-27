package sanitizer

import (
	"testing"
)

// Test constants for expected redaction values.
const (
	expectedRedactedPublicIP1 = "[REDACTED-PUBLIC-IP-1]"
	expectedMappedHostname1   = "host-001.example.com"
	expectedMappedEmail1      = "user1@example.com"
	testBase64PubKey          = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="
)

func TestValidModes(t *testing.T) {
	modes := ValidModes()
	if len(modes) != 3 {
		t.Errorf("ValidModes() returned %d modes, want 3", len(modes))
	}

	expected := map[Mode]bool{
		ModeAggressive: false,
		ModeModerate:   false,
		ModeMinimal:    false,
	}
	for _, m := range modes {
		expected[m] = true
	}
	for m, found := range expected {
		if !found {
			t.Errorf("ValidModes() missing mode %q", m)
		}
	}
}

func TestIsValidMode(t *testing.T) {
	tests := []struct {
		mode string
		want bool
	}{
		{"aggressive", true},
		{"moderate", true},
		{"minimal", true},
		{"invalid", false},
		{"", false},
		{"AGGRESSIVE", false}, // case sensitive
	}

	for _, tt := range tests {
		t.Run(tt.mode, func(t *testing.T) {
			if got := IsValidMode(tt.mode); got != tt.want {
				t.Errorf("IsValidMode(%q) = %v, want %v", tt.mode, got, tt.want)
			}
		})
	}
}

func TestNewRuleEngine(t *testing.T) {
	engine := NewRuleEngine(ModeAggressive)
	if engine == nil {
		t.Fatal("NewRuleEngine() returned nil")
	}
	if engine.mode != ModeAggressive {
		t.Errorf("engine.mode = %q, want %q", engine.mode, ModeAggressive)
	}
	if engine.mapper == nil {
		t.Error("engine.mapper is nil")
	}
	if len(engine.rules) == 0 {
		t.Error("engine.rules is empty")
	}
}

func TestShouldRedactField_Password(t *testing.T) {
	tests := []struct {
		mode      Mode
		fieldName string
		want      bool
	}{
		{ModeAggressive, "password", true},
		{ModeModerate, "password", true},
		{ModeMinimal, "password", true},
		{ModeAggressive, "userPassword", true},
		{ModeAggressive, "Password", true},
		{ModeAggressive, "passwd", true},
		{ModeAggressive, "description", false},
	}

	for _, tt := range tests {
		t.Run(string(tt.mode)+"_"+tt.fieldName, func(t *testing.T) {
			engine := NewRuleEngine(tt.mode)
			got, _ := engine.ShouldRedactField(tt.fieldName)
			if got != tt.want {
				t.Errorf("ShouldRedactField(%q) = %v, want %v", tt.fieldName, got, tt.want)
			}
		})
	}
}

func TestShouldRedactField_Secret(t *testing.T) {
	engine := NewRuleEngine(ModeMinimal)

	secretFields := []string{"secret", "token", "apikey", "api_key", "authkey"}
	for _, field := range secretFields {
		should, rule := engine.ShouldRedactField(field)
		if !should {
			t.Errorf("ShouldRedactField(%q) = false, want true", field)
		}
		if rule == nil {
			t.Errorf("ShouldRedactField(%q) returned nil rule", field)
		}
	}
}

func TestShouldRedactField_PSK(t *testing.T) {
	engine := NewRuleEngine(ModeMinimal)

	pskFields := []string{"psk", "ipsecpsk", "presharedkey", "pre-shared-key"}
	for _, field := range pskFields {
		should, _ := engine.ShouldRedactField(field)
		if !should {
			t.Errorf("ShouldRedactField(%q) = false, want true", field)
		}
	}
}

func TestShouldRedactValue_PublicIP(t *testing.T) {
	tests := []struct {
		mode  Mode
		value string
		want  bool
	}{
		{ModeAggressive, "8.8.8.8", true},
		{ModeModerate, "8.8.8.8", true},
		{ModeMinimal, "8.8.8.8", false},       // Public IPs not redacted in minimal
		{ModeAggressive, "192.168.1.1", true}, // Private IP in aggressive
		{ModeModerate, "192.168.1.1", false},  // Private IP not in moderate
	}

	for _, tt := range tests {
		t.Run(string(tt.mode)+"_"+tt.value, func(t *testing.T) {
			engine := NewRuleEngine(tt.mode)
			got, _ := engine.ShouldRedactValue("someField", tt.value)
			if got != tt.want {
				t.Errorf("ShouldRedactValue(%q) = %v, want %v", tt.value, got, tt.want)
			}
		})
	}
}

func TestShouldRedactValue_MAC(t *testing.T) {
	tests := []struct {
		mode  Mode
		value string
		want  bool
	}{
		{ModeAggressive, "00:11:22:33:44:55", true},
		{ModeModerate, "00:11:22:33:44:55", true},
		{ModeMinimal, "00:11:22:33:44:55", false},
	}

	for _, tt := range tests {
		t.Run(string(tt.mode)+"_"+tt.value, func(t *testing.T) {
			engine := NewRuleEngine(tt.mode)
			got, _ := engine.ShouldRedactValue("macaddr", tt.value)
			if got != tt.want {
				t.Errorf("ShouldRedactValue(%q) = %v, want %v", tt.value, got, tt.want)
			}
		})
	}
}

func TestShouldRedactValue_Email(t *testing.T) {
	tests := []struct {
		mode  Mode
		value string
		want  bool
	}{
		{ModeAggressive, "admin@company.com", true},
		{ModeModerate, "admin@company.com", true},
		{ModeMinimal, "admin@company.com", false},
	}

	for _, tt := range tests {
		t.Run(string(tt.mode)+"_"+tt.value, func(t *testing.T) {
			engine := NewRuleEngine(tt.mode)
			got, _ := engine.ShouldRedactValue("contact", tt.value)
			if got != tt.want {
				t.Errorf("ShouldRedactValue(%q) = %v, want %v", tt.value, got, tt.want)
			}
		})
	}
}

func TestRedact_Password(t *testing.T) {
	engine := NewRuleEngine(ModeMinimal)
	result := engine.Redact("password", "supersecret123")
	if result != "[REDACTED-PASSWORD]" {
		t.Errorf("Redact password = %q, want %q", result, "[REDACTED-PASSWORD]")
	}
}

func TestRedact_Secret(t *testing.T) {
	engine := NewRuleEngine(ModeMinimal)
	result := engine.Redact("apikey", "sk-abc123xyz")
	if result != redactedSecretValue {
		t.Errorf("Redact apikey = %q, want %q", result, redactedSecretValue)
	}
}

func TestRedact_PSK(t *testing.T) {
	engine := NewRuleEngine(ModeMinimal)
	result := engine.Redact("ipsecpsk", "mypresharedkey")
	if result != "[REDACTED-PSK]" {
		t.Errorf("Redact psk = %q, want %q", result, "[REDACTED-PSK]")
	}
}

func TestRedact_PublicIP(t *testing.T) {
	engine := NewRuleEngine(ModeAggressive)

	result := engine.Redact("gateway", "8.8.8.8")
	if result != expectedRedactedPublicIP1 {
		t.Errorf("Redact public IP = %q, want %q", result, expectedRedactedPublicIP1)
	}

	// Same IP should get same redaction
	result2 := engine.Redact("dns", "8.8.8.8")
	if result2 != result {
		t.Errorf("Redact same IP = %q, want %q", result2, result)
	}
}

func TestRedact_PrivateIP(t *testing.T) {
	engine := NewRuleEngine(ModeAggressive)

	result := engine.Redact("lan_ip", "192.168.1.1")
	if result != "10.0.0.1" {
		t.Errorf("Redact private IP = %q, want %q", result, "10.0.0.1")
	}
}

func TestRedact_MAC(t *testing.T) {
	engine := NewRuleEngine(ModeAggressive)

	result := engine.Redact("hwaddr", "00:11:22:33:44:55")
	if result != "XX:XX:XX:XX:XX:01" {
		t.Errorf("Redact MAC = %q, want %q", result, "XX:XX:XX:XX:XX:01")
	}
}

func TestRedact_Email(t *testing.T) {
	engine := NewRuleEngine(ModeAggressive)

	result := engine.Redact("contact", "admin@company.com")
	if result != expectedMappedEmail1 {
		t.Errorf("Redact email = %q, want %q", result, expectedMappedEmail1)
	}
}

func TestRedact_Hostname(t *testing.T) {
	engine := NewRuleEngine(ModeAggressive)

	result := engine.Redact("fqdn", "firewall.company.local")
	if result != expectedMappedHostname1 {
		t.Errorf("Redact hostname = %q, want %q", result, expectedMappedHostname1)
	}
}

func TestRedact_Username_SystemUser(t *testing.T) {
	engine := NewRuleEngine(ModeAggressive)

	// System users should not be redacted
	systemUsers := []string{"root", "admin", "nobody", "www", "opnsense"}
	for _, user := range systemUsers {
		result := engine.Redact("username", user)
		if result != user {
			t.Errorf("Redact system user %q = %q, want unchanged", user, result)
		}
	}
}

func TestRedact_Username_NonSystem(t *testing.T) {
	engine := NewRuleEngine(ModeAggressive)

	result := engine.Redact("username", "jsmith")
	if result != "user-001" {
		t.Errorf("Redact username = %q, want %q", result, "user-001")
	}
}

func TestRedact_NoRedaction(t *testing.T) {
	engine := NewRuleEngine(ModeMinimal)

	// In minimal mode, hostnames should not be redacted
	result := engine.Redact("servername", "firewall.company.local")
	if result != "firewall.company.local" {
		t.Errorf("Redact in minimal mode = %q, want unchanged", result)
	}
}

func TestGetActiveRules(t *testing.T) {
	tests := []struct {
		mode         Mode
		minRuleCount int
	}{
		{ModeAggressive, 18}, // All rules including aggressive-only
		{ModeModerate, 9},    // Credentials + crypto + identity + network (public IP, MAC)
		{ModeMinimal, 6},     // Credentials + crypto + system (SSH keys)
	}

	for _, tt := range tests {
		t.Run(string(tt.mode), func(t *testing.T) {
			engine := NewRuleEngine(tt.mode)
			active := engine.GetActiveRules()
			if len(active) < tt.minRuleCount {
				t.Errorf("GetActiveRules() returned %d rules, want at least %d", len(active), tt.minRuleCount)
			}
		})
	}
}

func TestGetRulesByCategory(t *testing.T) {
	engine := NewRuleEngine(ModeAggressive)

	categories := []RuleCategory{
		CategoryCredentials,
		CategoryNetwork,
		CategoryIdentity,
		CategoryCrypto,
	}

	for _, cat := range categories {
		rules := engine.GetRulesByCategory(cat)
		if len(rules) == 0 {
			t.Errorf("GetRulesByCategory(%q) returned no rules", cat)
		}
		for _, rule := range rules {
			if rule.Category != cat {
				t.Errorf("rule %q has category %q, want %q", rule.Name, rule.Category, cat)
			}
		}
	}
}

func TestSetMapper(t *testing.T) {
	engine := NewRuleEngine(ModeAggressive)
	customMapper := NewMapper()

	// Pre-populate custom mapper
	customMapper.MapPublicIP("1.2.3.4")

	engine.SetMapper(customMapper)

	if engine.GetMapper() != customMapper {
		t.Error("SetMapper() did not update the mapper")
	}

	// Verify the pre-populated mapping is used
	result := engine.Redact("ip", "1.2.3.4")
	if result != expectedRedactedPublicIP1 {
		t.Errorf("Custom mapper not used, got %q", result)
	}
}

func TestContainsIgnoreCase(t *testing.T) {
	tests := []struct {
		s      string
		substr string
		want   bool
	}{
		{"password", "pass", true},
		{"PASSWORD", "pass", true},
		{"userPassword", "password", true},
		{"hostname", "pass", false},
		{"", "pass", false},
		{"password", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.s+"_"+tt.substr, func(t *testing.T) {
			if got := containsIgnoreCase(tt.s, tt.substr); got != tt.want {
				t.Errorf("containsIgnoreCase(%q, %q) = %v, want %v", tt.s, tt.substr, got, tt.want)
			}
		})
	}
}

func TestRedact_IPAddressField_NonIPValue(t *testing.T) {
	t.Parallel()

	engine := NewRuleEngine(ModeAggressive)

	// "from" matches the ip_address_field rule's FieldPatterns,
	// but non-IP values must pass through unchanged.
	nonIPValues := []string{"any", "lan", "10:00", "dhcp", ""}
	for _, val := range nonIPValues {
		result := engine.Redact("from", val)
		if result != val {
			t.Errorf("Redact('from', %q) = %q, want unchanged", val, result)
		}
	}

	// "to" field with a non-IP value
	result := engine.Redact("to", "wan")
	if result != "wan" {
		t.Errorf("Redact('to', %q) = %q, want unchanged", "wan", result)
	}
}

func TestRedact_IPAddressField_IPValue(t *testing.T) {
	t.Parallel()

	engine := NewRuleEngine(ModeAggressive)

	// "from" field with a real IP should still be redacted
	result := engine.Redact("from", "192.168.1.100")
	if result == "192.168.1.100" {
		t.Error("Redact('from', '192.168.1.100') should redact a private IP")
	}

	result = engine.Redact("to", "8.8.8.8")
	if result == "8.8.8.8" {
		t.Error("Redact('to', '8.8.8.8') should redact a public IP")
	}
}

func TestRedact_Hostname_EmailValue(t *testing.T) {
	t.Parallel()

	engine := NewRuleEngine(ModeAggressive)

	// A hostname-named field containing an email should use email mapping, not hostname mapping
	result := engine.Redact("hostname", "admin@company.com")
	if result == "admin@company.com" {
		t.Error("Redact('hostname', email) should redact the email")
	}
	// Verify it was mapped as an email (user<N>@example.com), not a hostname (host-<N>.example.com)
	if result != expectedMappedEmail1 {
		t.Errorf("Redact('hostname', email) = %q, want email-style mapping 'user1@example.com'", result)
	}
}

func TestRedact_Hostname_NonEmailValue(t *testing.T) {
	t.Parallel()

	engine := NewRuleEngine(ModeAggressive)

	// A hostname-named field with a regular hostname should still use hostname mapping
	result := engine.Redact("hostname", "fw.corp.local")
	if result == "fw.corp.local" {
		t.Error("Redact('hostname', FQDN) should redact the hostname")
	}
	if result != expectedMappedHostname1 {
		t.Errorf("Redact('hostname', FQDN) = %q, want 'host-001.example.com'", result)
	}
}

func TestIsSystemUser(t *testing.T) {
	tests := []struct {
		username string
		want     bool
	}{
		{"root", true},
		{"admin", true},
		{"nobody", true},
		{"opnsense", true},
		{"ROOT", true}, // Case insensitive
		{"jsmith", false},
		{"johndoe", false},
	}

	for _, tt := range tests {
		t.Run(tt.username, func(t *testing.T) {
			if got := isSystemUser(tt.username); got != tt.want {
				t.Errorf("isSystemUser(%q) = %v, want %v", tt.username, got, tt.want)
			}
		})
	}
}
