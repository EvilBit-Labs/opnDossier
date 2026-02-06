package sanitizer

import (
	"testing"
)

// Test constants for expected redaction values.
const (
	expectedRedactedPublicIP1 = "[REDACTED-PUBLIC-IP-1]"
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
		{ModeAggressive, "hostname", false},
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
	if result != "[REDACTED-SECRET]" {
		t.Errorf("Redact apikey = %q, want %q", result, "[REDACTED-SECRET]")
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
	if result != "user1@example.com" {
		t.Errorf("Redact email = %q, want %q", result, "user1@example.com")
	}
}

func TestRedact_Hostname(t *testing.T) {
	engine := NewRuleEngine(ModeAggressive)

	result := engine.Redact("fqdn", "firewall.company.local")
	if result != "host-001.example.com" {
		t.Errorf("Redact hostname = %q, want %q", result, "host-001.example.com")
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
		{ModeAggressive, 10}, // Should have most rules
		{ModeModerate, 7},    // Fewer rules
		{ModeMinimal, 5},     // Fewest rules
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
