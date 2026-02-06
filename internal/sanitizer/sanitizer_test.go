package sanitizer

import (
	"bytes"
	"strings"
	"testing"
)

func TestNewSanitizer(t *testing.T) {
	s := NewSanitizer(ModeAggressive)
	if s == nil {
		t.Fatal("NewSanitizer() returned nil")
	}
	if s.mode != ModeAggressive {
		t.Errorf("mode = %q, want %q", s.mode, ModeAggressive)
	}
	if s.engine == nil {
		t.Error("engine is nil")
	}
	if s.stats == nil {
		t.Error("stats is nil")
	}
}

func TestGetStats(t *testing.T) {
	s := NewSanitizer(ModeAggressive)
	stats := s.GetStats()
	// GetStats now returns a value copy, not a pointer
	if stats.RedactionsByType == nil {
		t.Error("RedactionsByType map not initialized")
	}
	// Verify stats starts at zero
	if stats.TotalFields != 0 {
		t.Errorf("expected TotalFields=0, got %d", stats.TotalFields)
	}
}

func TestGetMapper(t *testing.T) {
	s := NewSanitizer(ModeAggressive)
	mapper := s.GetMapper()
	if mapper == nil {
		t.Error("GetMapper() returned nil")
	}
}

func TestSanitizeXML_Password(t *testing.T) {
	input := `<?xml version="1.0"?>
<opnsense>
  <system>
    <user>
      <password>supersecret123</password>
    </user>
  </system>
</opnsense>`

	s := NewSanitizer(ModeMinimal)
	var output bytes.Buffer
	err := s.SanitizeXML(strings.NewReader(input), &output)
	if err != nil {
		t.Fatalf("SanitizeXML() error = %v", err)
	}

	result := output.String()
	if strings.Contains(result, "supersecret123") {
		t.Error("Password was not redacted")
	}
	if !strings.Contains(result, "[REDACTED-PASSWORD]") {
		t.Error("Password redaction placeholder not found")
	}
}

func TestSanitizeXML_PublicIP(t *testing.T) {
	input := `<config><gateway>8.8.8.8</gateway></config>`

	s := NewSanitizer(ModeAggressive)
	var output bytes.Buffer
	err := s.SanitizeXML(strings.NewReader(input), &output)
	if err != nil {
		t.Fatalf("SanitizeXML() error = %v", err)
	}

	result := output.String()
	if strings.Contains(result, "8.8.8.8") {
		t.Error("Public IP was not redacted")
	}
	if !strings.Contains(result, "[REDACTED-PUBLIC-IP") {
		t.Error("Public IP redaction placeholder not found")
	}
}

func TestSanitizeXML_PrivateIP_Aggressive(t *testing.T) {
	input := `<config><lan>192.168.1.1</lan></config>`

	s := NewSanitizer(ModeAggressive)
	var output bytes.Buffer
	err := s.SanitizeXML(strings.NewReader(input), &output)
	if err != nil {
		t.Fatalf("SanitizeXML() error = %v", err)
	}

	result := output.String()
	if strings.Contains(result, "192.168.1.1") {
		t.Error("Private IP was not redacted in aggressive mode")
	}
	// Should be mapped to 10.0.0.x format
	if !strings.Contains(result, "10.0.0.") {
		t.Errorf("Private IP mapping not found in output: %s", result)
	}
}

func TestSanitizeXML_PrivateIP_Moderate(t *testing.T) {
	input := `<config><lan>192.168.1.1</lan></config>`

	s := NewSanitizer(ModeModerate)
	var output bytes.Buffer
	err := s.SanitizeXML(strings.NewReader(input), &output)
	if err != nil {
		t.Fatalf("SanitizeXML() error = %v", err)
	}

	result := output.String()
	// In moderate mode, private IPs should NOT be redacted
	if !strings.Contains(result, "192.168.1.1") {
		t.Error("Private IP should not be redacted in moderate mode")
	}
}

func TestSanitizeXML_MAC(t *testing.T) {
	input := `<config><hwaddr>00:11:22:33:44:55</hwaddr></config>`

	s := NewSanitizer(ModeAggressive)
	var output bytes.Buffer
	err := s.SanitizeXML(strings.NewReader(input), &output)
	if err != nil {
		t.Fatalf("SanitizeXML() error = %v", err)
	}

	result := output.String()
	if strings.Contains(result, "00:11:22:33:44:55") {
		t.Error("MAC address was not redacted")
	}
	if !strings.Contains(result, "XX:XX:XX:XX:XX:") {
		t.Error("MAC redaction pattern not found")
	}
}

func TestSanitizeXML_Email(t *testing.T) {
	input := `<config><contact>admin@company.com</contact></config>`

	s := NewSanitizer(ModeAggressive)
	var output bytes.Buffer
	err := s.SanitizeXML(strings.NewReader(input), &output)
	if err != nil {
		t.Fatalf("SanitizeXML() error = %v", err)
	}

	result := output.String()
	if strings.Contains(result, "admin@company.com") {
		t.Error("Email was not redacted")
	}
	if !strings.Contains(result, "@example.com") {
		t.Errorf("Email redaction pattern not found in: %s", result)
	}
}

func TestSanitizeXML_PSK(t *testing.T) {
	input := `<ipsec><psk>mysharedsecret</psk></ipsec>`

	s := NewSanitizer(ModeMinimal)
	var output bytes.Buffer
	err := s.SanitizeXML(strings.NewReader(input), &output)
	if err != nil {
		t.Fatalf("SanitizeXML() error = %v", err)
	}

	result := output.String()
	if strings.Contains(result, "mysharedsecret") {
		t.Error("PSK was not redacted")
	}
	if !strings.Contains(result, "[REDACTED-PSK]") {
		t.Error("PSK redaction placeholder not found")
	}
}

func TestSanitizeXML_PreservesStructure(t *testing.T) {
	input := `<?xml version="1.0"?>
<opnsense>
  <system>
    <hostname>firewall</hostname>
  </system>
</opnsense>`

	s := NewSanitizer(ModeMinimal) // Minimal mode preserves hostnames
	var output bytes.Buffer
	err := s.SanitizeXML(strings.NewReader(input), &output)
	if err != nil {
		t.Fatalf("SanitizeXML() error = %v", err)
	}

	result := output.String()
	// Structure should be preserved
	if !strings.Contains(result, "<opnsense>") {
		t.Error("Root element not preserved")
	}
	if !strings.Contains(result, "<system>") {
		t.Error("System element not preserved")
	}
	if !strings.Contains(result, "</opnsense>") {
		t.Error("Closing root element not preserved")
	}
}

func TestSanitizeXML_Attributes(t *testing.T) {
	input := `<rule password="secret123" name="allow"></rule>`

	s := NewSanitizer(ModeMinimal)
	var output bytes.Buffer
	err := s.SanitizeXML(strings.NewReader(input), &output)
	if err != nil {
		t.Fatalf("SanitizeXML() error = %v", err)
	}

	result := output.String()
	if strings.Contains(result, "secret123") {
		t.Error("Password in attribute was not redacted")
	}
	// The name attribute should be preserved
	if !strings.Contains(result, `name="allow"`) {
		t.Errorf("Non-sensitive attribute not preserved: %s", result)
	}
}

func TestSanitizeXML_ConsistentMapping(t *testing.T) {
	input := `<config>
  <server1>8.8.8.8</server1>
  <server2>8.8.8.8</server2>
  <server3>1.1.1.1</server3>
</config>`

	s := NewSanitizer(ModeAggressive)
	var output bytes.Buffer
	err := s.SanitizeXML(strings.NewReader(input), &output)
	if err != nil {
		t.Fatalf("SanitizeXML() error = %v", err)
	}

	result := output.String()
	// Same IP should get same replacement
	firstCount := strings.Count(result, "[REDACTED-PUBLIC-IP-1]")
	if firstCount != 2 {
		t.Errorf("Same IP should have consistent mapping, got %d occurrences of first mapping", firstCount)
	}
	// Different IP should get different replacement
	if !strings.Contains(result, "[REDACTED-PUBLIC-IP-2]") {
		t.Error("Different IP should have different mapping")
	}
}

func TestSanitizeXML_Stats(t *testing.T) {
	input := `<config>
  <password>secret</password>
  <ip>8.8.8.8</ip>
  <name>test</name>
</config>`

	s := NewSanitizer(ModeAggressive)
	var output bytes.Buffer
	err := s.SanitizeXML(strings.NewReader(input), &output)
	if err != nil {
		t.Fatalf("SanitizeXML() error = %v", err)
	}

	stats := s.GetStats()
	if stats.TotalFields == 0 {
		t.Error("TotalFields should be > 0")
	}
	if stats.RedactedFields == 0 {
		t.Error("RedactedFields should be > 0")
	}
	if len(stats.RedactionsByType) == 0 {
		t.Error("RedactionsByType should have entries")
	}
}

func TestSanitizeStruct(t *testing.T) {
	type TestConfig struct {
		Password string
		Username string
		Gateway  string
		Hostname string
	}

	config := &TestConfig{
		Password: "supersecret",
		Username: "jsmith",
		Gateway:  "8.8.8.8",
		Hostname: "firewall.company.com",
	}

	s := NewSanitizer(ModeAggressive)
	err := s.SanitizeStruct(config)
	if err != nil {
		t.Fatalf("SanitizeStruct() error = %v", err)
	}

	if config.Password == "supersecret" {
		t.Error("Password was not redacted")
	}
	if config.Username == "jsmith" {
		t.Error("Username was not redacted")
	}
	if config.Gateway == "8.8.8.8" {
		t.Error("Gateway (public IP) was not redacted")
	}
	if config.Hostname == "firewall.company.com" {
		t.Error("Hostname was not redacted")
	}
}

func TestSanitizeStruct_NestedStruct(t *testing.T) {
	type User struct {
		Name     string
		Password string
	}
	type Config struct {
		Users []User
	}

	config := &Config{
		Users: []User{
			{Name: "admin", Password: "secret1"},
			{Name: "jsmith", Password: "secret2"},
		},
	}

	s := NewSanitizer(ModeAggressive)
	err := s.SanitizeStruct(config)
	if err != nil {
		t.Fatalf("SanitizeStruct() error = %v", err)
	}

	for i, user := range config.Users {
		if strings.Contains(user.Password, "secret") {
			t.Errorf("User[%d].Password was not redacted: %s", i, user.Password)
		}
	}
}

func TestSanitizeStruct_NilPointer(t *testing.T) {
	type Config struct {
		Name *string
	}

	config := &Config{Name: nil}

	s := NewSanitizer(ModeAggressive)
	err := s.SanitizeStruct(config)
	if err != nil {
		t.Fatalf("SanitizeStruct() error with nil pointer = %v", err)
	}
}

func TestEscapeXMLText(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"hello", "hello"},
		{"<script>", "&lt;script&gt;"},
		{"a & b", "a &amp; b"},
		{"", ""},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			if got := escapeXMLText(tt.input); got != tt.want {
				t.Errorf("escapeXMLText(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestEscapeXMLAttr(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"hello", "hello"},
		{`"quoted"`, "&#34;quoted&#34;"}, // xml.EscapeText uses numeric references
		{"a & b", "a &amp; b"},
		{"it's", "it&#39;s"}, // xml.EscapeText uses numeric references
		{"", ""},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			if got := escapeXMLAttr(tt.input); got != tt.want {
				t.Errorf("escapeXMLAttr(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}
