package sanitizer

import (
	"bytes"
	"strconv"
	"strings"
	"testing"
)

const testPublicIP = "8.8.8.8"

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
	if strings.Contains(result, testPublicIP) {
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

func TestSanitizeXML_AuthServerConfig(t *testing.T) {
	input := `<opnsense><system><authserver><type>ldap</type><name>corp-ldap</name><host>ldap.corp.example.com</host><ldap_port>636</ldap_port><ldap_basedn>dc=corp,dc=example,dc=com</ldap_basedn><ldap_authcn>cn=users,dc=corp,dc=example,dc=com</ldap_authcn><ldap_extended_query>(|(memberOf=cn=admins,ou=groups,dc=corp,dc=example,dc=com))</ldap_extended_query><ldap_attr_user>uid</ldap_attr_user><ldap_binddn>cn=svc_bind,ou=svc,dc=corp,dc=example,dc=com</ldap_binddn><ldap_bindpw>supersecret123</ldap_bindpw><ldap_sync_memberof_groups>cn=sync-members,ou=groups,dc=corp,dc=example,dc=com</ldap_sync_memberof_groups><ldap_sync_default_groups>cn=defaults,ou=groups,dc=corp,dc=example,dc=com</ldap_sync_default_groups></authserver></system></opnsense>`

	rawFragments := []string{
		"<name>corp-ldap</name>",
		"<host>ldap.corp.example.com</host>",
		"<ldap_port>636</ldap_port>",
		"<ldap_basedn>dc=corp,dc=example,dc=com</ldap_basedn>",
		"<ldap_authcn>cn=users,dc=corp,dc=example,dc=com</ldap_authcn>",
		"<ldap_extended_query>(|(memberOf=cn=admins,ou=groups,dc=corp,dc=example,dc=com))</ldap_extended_query>",
		"<ldap_attr_user>uid</ldap_attr_user>",
		"<ldap_binddn>cn=svc_bind,ou=svc,dc=corp,dc=example,dc=com</ldap_binddn>",
		"<ldap_bindpw>supersecret123</ldap_bindpw>",
		"<ldap_sync_memberof_groups>cn=sync-members,ou=groups,dc=corp,dc=example,dc=com</ldap_sync_memberof_groups>",
		"<ldap_sync_default_groups>cn=defaults,ou=groups,dc=corp,dc=example,dc=com</ldap_sync_default_groups>",
	}

	expectedFragments := []string{
		"<name>" + expectedAuthServerName1 + "</name>",
		"<host>" + expectedAuthServerHost1 + "</host>",
		"<ldap_port>" + expectedAuthServerPort1 + "</ldap_port>",
		"<ldap_basedn>" + expectedAuthServerBaseDN1 + "</ldap_basedn>",
		"<ldap_authcn>" + expectedAuthServerAuthCN1 + "</ldap_authcn>",
		"<ldap_extended_query>(&amp;(objectClass=person)(uid=redacted-001))</ldap_extended_query>",
		"<ldap_attr_user>" + expectedAuthServerAttrUser1 + "</ldap_attr_user>",
		"<ldap_binddn>" + expectedAuthServerBindDN1 + "</ldap_binddn>",
		"<ldap_bindpw>" + expectedAuthServerBindPW1 + "</ldap_bindpw>",
		"<ldap_sync_memberof_groups>" + expectedAuthServerSyncMemberOfGroups1 + "</ldap_sync_memberof_groups>",
		"<ldap_sync_default_groups>" + expectedAuthServerSyncDefaultGroups1 + "</ldap_sync_default_groups>",
	}

	for _, mode := range ValidModes() {
		s := NewSanitizer(mode)
		var output bytes.Buffer
		err := s.SanitizeXML(strings.NewReader(input), &output)
		if err != nil {
			t.Fatalf("SanitizeXML() error = %v", err)
		}

		result := output.String()
		for _, rawFragment := range rawFragments {
			if strings.Contains(result, rawFragment) {
				t.Errorf("mode=%q should not leak authserver fragment %q", mode, rawFragment)
			}
		}
		for _, expectedFragment := range expectedFragments {
			if !strings.Contains(result, expectedFragment) {
				t.Errorf("mode=%q missing mapped authserver fragment %q", mode, expectedFragment)
			}
		}
		if !strings.Contains(result, "<type>ldap</type>") {
			t.Errorf("mode=%q should preserve authserver type", mode)
		}
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

// TestSanitizeXML_OpenVPNStaticKey verifies the sanitizer redacts OpenVPN
// TLS auth / static-key material across the XML element names OPNsense emits
// (<tls> on legacy server/client configs and <StaticKeys> on the MVC model).
// Regression coverage for SEC-H1 / todos #104 + #127: prior to the fix the
// `sanitize` subcommand leaked the raw HMAC key needed to forge OpenVPN
// handshakes. Tests run in all three sanitizer modes because the private_key
// rule is active in every mode.
func TestSanitizeXML_OpenVPNStaticKey(t *testing.T) {
	const staticKeyBody = "-----BEGIN OpenVPN Static key V1-----\n" +
		"abc123def456789001234567890abcdef\n" +
		"-----END OpenVPN Static key V1-----"

	type fixture struct {
		name string
		xml  string
	}

	fixtures := []fixture{
		{
			name: "legacy_openvpn_server_tls",
			xml: "<opnsense><openvpn><openvpn-server><tls>" +
				staticKeyBody +
				"</tls></openvpn-server></openvpn></opnsense>",
		},
		{
			name: "legacy_openvpn_client_tls",
			xml: "<opnsense><openvpn><openvpn-client><tls>" +
				staticKeyBody +
				"</tls></openvpn-client></openvpn></opnsense>",
		},
		{
			name: "mvc_openvpn_statickeys",
			xml: "<opnsense><OPNsense><OpenVPN><StaticKeys>" +
				staticKeyBody +
				"</StaticKeys></OpenVPN></OPNsense></opnsense>",
		},
		{
			name: "tls_crypt_alias",
			xml: "<opnsense><openvpn><openvpn-server><tls_crypt>" +
				staticKeyBody +
				"</tls_crypt></openvpn-server></openvpn></opnsense>",
		},
	}

	for _, mode := range ValidModes() {
		for _, fx := range fixtures {
			t.Run(string(mode)+"_"+fx.name, func(t *testing.T) {
				s := NewSanitizer(mode)
				var output bytes.Buffer
				if err := s.SanitizeXML(strings.NewReader(fx.xml), &output); err != nil {
					t.Fatalf("SanitizeXML() error = %v", err)
				}
				result := output.String()
				if strings.Contains(result, "BEGIN OpenVPN Static key") {
					t.Errorf("mode=%q fixture=%q leaked OpenVPN envelope: %s", mode, fx.name, result)
				}
				if strings.Contains(result, "abc123def456") {
					t.Errorf("mode=%q fixture=%q leaked key body: %s", mode, fx.name, result)
				}
				if !strings.Contains(result, "[REDACTED-PRIVATE-KEY]") {
					t.Errorf("mode=%q fixture=%q missing redaction marker: %s", mode, fx.name, result)
				}
			})
		}
	}
}

// TestSanitizeXML_OpenVPN_TLS_NoFalsePositives guards against over-broad
// redaction of the `tls` substring. The <tls> wrapper on Suricata eveLog
// and the <tls> log-level enum under the IPsec strongSwan daemon syslog
// (both in pkg/schema/opnsense/security.go) must survive sanitization —
// they carry no secrets and redacting them would break downstream parsing.
func TestSanitizeXML_OpenVPN_TLS_NoFalsePositives(t *testing.T) {
	// Suricata eveLog.tls wraps boolean-ish enable/extended children.
	suricataXML := `<opnsense><OPNsense><IDS><general><eveLog><tls>` +
		`<enable>1</enable><extended>1</extended><sessionResumption>1</sessionResumption>` +
		`</tls></eveLog></general></IDS></OPNsense></opnsense>`

	// IPsec charon syslog daemon.tls carries a log-level string (0-5).
	ipsecXML := `<opnsense><OPNsense><IPsec><charon><syslog><daemon>` +
		`<tls>1</tls></daemon></syslog></charon></IPsec></OPNsense></opnsense>`

	cases := []struct {
		name string
		in   string
		want []string // substrings that must survive
	}{
		{"suricata_evelog_tls_children", suricataXML, []string{"<enable>1</enable>", "<extended>1</extended>"}},
		{"ipsec_syslog_daemon_tls", ipsecXML, []string{"<tls>1</tls>"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := NewSanitizer(ModeAggressive)
			var output bytes.Buffer
			if err := s.SanitizeXML(strings.NewReader(tc.in), &output); err != nil {
				t.Fatalf("SanitizeXML() error = %v", err)
			}
			result := output.String()
			if strings.Contains(result, "[REDACTED-PRIVATE-KEY]") {
				t.Errorf("non-OpenVPN <tls> element was over-redacted as private key: %s", result)
			}
			for _, want := range tc.want {
				if !strings.Contains(result, want) {
					t.Errorf("expected %q to survive sanitization, got: %s", want, result)
				}
			}
		})
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
		Gateway:  testPublicIP,
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
	if config.Gateway == testPublicIP {
		t.Error("Gateway (public IP) was not redacted")
	}
	if config.Hostname == "firewall.company.com" {
		t.Error("Hostname was not redacted")
	}
}

func TestSanitizeStruct_NestedStruct(t *testing.T) {
	type User struct {
		Name string

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

func TestSanitizeXML_GuardedRedactorStats(t *testing.T) {
	t.Parallel()

	// When a guarded Redactor (e.g., ip_address_field) returns the original
	// value because the guard rejects it (non-IP value on a "from" field),
	// stats must count it as SkippedFields, not RedactedFields.
	input := `<config>
  <filter>
    <rule>
      <from>any</from>
      <to>lan</to>
    </rule>
  </filter>
</config>`

	s := NewSanitizer(ModeAggressive)
	var output bytes.Buffer
	err := s.SanitizeXML(strings.NewReader(input), &output)
	if err != nil {
		t.Fatalf("SanitizeXML() error = %v", err)
	}

	stats := s.GetStats()

	// "any" and "lan" are non-IP values on ip_address_field-matched fields;
	// guarded Redactors should return them unchanged → SkippedFields.
	if stats.RedactedFields != 0 {
		t.Errorf("RedactedFields = %d, want 0 (non-IP values should not be redacted)", stats.RedactedFields)
	}
	if stats.SkippedFields == 0 {
		t.Error(
			"SkippedFields should be > 0 (guarded Redactors returning original value should increment SkippedFields)",
		)
	}

	// Verify output preserved original values.
	result := output.String()
	if !strings.Contains(result, "any") {
		t.Error("output should contain 'any' unchanged")
	}
	if !strings.Contains(result, "lan") {
		t.Error("output should contain 'lan' unchanged")
	}
}

func TestSanitizeXML_PreventsEntityExpansion(t *testing.T) {
	t.Parallel()

	// XML with entity definition and reference — entity must not expand.
	// With Strict=false and empty Entity map, the decoder passes entity
	// references through as literal text rather than expanding them.
	input := `<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe "pwned">]><root>&xxe;</root>`

	s := NewSanitizer(ModeMinimal)
	var output bytes.Buffer
	err := s.SanitizeXML(strings.NewReader(input), &output)
	if err != nil {
		t.Fatalf("SanitizeXML() error = %v", err)
	}

	result := output.String()
	// The entity value "pwned" must NOT appear in the output.
	if strings.Contains(result, "pwned") {
		t.Error("XXE entity was expanded — entity value 'pwned' found in output")
	}
	// The DTD directive should be stripped.
	if strings.Contains(result, "DOCTYPE") {
		t.Error("DOCTYPE directive was not stripped from output")
	}
}

func TestSanitizeXML_RejectsOversizedInput(t *testing.T) {
	t.Parallel()

	// Create input larger than maxSanitizeInputSize.
	oversized := strings.Repeat("x", int(maxSanitizeInputSize)+1)
	input := "<root>" + oversized + "</root>"

	s := NewSanitizer(ModeMinimal)
	var output bytes.Buffer
	err := s.SanitizeXML(strings.NewReader(input), &output)

	if err == nil {
		t.Fatal("expected error for oversized input, got nil")
	}
	if !strings.Contains(err.Error(), "exceeds maximum size") {
		t.Errorf("expected size limit error, got: %v", err)
	}
}

func TestSanitizeXML_StripsDTDDirective(t *testing.T) {
	t.Parallel()

	// XML with a DTD directive that should be stripped.
	input := `<?xml version="1.0"?><!DOCTYPE foo SYSTEM "http://evil.com/xxe.dtd"><root><name>safe</name></root>`

	s := NewSanitizer(ModeMinimal)
	var output bytes.Buffer
	err := s.SanitizeXML(strings.NewReader(input), &output)
	if err != nil {
		t.Fatalf("SanitizeXML() error = %v", err)
	}

	result := output.String()

	// The DTD directive should be replaced with a comment.
	if !strings.Contains(result, "<!-- DTD directive stripped -->") {
		t.Error("DTD directive was not replaced with stripped comment")
	}
	// The original DOCTYPE should not appear.
	if strings.Contains(result, "DOCTYPE") {
		t.Error("DOCTYPE directive was not stripped from output")
	}
	// The document content should still be present.
	if !strings.Contains(result, "<root>") {
		t.Error("root element not preserved after directive stripping")
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

func BenchmarkSanitizeXML(b *testing.B) {
	// Generate a realistic XML input with ~1000 nested elements.
	var sb strings.Builder
	sb.WriteString(`<?xml version="1.0"?>` + "\n")
	sb.WriteString("<opnsense>\n")
	sb.WriteString("  <system>\n")

	// Generate users with passwords and IPs to exercise redaction paths.
	for i := range 100 {
		n := strconv.Itoa(i)
		sb.WriteString("    <user>\n")
		sb.WriteString("      <name>user" + n + "</name>\n")
		sb.WriteString("      <password>secret" + n + "</password>\n")
		sb.WriteString("      <email>user" + n + "@company.com</email>\n")
		sb.WriteString("      <gateway>8.8." + strconv.Itoa(i/256) + "." + n + "</gateway>\n")
		sb.WriteString("    </user>\n")
	}

	sb.WriteString("  </system>\n")
	sb.WriteString("  <interfaces>\n")

	// Generate interface entries with nested elements.
	for i := range 50 {
		n := strconv.Itoa(i)
		sb.WriteString("    <iface" + n + ">\n")
		sb.WriteString("      <ipaddr>192.168." + n + ".1</ipaddr>\n")
		sb.WriteString("      <subnet>24</subnet>\n")
		sb.WriteString("      <descr>Interface " + n + "</descr>\n")
		sb.WriteString("    </iface" + n + ">\n")
	}

	sb.WriteString("  </interfaces>\n")
	sb.WriteString("  <filter>\n")

	// Generate firewall rules.
	for i := range 100 {
		n := strconv.Itoa(i)
		sb.WriteString("    <rule>\n")
		sb.WriteString("      <descr>Rule " + n + "</descr>\n")
		sb.WriteString("      <source>10.0." + n + ".0/24</source>\n")
		sb.WriteString("      <destination>172.16." + n + ".0/24</destination>\n")
		sb.WriteString("      <protocol>tcp</protocol>\n")
		sb.WriteString("    </rule>\n")
	}

	sb.WriteString("  </filter>\n")
	sb.WriteString("</opnsense>\n")

	input := sb.String()

	b.ResetTimer()
	b.ReportAllocs()

	for b.Loop() {
		s := NewSanitizer(ModeAggressive)
		var output bytes.Buffer
		if err := s.SanitizeXML(strings.NewReader(input), &output); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkSanitizeXML_MixedEmpty simulates a more realistic OPNsense config
// where many elements are empty/self-closing containers (common in real
// exports) interleaved with populated leaf elements. This exercises the
// deferred path-materialization optimization from issue #148 — empty
// CharData tokens should not trigger a strings.Join call.
func BenchmarkSanitizeXML_MixedEmpty(b *testing.B) {
	var sb strings.Builder
	sb.WriteString(`<?xml version="1.0"?>` + "\n")
	sb.WriteString("<opnsense>\n")

	// Emit a realistic mix: ~5k populated leaves alongside ~10k empty
	// containers and self-closing elements (matches config.xml shape).
	sb.WriteString("  <system>\n")
	for i := range 200 {
		n := strconv.Itoa(i)
		sb.WriteString("    <user>\n")
		sb.WriteString("      <name>user" + n + "</name>\n")
		sb.WriteString("      <password>secret" + n + "</password>\n")
		sb.WriteString("      <descr></descr>\n") // empty element (no join needed)
		sb.WriteString("      <disabled/>\n")     // self-closing (no CharData match)
		sb.WriteString("      <scope>user</scope>\n")
		sb.WriteString("      <expires></expires>\n") // empty
		sb.WriteString("      <authorizedkeys></authorizedkeys>\n")
		sb.WriteString("      <ipsecpsk></ipsecpsk>\n")
		sb.WriteString("    </user>\n")
	}
	sb.WriteString("  </system>\n")

	sb.WriteString("  <filter>\n")
	for i := range 500 {
		n := strconv.Itoa(i)
		octet := strconv.Itoa(i % 256) // keep third octet in valid 0-255 range
		sb.WriteString("    <rule>\n")
		sb.WriteString("      <type>pass</type>\n")
		sb.WriteString("      <descr>Rule " + n + "</descr>\n")
		sb.WriteString("      <source>\n")
		sb.WriteString("        <network></network>\n") // empty container
		sb.WriteString("        <address>10.0." + octet + ".0/24</address>\n")
		sb.WriteString("      </source>\n")
		sb.WriteString("      <destination>\n")
		sb.WriteString("        <any/>\n")
		sb.WriteString("      </destination>\n")
		sb.WriteString("      <protocol>tcp</protocol>\n")
		sb.WriteString("      <log/>\n")      // self-closing
		sb.WriteString("      <disabled/>\n") // self-closing
		sb.WriteString("      <interface>lan</interface>\n")
		sb.WriteString("    </rule>\n")
	}
	sb.WriteString("  </filter>\n")

	sb.WriteString("</opnsense>\n")
	input := sb.String()

	b.ResetTimer()
	b.ReportAllocs()

	for b.Loop() {
		s := NewSanitizer(ModeAggressive)
		var output bytes.Buffer
		if err := s.SanitizeXML(strings.NewReader(input), &output); err != nil {
			b.Fatal(err)
		}
	}
}
