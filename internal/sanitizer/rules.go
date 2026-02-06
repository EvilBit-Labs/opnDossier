package sanitizer

import "slices"

// Mode represents the sanitization aggressiveness level.
type Mode string

const (
	// ModeAggressive redacts all sensitive data for public sharing.
	ModeAggressive Mode = "aggressive"
	// ModeModerate redacts most sensitive data but preserves some network structure.
	ModeModerate Mode = "moderate"
	// ModeMinimal redacts only the most sensitive data (passwords, keys).
	ModeMinimal Mode = "minimal"
)

// ValidModes returns the supported sanitization modes (aggressive, moderate, minimal) in order from most to least aggressive.
func ValidModes() []Mode {
	return []Mode{ModeAggressive, ModeModerate, ModeMinimal}
}

// Valid modes are "aggressive", "moderate", and "minimal".
func IsValidMode(mode string) bool {
	switch Mode(mode) {
	case ModeAggressive, ModeModerate, ModeMinimal:
		return true
	default:
		return false
	}
}

// Rule defines a redaction rule for a specific type of sensitive data.
type Rule struct {
	// Name is the rule identifier.
	Name string
	// Description explains what this rule redacts.
	Description string
	// Category groups related rules together.
	Category RuleCategory
	// Modes specifies which sanitization modes activate this rule.
	Modes []Mode
	// FieldPatterns are field name patterns that trigger redaction.
	FieldPatterns []string
	// ValueDetector is an optional function to detect sensitive values.
	ValueDetector func(value string) bool
	// Redactor performs the actual redaction using the mapper.
	Redactor func(mapper *Mapper, fieldName, value string) string
}

// RuleCategory groups related redaction rules.
type RuleCategory string

// Rule category constants.
const (
	CategoryCredentials RuleCategory = "credentials"
	CategoryNetwork     RuleCategory = "network"
	CategoryIdentity    RuleCategory = "identity"
	CategoryCrypto      RuleCategory = "crypto"
	CategorySystem      RuleCategory = "system"
)

// RuleEngine manages and applies redaction rules.
type RuleEngine struct {
	rules  []Rule
	mapper *Mapper
	mode   Mode
}

// NewRuleEngine creates a RuleEngine configured for the given Mode.
// The engine is populated with the package's builtin rules and a default Mapper.
func NewRuleEngine(mode Mode) *RuleEngine {
	engine := &RuleEngine{
		rules:  builtinRules(),
		mapper: NewMapper(),
		mode:   mode,
	}
	return engine
}

// SetMapper allows setting a custom mapper (useful for testing or chaining).
func (e *RuleEngine) SetMapper(m *Mapper) {
	e.mapper = m
}

// GetMapper returns the current mapper for generating reports.
func (e *RuleEngine) GetMapper() *Mapper {
	return e.mapper
}

// ShouldRedactField determines if a field should be redacted based on its name.
func (e *RuleEngine) ShouldRedactField(fieldName string) (bool, *Rule) {
	for i := range e.rules {
		rule := &e.rules[i]
		if !e.ruleActiveForMode(rule) {
			continue
		}
		for _, pattern := range rule.FieldPatterns {
			if fieldNameMatches(fieldName, pattern) {
				return true, rule
			}
		}
	}
	return false, nil
}

// ShouldRedactValue determines if a value should be redacted based on its content.
func (e *RuleEngine) ShouldRedactValue(fieldName, value string) (bool, *Rule) {
	// First check field-based rules
	if should, rule := e.ShouldRedactField(fieldName); should {
		return true, rule
	}

	// Then check value-based detection
	for i := range e.rules {
		rule := &e.rules[i]
		if !e.ruleActiveForMode(rule) {
			continue
		}
		if rule.ValueDetector != nil && rule.ValueDetector(value) {
			return true, rule
		}
	}
	return false, nil
}

// Redact applies the appropriate redaction for a field/value pair.
func (e *RuleEngine) Redact(fieldName, value string) string {
	should, rule := e.ShouldRedactValue(fieldName, value)
	if !should || rule == nil {
		return value
	}
	if rule.Redactor != nil {
		return rule.Redactor(e.mapper, fieldName, value)
	}
	// Default redaction
	return e.mapper.MapGeneric(value, string(rule.Category))
}

// ruleActiveForMode checks if a rule should be active for the current mode.
func (e *RuleEngine) ruleActiveForMode(rule *Rule) bool {
	return slices.Contains(rule.Modes, e.mode)
}

// fieldNameMatches reports whether pattern is a case-insensitive substring of fieldName.
// An empty pattern always matches.
func fieldNameMatches(fieldName, pattern string) bool {
	return containsIgnoreCase(fieldName, pattern)
}

// containsIgnoreCase reports whether substr is contained within s using an
// ASCII-only, case-insensitive comparison.
// It returns true if substr appears in s when letters A–Z are treated as a–z,
// false otherwise.
func containsIgnoreCase(s, substr string) bool {
	sLower := toLower(s)
	substrLower := toLower(substr)
	return contains(sLower, substrLower)
}

// asciiLowercaseDelta is the offset between uppercase and lowercase ASCII letters.
const asciiLowercaseDelta = 32

// toLower converts ASCII uppercase letters (A-Z) in s to their lowercase
// equivalents and returns the resulting string. Non-ASCII bytes and ASCII
// characters outside A-Z are left unchanged; the result has the same length
// as the input.
func toLower(s string) string {
	result := make([]byte, len(s))
	for i := range len(s) {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			result[i] = c + asciiLowercaseDelta
		} else {
			result[i] = c
		}
	}
	return string(result)
}

// contains reports whether substr is a substring of s.
// An empty substr is considered contained; if substr is longer than s it is not contained.
func contains(s, substr string) bool {
	if substr == "" {
		return true
	}
	if len(substr) > len(s) {
		return false
	}
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// builtinRules returns the default set of redaction rules used by the sanitizer package.
// The returned rules cover credentials, cryptographic material, identity, network, and system
// fields; each rule indicates the modes in which it is active and provides field patterns,
// optional value detectors, and redactors that the engine uses to determine and perform
// redaction.
func builtinRules() []Rule {
	allModes := []Mode{ModeAggressive, ModeModerate, ModeMinimal}
	aggressiveModerate := []Mode{ModeAggressive, ModeModerate}
	aggressiveOnly := []Mode{ModeAggressive}

	return []Rule{
		// Credential rules - all modes
		{
			Name:        "password",
			Description: "Redacts password fields",
			Category:    CategoryCredentials,
			Modes:       allModes,
			FieldPatterns: []string{
				"password", "passwd", "pass", "pwd",
			},
			Redactor: func(_ *Mapper, _, _ string) string {
				return "[REDACTED-PASSWORD]"
			},
		},
		{
			Name:        "secret",
			Description: "Redacts secret/token fields",
			Category:    CategoryCredentials,
			Modes:       allModes,
			FieldPatterns: []string{
				"secret", "token", "apikey", "api_key", "api-key",
				"accesskey", "secretkey", "authkey", "auth_key",
			},
			Redactor: func(_ *Mapper, _, _ string) string {
				return "[REDACTED-SECRET]"
			},
		},
		{
			Name:        "psk",
			Description: "Redacts pre-shared keys",
			Category:    CategoryCredentials,
			Modes:       allModes,
			FieldPatterns: []string{
				"psk", "preshared", "pre-shared", "ipsecpsk",
			},
			Redactor: func(_ *Mapper, _, _ string) string {
				return "[REDACTED-PSK]"
			},
		},
		{
			Name:        "snmp_community",
			Description: "Redacts SNMP community strings",
			Category:    CategoryCredentials,
			Modes:       allModes,
			FieldPatterns: []string{
				"community", "rocommunity", "rwcommunity",
			},
			Redactor: func(_ *Mapper, _, _ string) string {
				return "[REDACTED-SNMP-COMMUNITY]"
			},
		},

		// Crypto rules - all modes
		{
			Name:        "private_key",
			Description: "Redacts private keys",
			Category:    CategoryCrypto,
			Modes:       allModes,
			FieldPatterns: []string{
				"privatekey", "private_key", "prv", "privkey",
			},
			ValueDetector: IsPrivateKey,
			Redactor: func(_ *Mapper, _, _ string) string {
				return "[REDACTED-PRIVATE-KEY]"
			},
		},
		{
			Name:        "certificate",
			Description: "Redacts certificates (aggressive only)",
			Category:    CategoryCrypto,
			Modes:       aggressiveOnly,
			FieldPatterns: []string{
				"cert", "certificate", "crt",
			},
			ValueDetector: IsCertificate,
			Redactor: func(_ *Mapper, _, _ string) string {
				return "[REDACTED-CERTIFICATE]"
			},
		},

		// Identity rules - aggressive and moderate
		// NOTE: Email must be checked BEFORE hostname, as emails contain dots
		{
			Name:          "email",
			Description:   "Redacts email addresses",
			Category:      CategoryIdentity,
			Modes:         aggressiveModerate,
			ValueDetector: IsEmail,
			Redactor: func(m *Mapper, _, value string) string {
				return m.MapEmail(value)
			},
		},

		// Network rules - aggressive and moderate
		{
			Name:          "public_ip",
			Description:   "Redacts public IP addresses",
			Category:      CategoryNetwork,
			Modes:         aggressiveModerate,
			ValueDetector: IsPublicIP,
			Redactor: func(m *Mapper, _, value string) string {
				return m.MapPublicIP(value)
			},
		},
		{
			Name:        "private_ip_aggressive",
			Description: "Redacts private IP addresses (aggressive mode)",
			Category:    CategoryNetwork,
			Modes:       aggressiveOnly,
			ValueDetector: func(value string) bool {
				return IsPrivateIP(value) && IsIPv4(value)
			},
			Redactor: func(m *Mapper, _, value string) string {
				return m.MapPrivateIP(value, false)
			},
		},
		{
			Name:          "mac_address",
			Description:   "Redacts MAC addresses",
			Category:      CategoryNetwork,
			Modes:         aggressiveModerate,
			ValueDetector: IsMAC,
			Redactor: func(m *Mapper, _, value string) string {
				return m.MapMAC(value)
			},
		},
		{
			Name:        "hostname",
			Description: "Redacts hostnames/FQDNs",
			Category:    CategoryNetwork,
			Modes:       aggressiveOnly,
			ValueDetector: func(value string) bool {
				// Don't match emails as hostnames
				if IsEmail(value) {
					return false
				}
				return IsHostname(value)
			},
			Redactor: func(m *Mapper, _, value string) string {
				return m.MapHostname(value)
			},
		},
		{
			Name:        "username",
			Description: "Redacts usernames",
			Category:    CategoryIdentity,
			Modes:       aggressiveOnly,
			FieldPatterns: []string{
				"username", "user", "login", "uid",
			},
			Redactor: func(m *Mapper, _, value string) string {
				// Don't redact common system users
				if isSystemUser(value) {
					return value
				}
				return m.MapUsername(value)
			},
		},

		// System rules
		{
			Name:        "ssh_authorized_keys",
			Description: "Redacts SSH authorized keys",
			Category:    CategorySystem,
			Modes:       allModes,
			FieldPatterns: []string{
				"authorizedkeys", "authorized_keys", "sshkey", "ssh_key",
			},
			Redactor: func(_ *Mapper, _, _ string) string {
				return "[REDACTED-SSH-KEY]"
			},
		},
	}
}

// isSystemUser reports whether username matches a known common system account.
// The check is case-insensitive and uses a predefined list (for example: "root", "admin", "nobody", "daemon", "www-data").
func isSystemUser(username string) bool {
	systemUsers := []string{
		"root", "admin", "nobody", "daemon", "www", "www-data",
		"opnsense", "unbound", "dhcpd", "sshd", "ntp", "proxy",
	}
	lower := toLower(username)
	return slices.Contains(systemUsers, lower)
}

// GetActiveRules returns rules that are active for the current mode.
func (e *RuleEngine) GetActiveRules() []Rule {
	var active []Rule
	for _, rule := range e.rules {
		if e.ruleActiveForMode(&rule) {
			active = append(active, rule)
		}
	}
	return active
}

// GetRulesByCategory returns all rules in a specific category.
func (e *RuleEngine) GetRulesByCategory(category RuleCategory) []Rule {
	var result []Rule
	for _, rule := range e.rules {
		if rule.Category == category {
			result = append(result, rule)
		}
	}
	return result
}