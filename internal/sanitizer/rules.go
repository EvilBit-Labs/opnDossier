package sanitizer

import (
	"slices"
	"strings"
)

// Mode represents the sanitization aggressiveness level.
type Mode string

// Sanitization mode constants ordered from most to least aggressive.
const (
	// ModeAggressive redacts all sensitive data for public sharing.
	ModeAggressive Mode = "aggressive"
	// ModeModerate redacts most sensitive data but preserves some network structure.
	ModeModerate Mode = "moderate"
	// ModeMinimal redacts only the most sensitive data (credentials and authserver values).
	ModeMinimal Mode = "minimal"
)

// ValidModes returns the supported sanitization modes (aggressive, moderate, minimal) in order from most to least aggressive.
func ValidModes() []Mode {
	return []Mode{ModeAggressive, ModeModerate, ModeMinimal}
}

// IsValidMode checks if the provided mode string is one of the valid sanitization modes (aggressive, moderate, minimal).
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
	// CategoryCredentials groups rules that redact passwords, keys, and tokens.
	CategoryCredentials RuleCategory = "credentials"
	// CategoryNetwork groups rules that redact IP addresses, MAC addresses, hostnames, subnets, and endpoint configurations.
	CategoryNetwork RuleCategory = "network"
	// CategoryIdentity groups rules that redact usernames, email addresses, and cloud account identifiers.
	CategoryIdentity RuleCategory = "identity"
	// CategoryCrypto groups rules that redact certificates and cryptographic material.
	CategoryCrypto RuleCategory = "crypto"
	// CategorySystem groups rules that redact system-level configuration details.
	CategorySystem RuleCategory = "system"

	redactedSecretValue    = "[REDACTED-SECRET]"
	redactedSubnetValue    = "[REDACTED-SUBNET]"
	redactedPublicKeyValue = "[REDACTED-PUBLIC-KEY]"
)

// RuleEngine manages and applies redaction rules.
type RuleEngine struct {
	rules  []Rule
	mapper *Mapper
	mode   Mode
}

// NewRuleEngine creates a RuleEngine configured for the given Mode.
// The engine is populated with the package's builtin rules and a default Mapper.
// Field patterns are pre-lowercased at construction time to avoid redundant
// allocations on every fieldNameMatches call.
func NewRuleEngine(mode Mode) *RuleEngine {
	rules := builtinRules()
	for i := range rules {
		for j, pat := range rules[i].FieldPatterns {
			rules[i].FieldPatterns[j] = strings.ToLower(pat)
		}
	}
	engine := &RuleEngine{
		rules:  rules,
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
	return e.redactWithRule(rule, fieldName, value)
}

// RedactWithRule applies a specific rule's Redactor to the given field/value pair.
// Use this when you already have the matched rule from ShouldRedactValue to avoid
// a redundant rule lookup (which could match a different rule than the one tracked
// for statistics).
func (e *RuleEngine) RedactWithRule(rule *Rule, fieldName, value string) string {
	if rule == nil {
		return value
	}
	return e.redactWithRule(rule, fieldName, value)
}

// redactWithRule applies the given rule's Redactor, falling back to the generic mapper.
func (e *RuleEngine) redactWithRule(rule *Rule, fieldName, value string) string {
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

// exactMatchPatterns lists field patterns that require exact (case-insensitive)
// matching instead of substring matching. This prevents false positives on
// compound field names (e.g., "key" would otherwise match "sshkey", "apikey";
// "from"/"to" would match "timeout", "protocol", "platformfrom").
// All entries are stored pre-lowercased to match the pre-lowercased field patterns.
var exactMatchPatterns = []string{"key", "from", "to"}

// fieldNameMatches reports whether pattern matches fieldName using a
// case-insensitive substring check. An empty pattern always matches.
// Patterns listed in exactMatchPatterns require an exact (case-insensitive)
// match to prevent false positives on compound field names.
//
// The pattern argument must be pre-lowercased (see NewRuleEngine).
func fieldNameMatches(fieldName, pattern string) bool {
	lowerField := strings.ToLower(fieldName)
	for _, exact := range exactMatchPatterns {
		if pattern == exact {
			return lowerField == exact
		}
	}
	return strings.Contains(lowerField, pattern)
}

// builtinRules returns the default set of redaction rules used by the sanitizer package.
// The returned rules cover credentials, cryptographic material, identity, network, and system
// fields; each rule indicates the modes in which it is active and provides field patterns,
// optional value detectors, and redactors that the engine uses to determine and perform
// redaction.
//
// ORDERING CONTRACT: Rule ordering matters. ShouldRedactField returns on the first
// matching rule, so earlier rules take precedence. Specifically:
//
//   - authserver_config MUST precede password. Both match "ldap_bindpw" (authserver_config
//     via an exact field pattern, password via the "pass" substring). authserver_config
//     pseudonymizes the value via MapAuthServerValue; password flat-redacts to
//     "[REDACTED-PASSWORD]". If reordered, LDAP bind passwords silently switch from
//     pseudonymized to flat-redacted with no error or warning.
//
//   - email MUST precede hostname. Email addresses contain dots that match hostname
//     patterns. The ordering ensures emails are mapped via MapEmail, not MapHostname.
func builtinRules() []Rule {
	allModes := []Mode{ModeAggressive, ModeModerate, ModeMinimal}
	aggressiveModerate := []Mode{ModeAggressive, ModeModerate}
	aggressiveOnly := []Mode{ModeAggressive}

	return []Rule{
		// NOTE: authserver.ldap_* patterns assume OPNsense XML nesting
		// (system.authserver.ldap_*). If a device type uses different nesting
		// (e.g., system.ldap_bindpw without authserver parent), those fields
		// will fall through to the password rule (flat-redacted, not
		// pseudonymized). This is acceptable — pfSense reuses the same
		// opnsense.AuthServer schema with identical nesting.
		{
			Name:        "authserver_config",
			Description: "Pseudonymizes sensitive system/authserver LDAP values",
			Category:    CategorySystem,
			Modes:       allModes,
			FieldPatterns: []string{
				"system.authserver.name",
				"system.authserver.host",
				"authserver.ldap_port",
				"authserver.ldap_basedn",
				"authserver.ldap_authcn",
				"authserver.ldap_extended_query",
				"authserver.ldap_attr_user",
				"authserver.ldap_binddn",
				"authserver.ldap_bindpw",
				"authserver.ldap_sync_memberof_groups",
				"authserver.ldap_sync_default_groups",
			},
			Redactor: func(m *Mapper, fieldName, value string) string {
				return m.MapAuthServerValue(authServerFieldFromPath(fieldName), value)
			},
		},

		// Credential rules - all modes
		{
			Name:        "password",
			Description: "Redacts password fields",
			Category:    CategoryCredentials,
			Modes:       allModes,
			FieldPatterns: []string{
				"password", "passwd", "pass", "pwd",
				"bcrypt-hash", "bcrypt_hash", "sha512-hash",
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
				"otp_seed", "otpseed",
			},
			Redactor: func(_ *Mapper, _, _ string) string {
				return redactedSecretValue
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
				"privatekey", "private_key", "prv", "privkey", "key",
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
			Name:        "email",
			Description: "Redacts email addresses",
			Category:    CategoryIdentity,
			Modes:       aggressiveModerate,
			FieldPatterns: []string{
				"email",
			},
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
			Name:        "mac_address",
			Description: "Redacts MAC addresses",
			Category:    CategoryNetwork,
			Modes:       aggressiveModerate,
			FieldPatterns: []string{
				"mac",
			},
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
			FieldPatterns: []string{
				"hostname", "domain", "althostnames", "hostnames",
			},
			ValueDetector: func(value string) bool {
				// Don't match emails as hostnames
				if IsEmail(value) {
					return false
				}
				return IsHostname(value)
			},
			Redactor: func(m *Mapper, _, value string) string {
				// Guard: hostname field patterns can match fields containing
				// email addresses; delegate to email mapping in that case.
				if IsEmail(value) {
					return m.MapEmail(value)
				}
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

		// Aggressive-only rules — network topology (IPs, subnets, endpoints), cloud identifiers, and public keys.
		{
			Name:        "endpoint",
			Description: "Redacts VPN/tunnel endpoint addresses",
			Category:    CategoryNetwork,
			Modes:       aggressiveOnly,
			FieldPatterns: []string{
				"endpoint", "tunneladdress",
			},
			Redactor: func(_ *Mapper, _, value string) string {
				if value == "" {
					return value
				}
				return "[REDACTED-ENDPOINT]"
			},
		},
		{
			Name:        "ip_address_field",
			Description: "Redacts IP address values in named address fields",
			Category:    CategoryNetwork,
			Modes:       aggressiveOnly,
			FieldPatterns: []string{
				"ipaddr", "ipaddrv6", "from", "to",
			},
			// No ValueDetector: redaction is purely field-name-driven.
			// "from"/"to" are too generic for value-based matching across all fields.
			Redactor: func(m *Mapper, _, value string) string {
				// Guard: field patterns like "from"/"to" can match non-IP values
				// (e.g., "any", "lan"); only redact when the value is actually an IP.
				// When the guard rejects, sanitizer.go counts it as SkippedFields.
				if !IsIP(value) {
					return value
				}
				if IsPublicIP(value) {
					return m.MapPublicIP(value)
				}
				return m.MapPrivateIP(value, false)
			},
		},
		{
			Name:        "subnet_field",
			Description: "Redacts subnet CIDR values in named subnet fields",
			Category:    CategoryNetwork,
			Modes:       aggressiveOnly,
			FieldPatterns: []string{
				"subnet", "subnetv6",
			},
			// ValueDetector enables CIDR detection on unrecognized field names;
			// the Redactor guard handles the field-pattern match path separately.
			ValueDetector: IsSubnet,
			Redactor: func(_ *Mapper, _, value string) string {
				// Guard: field-pattern matches (e.g., "subnet") bypass the ValueDetector,
				// so we must validate here too for non-CIDR values like "255.255.255.0".
				if !IsSubnet(value) {
					return value
				}
				return redactedSubnetValue
			},
		},
		{
			Name:        "cloud_identifier",
			Description: "Redacts cloud provider account and zone identifiers",
			Category:    CategoryIdentity,
			Modes:       aggressiveOnly,
			FieldPatterns: []string{
				"dns_cf_account_id", "dns_cf_zone_id", "account_id", "zone_id",
			},
			Redactor: func(_ *Mapper, _, value string) string {
				if value == "" {
					return value
				}
				return "[REDACTED-CLOUD-ID]"
			},
		},
		{
			Name:        "public_key",
			Description: "Redacts public keys in base64 form",
			Category:    CategoryCrypto,
			Modes:       aggressiveOnly,
			FieldPatterns: []string{
				"pubkey", "pub_key",
			},
			ValueDetector: IsBase64,
			Redactor: func(_ *Mapper, _, _ string) string {
				return redactedPublicKeyValue
			},
		},
	}
}

// authServerFieldFromPath extracts the authserver field type from a dotted path.
// For ldap_* fields, the terminal segment is returned unconditionally since these
// names are LDAP-specific and unambiguous. For all other fields (including "name"
// and "host"), the raw terminal segment is returned so the caller's default
// replacement handles unknown fields in a fail-closed manner. FieldPatterns on the
// authserver_config rule scope which paths reach this function; this function only
// extracts the terminal segment for mapping dispatch.
func authServerFieldFromPath(fieldName string) string {
	lowerFieldName := strings.ToLower(fieldName)
	lastDot := strings.LastIndexByte(lowerFieldName, '.')
	field := lowerFieldName
	if lastDot != -1 && lastDot < len(lowerFieldName)-1 {
		field = lowerFieldName[lastDot+1:]
	}

	return field
}

// systemUsers lists known common system accounts for isSystemUser lookups.
//
//nolint:gochecknoglobals // Immutable lookup table, avoids per-call allocation
var systemUsers = []string{
	"root", "admin", "nobody", "daemon", "www", "www-data",
	"opnsense", "unbound", "dhcpd", "sshd", "ntp", "proxy",
}

// isSystemUser reports whether username matches a known common system account.
// The check is case-insensitive and uses a predefined list (for example: "root", "admin", "nobody", "daemon", "www-data").
func isSystemUser(username string) bool {
	lower := strings.ToLower(username)
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
