package security

import "regexp"

// Pattern defines a security impact matching rule.
type Pattern struct {
	Name        string
	Description string
	Section     string         // Section to match (empty = any)
	PathRegex   *regexp.Regexp // Path regex to match (nil = any)
	ChangeType  string         // Change type to match (empty = any)
	Impact      string         // Impact level: "high", "medium", "low"
}

// DefaultPatterns returns the built-in security impact patterns.
// These augment the context-specific scoring in the analyzer (e.g., isPermissiveRule)
// by providing pattern-based scoring for changes that lack explicit SecurityImpact.
func DefaultPatterns() []Pattern {
	return []Pattern{
		// Firewall patterns
		{
			Name:        "firewall-rule-removed",
			Description: "Removal of firewall rules may expose services",
			Section:     "firewall",
			ChangeType:  "removed",
			Impact:      "medium",
		},
		{
			Name:        "firewall-rule-added",
			Description: "New firewall rules change the security boundary",
			Section:     "firewall",
			ChangeType:  "added",
			Impact:      "low",
		},

		// System patterns
		{
			Name:        "webgui-protocol-change",
			Description: "WebGUI protocol changes affect admin access security",
			Section:     "system",
			PathRegex:   regexp.MustCompile(`system\.webgui\.protocol`),
			Impact:      "medium",
		},
		{
			Name:        "dns-server-change",
			Description: "DNS server changes can redirect traffic",
			Section:     "system",
			PathRegex:   regexp.MustCompile(`system\.dnsserver`),
			Impact:      "low",
		},

		// NAT patterns
		{
			Name:        "nat-mode-change",
			Description: "NAT mode changes affect traffic routing",
			Section:     "nat",
			PathRegex:   regexp.MustCompile(`nat\.outbound\.mode`),
			Impact:      "medium",
		},
		{
			Name:        "port-forward-change",
			Description: "Port forward changes expose or hide internal services",
			Section:     "nat",
			PathRegex:   regexp.MustCompile(`nat\.inbound`),
			Impact:      "medium",
		},

		// User patterns
		{
			Name:        "user-added",
			Description: "New user accounts expand access scope",
			Section:     "users",
			ChangeType:  "added",
			Impact:      "medium",
		},
		{
			Name:        "user-removed",
			Description: "Removed user accounts may indicate access revocation",
			Section:     "users",
			ChangeType:  "removed",
			Impact:      "medium",
		},
		{
			Name:        "user-modified",
			Description: "User modifications may change access levels",
			Section:     "users",
			ChangeType:  "modified",
			Impact:      "low",
		},

		// Interface patterns
		{
			Name:        "interface-enable-change",
			Description: "Interface enable state changes affect network connectivity",
			Section:     "interfaces",
			PathRegex:   regexp.MustCompile(`\.enable$`),
			Impact:      "medium",
		},
	}
}
