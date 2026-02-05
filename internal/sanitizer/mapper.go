package sanitizer

import (
	"encoding/json"
	"fmt"
	"maps"
	"sync"
	"time"
)

// Mapper maintains consistent mappings between original and redacted values.
// This ensures the same original value always maps to the same redacted value
// throughout the entire document for referential integrity.
type Mapper struct {
	mu sync.RWMutex

	// Counters for generating sequential replacements
	publicIPCounter  int
	privateIPCounter int
	hostnameCounter  int
	usernameCounter  int
	domainCounter    int
	macCounter       int
	emailCounter     int

	// Maps original values to their replacements
	ipMappings       map[string]string
	hostnameMappings map[string]string
	usernameMappings map[string]string
	domainMappings   map[string]string
	macMappings      map[string]string
	emailMappings    map[string]string

	// Generic mappings for other values
	genericMappings map[string]string
}

// MappingReport represents the JSON output for the mapping file.
type MappingReport struct {
	Version   string            `json:"version"`
	Timestamp string            `json:"timestamp"`
	Mode      string            `json:"mode"`
	Mappings  MappingCategories `json:"mappings"`
}

// MappingCategories groups mappings by category.
type MappingCategories struct {
	IPAddresses  map[string]string `json:"ip_addresses,omitempty"`
	Hostnames    map[string]string `json:"hostnames,omitempty"`
	Usernames    map[string]string `json:"usernames,omitempty"`
	Domains      map[string]string `json:"domains,omitempty"`
	MACAddresses map[string]string `json:"mac_addresses,omitempty"`
	Emails       map[string]string `json:"emails,omitempty"`
	Other        map[string]string `json:"other,omitempty"`
}

// NewMapper creates a new Mapper instance with initialized maps.
func NewMapper() *Mapper {
	return &Mapper{
		ipMappings:       make(map[string]string),
		hostnameMappings: make(map[string]string),
		usernameMappings: make(map[string]string),
		domainMappings:   make(map[string]string),
		macMappings:      make(map[string]string),
		emailMappings:    make(map[string]string),
		genericMappings:  make(map[string]string),
	}
}

// MapPublicIP returns a consistent replacement for a public IP address.
func (m *Mapper) MapPublicIP(original string) string {
	m.mu.Lock()
	defer m.mu.Unlock()

	if replacement, exists := m.ipMappings[original]; exists {
		return replacement
	}

	m.publicIPCounter++
	replacement := fmt.Sprintf("[REDACTED-PUBLIC-IP-%d]", m.publicIPCounter)
	m.ipMappings[original] = replacement
	return replacement
}

// MapPrivateIP returns a consistent replacement for a private IP address.
// If preserveStructure is true, it preserves the network class structure.
func (m *Mapper) MapPrivateIP(original string, preserveStructure bool) string {
	m.mu.Lock()
	defer m.mu.Unlock()

	if replacement, exists := m.ipMappings[original]; exists {
		return replacement
	}

	m.privateIPCounter++
	var replacement string

	if preserveStructure {
		// Preserve the first two octets to maintain network visibility
		// 192.168.1.100 -> 192.168.X.Y
		parts := extractOctets(original)
		if len(parts) >= minOctetsForStructure {
			replacement = fmt.Sprintf("%s.%s.X.%d", parts[0], parts[1], m.privateIPCounter)
		} else {
			replacement = fmt.Sprintf("10.0.0.%d", m.privateIPCounter)
		}
	} else {
		replacement = fmt.Sprintf("10.0.0.%d", m.privateIPCounter)
	}

	m.ipMappings[original] = replacement
	return replacement
}

// MapHostname returns a consistent replacement for a hostname.
func (m *Mapper) MapHostname(original string) string {
	m.mu.Lock()
	defer m.mu.Unlock()

	if replacement, exists := m.hostnameMappings[original]; exists {
		return replacement
	}

	m.hostnameCounter++
	replacement := fmt.Sprintf("host-%03d.example.com", m.hostnameCounter)
	m.hostnameMappings[original] = replacement
	return replacement
}

// MapUsername returns a consistent replacement for a username.
func (m *Mapper) MapUsername(original string) string {
	m.mu.Lock()
	defer m.mu.Unlock()

	if replacement, exists := m.usernameMappings[original]; exists {
		return replacement
	}

	m.usernameCounter++
	replacement := fmt.Sprintf("user-%03d", m.usernameCounter)
	m.usernameMappings[original] = replacement
	return replacement
}

// Domain redaction constants.
const (
	defaultRedactedDomain = "example.com"
	minOctetsForStructure = 2
)

// MapDomain returns a consistent replacement for a domain name.
func (m *Mapper) MapDomain(original string) string {
	m.mu.Lock()
	defer m.mu.Unlock()

	if replacement, exists := m.domainMappings[original]; exists {
		return replacement
	}

	m.domainCounter++
	if m.domainCounter == 1 {
		m.domainMappings[original] = defaultRedactedDomain
		return defaultRedactedDomain
	}
	replacement := fmt.Sprintf("example%d.com", m.domainCounter)
	m.domainMappings[original] = replacement
	return replacement
}

// MapMAC returns a consistent replacement for a MAC address.
func (m *Mapper) MapMAC(original string) string {
	m.mu.Lock()
	defer m.mu.Unlock()

	if replacement, exists := m.macMappings[original]; exists {
		return replacement
	}

	m.macCounter++
	replacement := fmt.Sprintf("XX:XX:XX:XX:XX:%02X", m.macCounter)
	m.macMappings[original] = replacement
	return replacement
}

// MapEmail returns a consistent replacement for an email address.
func (m *Mapper) MapEmail(original string) string {
	m.mu.Lock()
	defer m.mu.Unlock()

	if replacement, exists := m.emailMappings[original]; exists {
		return replacement
	}

	m.emailCounter++
	replacement := fmt.Sprintf("user%d@example.com", m.emailCounter)
	m.emailMappings[original] = replacement
	return replacement
}

// MapGeneric returns a consistent replacement for a generic value.
func (m *Mapper) MapGeneric(original, category string) string {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := category + ":" + original
	if replacement, exists := m.genericMappings[key]; exists {
		return replacement
	}

	replacement := fmt.Sprintf("[%s-REDACTED]", category)
	m.genericMappings[key] = replacement
	return replacement
}

// GenerateReport creates a mapping report for the given mode.
func (m *Mapper) GenerateReport(mode string) *MappingReport {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return &MappingReport{
		Version:   "1.0",
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Mode:      mode,
		Mappings: MappingCategories{
			IPAddresses:  copyMap(m.ipMappings),
			Hostnames:    copyMap(m.hostnameMappings),
			Usernames:    copyMap(m.usernameMappings),
			Domains:      copyMap(m.domainMappings),
			MACAddresses: copyMap(m.macMappings),
			Emails:       copyMap(m.emailMappings),
			Other:        copyMap(m.genericMappings),
		},
	}
}

// ToJSON returns the mapping report as JSON bytes.
func (m *Mapper) ToJSON(mode string) ([]byte, error) {
	report := m.GenerateReport(mode)
	return json.MarshalIndent(report, "", "  ")
}

// Reset clears all mappings and counters.
func (m *Mapper) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.publicIPCounter = 0
	m.privateIPCounter = 0
	m.hostnameCounter = 0
	m.usernameCounter = 0
	m.domainCounter = 0
	m.macCounter = 0
	m.emailCounter = 0

	m.ipMappings = make(map[string]string)
	m.hostnameMappings = make(map[string]string)
	m.usernameMappings = make(map[string]string)
	m.domainMappings = make(map[string]string)
	m.macMappings = make(map[string]string)
	m.emailMappings = make(map[string]string)
	m.genericMappings = make(map[string]string)
}

// extractOctets splits an IPv4 address into its octets.
func extractOctets(ip string) []string {
	var octets []string
	var current string
	for _, c := range ip {
		if c == '.' {
			octets = append(octets, current)
			current = ""
		} else {
			current += string(c)
		}
	}
	if current != "" {
		octets = append(octets, current)
	}
	return octets
}

// copyMap creates a copy of a string map.
func copyMap(m map[string]string) map[string]string {
	if len(m) == 0 {
		return nil
	}
	result := make(map[string]string, len(m))
	maps.Copy(result, m)
	return result
}
