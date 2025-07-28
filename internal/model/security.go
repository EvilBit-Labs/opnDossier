// Package model defines the data structures for OPNsense configurations.
package model

// SecurityConfig groups security-related configuration.
type SecurityConfig struct {
	Nat    Nat    `json:"nat,omitempty" yaml:"nat,omitempty"`
	Filter Filter `json:"filter,omitempty" yaml:"filter,omitempty"`
}

// Nat contains the NAT configuration.
type Nat struct {
	Outbound Outbound `xml:"outbound"`
}

// Outbound contains the outbound NAT configuration.
type Outbound struct {
	Mode string `xml:"mode"`
}

// Filter contains the firewall filter rules.
type Filter struct {
	Rule []Rule `xml:"rule"`
}

// Rule represents a firewall filter rule.
type Rule struct {
	Type        string      `xml:"type"`
	IPProtocol  string      `xml:"ipprotocol"`
	Descr       string      `xml:"descr"`
	Interface   string      `xml:"interface"`
	Source      Source      `xml:"source"`
	Destination Destination `xml:"destination"`
}

// Source represents the source of a firewall rule.
type Source struct {
	Network string `xml:"network"`
}

// Destination represents the destination of a firewall rule.
// TODO: More Granular Destination Analysis - Expand destination model to include:
//   - Port specifications (single port, port ranges, aliases)
//   - Protocol-specific destination options
//   - Network aliases and address groups
//   - IPv6 destination support
//   - Negation support (not destination)
//
// This would enable more comprehensive firewall rule analysis and comparison.
type Destination struct {
	Any     struct{} `xml:"any"`
	Network string   `xml:"network"`
	// TODO: Add missing destination fields for enhanced analysis:
	// Port    string   `xml:"port,omitempty" json:"port,omitempty" yaml:"port,omitempty"`
	// Address string   `xml:"address,omitempty" json:"address,omitempty" yaml:"address,omitempty"`
	// Not     string   `xml:"not,omitempty" json:"not,omitempty" yaml:"not,omitempty"`
}

// Constructor functions for security models

// NewSecurityConfig creates a new SecurityConfig with properly initialized slices.
func NewSecurityConfig() SecurityConfig {
	return SecurityConfig{
		Filter: Filter{
			Rule: make([]Rule, 0),
		},
	}
}
