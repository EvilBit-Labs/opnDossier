// Package opnsense defines the data structures for OPNsense configurations.
//
// This package provides comprehensive data models for OPNsense firewall configurations,
// supporting XML, JSON, and YAML serialization formats.
package opnsense

import (
	"encoding/xml"
	"strings"

	"github.com/EvilBit-Labs/opnDossier/pkg/schema/shared"
)

// BoolFlag represents a presence-based boolean used throughout OPNsense XML configurations.
// Absent element means false; <tag/> (empty body) means true; <tag>value</tag> delegates
// to the liberal value-parser [shared.IsValueTrue] so "on", "yes", "1", "true", "enabled",
// and their case variants are all interpreted correctly. This matches how both OPNsense
// and pfSense emit boolean-semantic fields in the wild.
//
// MarshalXML is defined on a POINTER receiver (*BoolFlag). This is critical for correct
// serialization: when a struct containing a BoolFlag field is marshaled by value (not pointer),
// encoding/xml cannot find the pointer-receiver method and falls back to default bool
// serialization, producing <enable>true</enable> instead of <enable/>. When embedding
// BoolFlag in structs that may be marshaled by value, the parent struct needs special
// handling for addressability (see GOTCHAS 15.1 in project documentation).
//
// Compile-time interface compliance is verified below:
//
//	var _ xml.Marshaler   = (*BoolFlag)(nil)
//	var _ xml.Unmarshaler = (*BoolFlag)(nil)
type BoolFlag bool

// MarshalXML implements [xml.Marshaler] for BoolFlag on a pointer receiver.
// When true, it encodes a self-closing empty element (e.g., <enable/>).
// When false, it encodes nothing (element absence means false in OPNsense).
func (bf *BoolFlag) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	if *bf {
		return e.EncodeElement("", start)
	}

	return nil
}

// UnmarshalXML implements [xml.Unmarshaler] for BoolFlag with presence+value
// semantics:
//   - Absent element (UnmarshalXML never called) → false (Go zero value).
//   - <tag/> or <tag></tag> (empty body) → true (presence means enabled,
//     preserving the historical OPNsense convention).
//   - <tag>body</tag> → [shared.IsValueTrue](body): "on", "yes", "1",
//     "true", "enabled" (any casing) → true; "off", "no", "0", "false",
//     "disabled" → false; unknown values → false.
//
// The delegation to shared.IsValueTrue unifies the liberal boolean vocabulary
// used by OPNsense and pfSense configuration exports.
func (bf *BoolFlag) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	var content string
	if err := d.DecodeElement(&content, &start); err != nil {
		return err
	}

	if strings.TrimSpace(content) == "" {
		*bf = true

		return nil
	}

	*bf = BoolFlag(shared.IsValueTrue(content))

	return nil
}

// String returns string representation of the boolean flag.
func (bf *BoolFlag) String() string {
	if *bf {
		return "true"
	}

	return "false"
}

// Bool returns the underlying boolean value.
func (bf *BoolFlag) Bool() bool {
	return bool(*bf)
}

// Set sets the boolean flag value.
func (bf *BoolFlag) Set(value bool) {
	*bf = BoolFlag(value)
}

// Compile-time interface compliance checks for BoolFlag.
var (
	_ xml.Marshaler   = (*BoolFlag)(nil)
	_ xml.Unmarshaler = (*BoolFlag)(nil)
)

// ChangeMeta tracks creation and modification metadata for configuration items,
// recording who made the change and when it was created or last updated.
type ChangeMeta struct {
	Created  string `xml:"created,omitempty"`
	Updated  string `xml:"updated,omitempty"`
	Username string `xml:"username,omitempty"`
}

// RuleLocation provides granular source/destination address and port specification
// for firewall and NAT rules. It supports network aliases, CIDR addresses, and
// negation via the Not flag. The Network, Address, and Subnet fields are used in
// combination: Network is a named alias (e.g., "lan", "wanip"), while Address holds
// a literal IP and Subnet holds the CIDR prefix length.
type RuleLocation struct {
	XMLName xml.Name `xml:",omitempty"`

	Network string   `xml:"network,omitempty"`
	Address string   `xml:"address,omitempty"`
	Subnet  string   `xml:"subnet,omitempty"`
	Port    string   `xml:"port,omitempty"`
	Not     BoolFlag `xml:"not,omitempty"`
}

// IsAny returns true if this location represents "any" -- either because Network
// is explicitly set to NetworkAny, or because all address fields are empty.
func (rl *RuleLocation) IsAny() bool {
	return rl.Network == NetworkAny || (rl.Network == "" && rl.Address == "" && rl.Port == "")
}

// String returns a human-readable representation of the rule location.
func (rl *RuleLocation) String() string {
	var parts []string

	if rl.Not {
		parts = append(parts, "NOT")
	}

	if rl.Network != "" {
		parts = append(parts, rl.Network)
	} else if rl.Address != "" {
		addr := rl.Address
		if rl.Subnet != "" {
			addr += "/" + rl.Subnet
		}

		parts = append(parts, addr)
	}

	if rl.Port != "" {
		parts = append(parts, ":"+rl.Port)
	}

	if len(parts) == 0 {
		return "any"
	}

	return strings.Join(parts, " ")
}
