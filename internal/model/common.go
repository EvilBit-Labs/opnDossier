// Package model defines the data structures for OPNsense configurations.
//
// This package provides comprehensive data models for OPNsense firewall configurations,
// supporting XML, JSON, and YAML serialization formats.
package model

import (
	"encoding/xml"
	"strings"
)

// BoolFlag provides custom XML marshaling for OPNsense boolean values.
type BoolFlag bool

// MarshalXML implements custom XML marshaling for boolean flags.
func (bf BoolFlag) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	if bf {
		return e.EncodeElement("", start)
	}

	return nil
}

// UnmarshalXML implements custom XML unmarshaling for boolean flags.
func (bf *BoolFlag) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	*bf = true

	var content string
	if err := d.DecodeElement(&content, &start); err != nil {
		return err
	}

	return nil
}

// String returns string representation of the boolean flag.
func (bf BoolFlag) String() string {
	if bf {
		return "true"
	}

	return "false"
}

// Bool returns the underlying boolean value.
func (bf BoolFlag) Bool() bool {
	return bool(bf)
}

// Set sets the boolean flag value.
func (bf *BoolFlag) Set(value bool) {
	*bf = BoolFlag(value)
}

var _ xml.Marshaler = (*BoolFlag)(nil)

// ChangeMeta tracks creation and modification metadata for configuration items.
type ChangeMeta struct {
	Created  string `xml:"created,omitempty"`
	Updated  string `xml:"updated,omitempty"`
	Username string `xml:"username,omitempty"`
}

// RuleLocation provides granular source/destination address and port specification.
type RuleLocation struct {
	XMLName xml.Name `xml:",omitempty"`

	Network string   `xml:"network,omitempty"`
	Address string   `xml:"address,omitempty"`
	Subnet  string   `xml:"subnet,omitempty"`
	Port    string   `xml:"port,omitempty"`
	Not     BoolFlag `xml:"not,omitempty"`
}

// IsAny returns true if this location represents "any".
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
