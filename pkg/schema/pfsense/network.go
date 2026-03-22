// Package pfsense defines the data structures for pfSense configurations.
package pfsense

import (
	"encoding/xml"
	"maps"
	"slices"

	opnsense "github.com/EvilBit-Labs/opnDossier/pkg/schema/opnsense"
)

// DHCPv6 contains the DHCPv6 server configuration for all interfaces.
// Uses a map-based representation identical to Dhcpd, supporting wan, lan, opt0, etc.
type DHCPv6 struct {
	Items map[string]DHCPv6Interface `xml:",any" json:"dhcpv6,omitempty" yaml:"dhcpv6,omitempty"`
}

// UnmarshalXML implements custom XML unmarshaling for the DHCPv6 map.
func (d *DHCPv6) UnmarshalXML(decoder *xml.Decoder, start xml.StartElement) error {
	d.Items = make(map[string]DHCPv6Interface)

	for {
		tok, err := decoder.Token()
		if err != nil {
			return err
		}

		switch se := tok.(type) {
		case xml.StartElement:
			var dhcpIface DHCPv6Interface
			if err := decoder.DecodeElement(&dhcpIface, &se); err != nil {
				return err
			}

			d.Items[se.Name.Local] = dhcpIface
		case xml.EndElement:
			if se.Name == start.Name {
				return nil
			}
		}
	}
}

// MarshalXML implements custom XML marshaling for the DHCPv6 map.
func (d *DHCPv6) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	if err := e.EncodeToken(start); err != nil {
		return err
	}

	for _, key := range slices.Sorted(maps.Keys(d.Items)) {
		dhcpIface := d.Items[key]
		dhcpStart := xml.StartElement{Name: xml.Name{Local: key}}
		if err := e.EncodeElement(dhcpIface, dhcpStart); err != nil {
			return err
		}
	}

	return e.EncodeToken(xml.EndElement{Name: start.Name})
}

// Get returns a DHCPv6 interface configuration by its key name (e.g., "lan", "opt0").
// Returns the DHCPv6 interface configuration and a boolean indicating if it was found.
func (d *DHCPv6) Get(key string) (DHCPv6Interface, bool) {
	if d.Items == nil {
		return DHCPv6Interface{}, false
	}

	dhcpIface, ok := d.Items[key]

	return dhcpIface, ok
}

// Names returns a slice of all DHCPv6 interface key names in the configuration.
func (d *DHCPv6) Names() []string {
	if d.Items == nil {
		return []string{}
	}

	return slices.Sorted(maps.Keys(d.Items))
}

// DHCPv6Interface contains the DHCPv6 server configuration for a specific interface.
// It includes pfSense-specific fields for Router Advertisement mode and priority.
type DHCPv6Interface struct {
	Enable     string         `xml:"enable,omitempty"     json:"enable,omitempty"     yaml:"enable,omitempty"`
	Range      opnsense.Range `xml:"range,omitempty"      json:"range"                yaml:"range,omitempty"`
	RAMode     string         `xml:"ramode,omitempty"     json:"raMode,omitempty"     yaml:"raMode,omitempty"`
	RAPriority string         `xml:"rapriority,omitempty" json:"raPriority,omitempty" yaml:"raPriority,omitempty"`
}
