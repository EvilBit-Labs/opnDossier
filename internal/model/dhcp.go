// Package model defines the data structures for OPNsense configurations.
package model

import (
	"encoding/xml"
)

// Dhcpd contains the DHCP server configuration for all interfaces.
// Uses a map-based representation to store all interface blocks generically,
// supporting wan, lan, opt0, opt1, etc., and any custom interface elements.
type Dhcpd struct {
	Items map[string]DhcpdInterface `xml:",any" json:"dhcp,omitempty" yaml:"dhcp,omitempty"`
}

// UnmarshalXML implements custom XML unmarshaling for the Dhcpd map.
func (d *Dhcpd) UnmarshalXML(decoder *xml.Decoder, start xml.StartElement) error {
	d.Items = make(map[string]DhcpdInterface)

	for {
		tok, err := decoder.Token()
		if err != nil {
			return err
		}

		switch se := tok.(type) {
		case xml.StartElement:
			// Each interface element (wan, lan, opt0, etc.) becomes a map entry
			var dhcpIface DhcpdInterface
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

// MarshalXML implements custom XML marshaling for the Dhcpd map.
func (d *Dhcpd) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	if err := e.EncodeToken(start); err != nil {
		return err
	}

	// Encode each DHCP interface as a separate element using the key as the element name
	for key, dhcpIface := range d.Items {
		dhcpStart := xml.StartElement{Name: xml.Name{Local: key}}
		if err := e.EncodeElement(dhcpIface, dhcpStart); err != nil {
			return err
		}
	}

	return e.EncodeToken(xml.EndElement{Name: start.Name})
}

// Get returns a DHCP interface configuration by its key name (e.g., "wan", "lan", "opt0").
// Returns the DHCP interface configuration and a boolean indicating if it was found.
//
// Example:
//
//	if lanDhcp, ok := dhcpd.Get("lan"); ok {
//		fmt.Printf("LAN DHCP range: %s - %s\n", lanDhcp.Range.From, lanDhcp.Range.To)
//	}
func (d *Dhcpd) Get(key string) (DhcpdInterface, bool) {
	if d.Items == nil {
		return DhcpdInterface{}, false
	}
	dhcpIface, ok := d.Items[key]
	return dhcpIface, ok
}

// Names returns a slice of all DHCP interface key names in the configuration.
// This includes standard interfaces like "wan", "lan" and optional ones like "opt0", "opt1", etc.
//
// Example:
//
//	names := dhcpd.Names()
//	fmt.Printf("DHCP configured on interfaces: %s\n", strings.Join(names, ", "))
func (d *Dhcpd) Names() []string {
	if d.Items == nil {
		return []string{}
	}
	names := make([]string, 0, len(d.Items))
	for key := range d.Items {
		names = append(names, key)
	}
	return names
}

// Wan returns the WAN DHCP interface configuration if it exists, otherwise returns a zero-value DhcpdInterface and false.
// This is a convenience method for backward compatibility.
func (d *Dhcpd) Wan() (DhcpdInterface, bool) {
	return d.Get("wan")
}

// Lan returns the LAN DHCP interface configuration if it exists, otherwise returns a zero-value DhcpdInterface and false.
// This is a convenience method for backward compatibility.
func (d *Dhcpd) Lan() (DhcpdInterface, bool) {
	return d.Get("lan")
}

// DhcpdInterface contains the DHCP server configuration for a specific interface.
type DhcpdInterface struct {
	Enable              string             `xml:"enable,omitempty"`
	Range               Range              `xml:"range,omitempty"`
	Gateway             string             `xml:"gateway,omitempty"`
	DdnsDomainAlgorithm string             `xml:"ddnsdomainalgorithm,omitempty"`
	NumberOptions       []DHCPNumberOption `xml:"numberoptions>item,omitempty"`
	Winsserver          string             `xml:"winsserver,omitempty"`
	Dnsserver           string             `xml:"dnsserver,omitempty"`
	Ntpserver           string             `xml:"ntpserver,omitempty"`
	Staticmap           []DHCPStaticLease  `xml:"staticmap,omitempty"`
}

// DHCPNumberOption represents a DHCP option with a number and value.
type DHCPNumberOption struct {
	Number string `xml:"number"`
	Type   string `xml:"type,omitempty"`
	Value  string `xml:"value,omitempty"`
}

// DHCPStaticLease represents a static DHCP lease.
type DHCPStaticLease struct {
	Mac              string `xml:"mac"`
	Cid              string `xml:"cid,omitempty"`
	IPAddr           string `xml:"ipaddr"`
	Hostname         string `xml:"hostname,omitempty"`
	Descr            string `xml:"descr,omitempty"`
	Filename         string `xml:"filename,omitempty"`
	Rootpath         string `xml:"rootpath,omitempty"`
	Defaultleasetime string `xml:"defaultleasetime,omitempty"`
	Maxleasetime     string `xml:"maxleasetime,omitempty"`
}

// Range represents a DHCP address range.
type Range struct {
	From string `xml:"from"`
	To   string `xml:"to"`
}

// Constructor functions for DHCP models

// NewDhcpdInterface creates a new DhcpdInterface with properly initialized slices.
func NewDhcpdInterface() DhcpdInterface {
	return DhcpdInterface{
		NumberOptions: make([]DHCPNumberOption, 0),
		Staticmap:     make([]DHCPStaticLease, 0),
	}
}
