// Package pfsense defines the data structures for pfSense configurations.
package pfsense

import (
	"encoding/xml"
	"fmt"
	"maps"
	"slices"

	opnsense "github.com/EvilBit-Labs/opnDossier/pkg/schema/opnsense"
)

// Interface represents a pfSense network interface configuration.
// It is a copy-on-write fork of opnsense.Interface with Enable changed from
// string to BoolFlag, because pfSense uses presence-based <enable/> elements.
type Interface struct {
	Enable              opnsense.BoolFlag     `xml:"enable,omitempty"              json:"enable,omitempty"              yaml:"enable,omitempty"`
	If                  string                `xml:"if,omitempty"                  json:"if,omitempty"                  yaml:"if,omitempty"`
	Descr               string                `xml:"descr,omitempty"               json:"descr,omitempty"               yaml:"descr,omitempty"`
	Spoofmac            string                `xml:"spoofmac,omitempty"            json:"spoofmac,omitempty"            yaml:"spoofmac,omitempty"`
	InternalDynamic     int                   `xml:"internal_dynamic,omitempty"    json:"internalDynamic,omitempty"     yaml:"internalDynamic,omitempty"`
	Type                string                `xml:"type,omitempty"                json:"type,omitempty"                yaml:"type,omitempty"`
	Virtual             int                   `xml:"virtual,omitempty"             json:"virtual,omitempty"             yaml:"virtual,omitempty"`
	Lock                int                   `xml:"lock,omitempty"                json:"lock,omitempty"                yaml:"lock,omitempty"`
	MTU                 string                `xml:"mtu,omitempty"                 json:"mtu,omitempty"                 yaml:"mtu,omitempty"`
	IPAddr              string                `xml:"ipaddr,omitempty"              json:"ipaddr,omitempty"              yaml:"ipaddr,omitempty"`
	IPAddrv6            string                `xml:"ipaddrv6,omitempty"            json:"ipaddrv6,omitempty"            yaml:"ipaddrv6,omitempty"`
	Subnet              string                `xml:"subnet,omitempty"              json:"subnet,omitempty"              yaml:"subnet,omitempty"`
	Subnetv6            string                `xml:"subnetv6,omitempty"            json:"subnetv6,omitempty"            yaml:"subnetv6,omitempty"`
	Gateway             string                `xml:"gateway,omitempty"             json:"gateway,omitempty"             yaml:"gateway,omitempty"`
	Gatewayv6           string                `xml:"gatewayv6,omitempty"           json:"gatewayv6,omitempty"           yaml:"gatewayv6,omitempty"`
	BlockPriv           string                `xml:"blockpriv,omitempty"           json:"blockpriv,omitempty"           yaml:"blockpriv,omitempty"`
	BlockBogons         string                `xml:"blockbogons,omitempty"         json:"blockbogons,omitempty"         yaml:"blockbogons,omitempty"`
	DHCPHostname        string                `xml:"dhcphostname,omitempty"        json:"dhcphostname,omitempty"        yaml:"dhcphostname,omitempty"`
	Media               string                `xml:"media,omitempty"               json:"media,omitempty"               yaml:"media,omitempty"`
	MediaOpt            string                `xml:"mediaopt,omitempty"            json:"mediaopt,omitempty"            yaml:"mediaopt,omitempty"`
	DHCP6IaPdLen        int                   `xml:"dhcp6-ia-pd-len,omitempty"     json:"dhcp6IaPdLen,omitempty"        yaml:"dhcp6IaPdLen,omitempty"`
	Track6Interface     string                `xml:"track6-interface,omitempty"    json:"track6Interface,omitempty"     yaml:"track6Interface,omitempty"`
	Track6PrefixID      string                `xml:"track6-prefix-id,omitempty"    json:"track6PrefixId,omitempty"      yaml:"track6PrefixId,omitempty"`
	AliasAddress        string                `xml:"alias-address,omitempty"       json:"aliasAddress,omitempty"        yaml:"aliasAddress,omitempty"`
	AliasSubnet         string                `xml:"alias-subnet,omitempty"        json:"aliasSubnet,omitempty"         yaml:"aliasSubnet,omitempty"`
	DHCPRejectFrom      string                `xml:"dhcprejectfrom,omitempty"      json:"dhcprejectfrom,omitempty"      yaml:"dhcprejectfrom,omitempty"`
	DDNSDomainAlgorithm string                `xml:"ddnsdomainalgorithm,omitempty" json:"ddnsdomainalgorithm,omitempty" yaml:"ddnsdomainalgorithm,omitempty"`
	NumberOptions       []opnsense.DhcpOption `xml:"numberoptions,omitempty"       json:"numberoptions,omitempty"       yaml:"numberoptions,omitempty"`
	Range               opnsense.DhcpRange    `xml:"range,omitempty"               json:"range"                         yaml:"range,omitempty"`
	Winsserver          string                `xml:"winsserver,omitempty"          json:"winsserver,omitempty"          yaml:"winsserver,omitempty"`
	Dnsserver           string                `xml:"dnsserver,omitempty"           json:"dnsserver,omitempty"           yaml:"dnsserver,omitempty"`
	Ntpserver           string                `xml:"ntpserver,omitempty"           json:"ntpserver,omitempty"           yaml:"ntpserver,omitempty"`

	// Advanced DHCP fields for interfaces
	AdvDHCPRequestOptions                    string `xml:"adv_dhcp_request_options,omitempty"                      json:"advDhcpRequestOptions,omitempty"                    yaml:"advDhcpRequestOptions,omitempty"`
	AdvDHCPRequiredOptions                   string `xml:"adv_dhcp_required_options,omitempty"                     json:"advDhcpRequiredOptions,omitempty"                   yaml:"advDhcpRequiredOptions,omitempty"`
	AdvDHCP6InterfaceStatementRequestOptions string `xml:"adv_dhcp6_interface_statement_request_options,omitempty" json:"advDhcp6InterfaceStatementRequestOptions,omitempty" yaml:"advDhcp6InterfaceStatementRequestOptions,omitempty"`
	AdvDHCP6ConfigFileOverride               string `xml:"adv_dhcp6_config_file_override,omitempty"                json:"advDhcp6ConfigFileOverride,omitempty"               yaml:"advDhcp6ConfigFileOverride,omitempty"`
	AdvDHCP6IDAssocStatementPrefixPLTime     string `xml:"adv_dhcp6_id_assoc_statement_prefix_pltime,omitempty"    json:"advDhcp6IdAssocStatementPrefixPltime,omitempty"     yaml:"advDhcp6IdAssocStatementPrefixPltime,omitempty"`
}

// interfaceAlias is a type alias used to break the recursion in Interface.MarshalXML.
// encoding/xml would infinitely recurse if MarshalXML called EncodeElement on the same type.
type interfaceAlias Interface

// MarshalXML implements custom XML marshaling for Interface, ensuring that the
// Enable BoolFlag field is addressable so (*BoolFlag).MarshalXML is invoked.
// Without this, direct xml.Marshal calls on Interface values would fall back to
// default bool serialization instead of producing pfSense-compatible <enable/> elements.
// Uses a value receiver so both value and pointer marshaling work correctly.
func (iface Interface) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	return e.EncodeElement((*interfaceAlias)(&iface), start)
}

// Interfaces contains the network interface configurations for a pfSense device.
// Uses a map-based representation where keys are interface identifiers (wan, lan, opt0, etc.).
type Interfaces struct {
	Items map[string]Interface `xml:",any" json:"interfaces,omitempty" yaml:"interfaces,omitempty"`
}

// UnmarshalXML implements custom XML unmarshaling for the Interfaces map.
func (i *Interfaces) UnmarshalXML(decoder *xml.Decoder, start xml.StartElement) error {
	i.Items = make(map[string]Interface)

	for {
		tok, err := decoder.Token()
		if err != nil {
			return fmt.Errorf("failed to read Interfaces token: %w", err)
		}

		switch se := tok.(type) {
		case xml.StartElement:
			var iface Interface
			if err := decoder.DecodeElement(&iface, &se); err != nil {
				return fmt.Errorf("failed to decode interface %s: %w", se.Name.Local, err)
			}

			i.Items[se.Name.Local] = iface
		case xml.EndElement:
			if se.Name == start.Name {
				return nil
			}
		}
	}
}

// MarshalXML implements custom XML marshaling for the Interfaces map.
func (i *Interfaces) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	if err := e.EncodeToken(start); err != nil {
		return err
	}

	for _, key := range slices.Sorted(maps.Keys(i.Items)) {
		iface := i.Items[key]
		ifaceStart := xml.StartElement{Name: xml.Name{Local: key}}
		if err := e.EncodeElement(&iface, ifaceStart); err != nil {
			return err
		}
	}

	return e.EncodeToken(xml.EndElement{Name: start.Name})
}

// Get returns an interface configuration by its key name (e.g., "wan", "lan", "opt0").
// Returns the interface configuration and a boolean indicating if it was found.
func (i *Interfaces) Get(key string) (Interface, bool) {
	if i.Items == nil {
		return Interface{}, false
	}

	iface, ok := i.Items[key]

	return iface, ok
}

// Names returns a sorted list of all interface names.
func (i *Interfaces) Names() []string {
	if i.Items == nil {
		return []string{}
	}

	return slices.Sorted(maps.Keys(i.Items))
}

// Wan returns the WAN interface if it exists, otherwise returns a zero-value Interface and false.
func (i *Interfaces) Wan() (Interface, bool) {
	return i.Get("wan")
}

// Lan returns the LAN interface if it exists, otherwise returns a zero-value Interface and false.
func (i *Interfaces) Lan() (Interface, bool) {
	return i.Get("lan")
}
