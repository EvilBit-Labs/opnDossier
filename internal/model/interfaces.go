// Package model defines the data structures for OPNsense configurations.
package model

import (
	"encoding/xml"
)

// InterfaceGroups represents interface groups configuration.
type InterfaceGroups struct {
	XMLName xml.Name `xml:"ifgroups"               json:"-"                 yaml:"-"`
	Version string   `xml:"version,attr,omitempty" json:"version,omitempty" yaml:"version,omitempty"`
}

// GIFInterfaces represents GIF interface configuration.
type GIFInterfaces struct {
	XMLName xml.Name `xml:"gifs"                   json:"-"                 yaml:"-"`
	Version string   `xml:"version,attr,omitempty" json:"version,omitempty" yaml:"version,omitempty"`
	Gif     string   `xml:"gif,omitempty"          json:"gif,omitempty"     yaml:"gif,omitempty"`
}

// GREInterfaces represents GRE interface configuration.
type GREInterfaces struct {
	XMLName xml.Name `xml:"gres"                   json:"-"                 yaml:"-"`
	Version string   `xml:"version,attr,omitempty" json:"version,omitempty" yaml:"version,omitempty"`
	Gre     string   `xml:"gre,omitempty"          json:"gre,omitempty"     yaml:"gre,omitempty"`
}

// LAGGInterfaces represents LAGG interface configuration.
type LAGGInterfaces struct {
	XMLName xml.Name `xml:"laggs"                  json:"-"                 yaml:"-"`
	Version string   `xml:"version,attr,omitempty" json:"version,omitempty" yaml:"version,omitempty"`
	Lagg    string   `xml:"lagg,omitempty"         json:"lagg,omitempty"    yaml:"lagg,omitempty"`
}

// VirtualIP represents virtual IP configuration.
type VirtualIP struct {
	XMLName xml.Name `xml:"virtualip"              json:"-"                 yaml:"-"`
	Version string   `xml:"version,attr,omitempty" json:"version,omitempty" yaml:"version,omitempty"`
	Vip     string   `xml:"vip,omitempty"          json:"vip,omitempty"     yaml:"vip,omitempty"`
}

// PPPInterfaces represents PPP interface configuration.
type PPPInterfaces struct {
	XMLName xml.Name `xml:"ppps"          json:"-"             yaml:"-"`
	Ppp     string   `xml:"ppp,omitempty" json:"ppp,omitempty" yaml:"ppp,omitempty"`
}

// Wireless represents wireless interface configuration.
type Wireless struct {
	XMLName xml.Name `xml:"wireless"        json:"-"               yaml:"-"`
	Clone   string   `xml:"clone,omitempty" json:"clone,omitempty" yaml:"clone,omitempty"`
}

// Interfaces contains the network interface configurations.
// Uses a map-based representation to store all interface blocks generically,
// supporting wan, lan, opt0, opt1, etc., and any custom interface elements.
type Interfaces struct {
	Items map[string]Interface `xml:",any" json:"interfaces,omitempty" yaml:"interfaces,omitempty"`
}

// UnmarshalXML implements custom XML unmarshaling for the Interfaces map.
func (i *Interfaces) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	i.Items = make(map[string]Interface)

	for {
		tok, err := d.Token()
		if err != nil {
			return err
		}

		switch se := tok.(type) {
		case xml.StartElement:
			// Each interface element (wan, lan, opt0, etc.) becomes a map entry
			var iface Interface
			if err := d.DecodeElement(&iface, &se); err != nil {
				return err
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

	// Encode each interface as a separate element using the key as the element name
	for key, iface := range i.Items {
		ifaceStart := xml.StartElement{Name: xml.Name{Local: key}}
		if err := e.EncodeElement(iface, ifaceStart); err != nil {
			return err
		}
	}

	return e.EncodeToken(xml.EndElement{Name: start.Name})
}

// Get returns an interface by its key name (e.g., "wan", "lan", "opt0").
// Returns the interface and a boolean indicating if it was found.
//
// Example:
//
//	if wan, ok := interfaces.Get("wan"); ok {
//		fmt.Printf("WAN IP: %s\n", wan.IPAddr)
//	}
func (i *Interfaces) Get(key string) (Interface, bool) {
	if i.Items == nil {
		return Interface{}, false
	}

	iface, ok := i.Items[key]

	return iface, ok
}

// Names returns a slice of all interface key names in the configuration.
// This includes standard interfaces like "wan", "lan" and optional ones like "opt0", "opt1", etc.
//
// Example:
//
//	names := interfaces.Names()
//	fmt.Printf("Available interfaces: %s\n", strings.Join(names, ", "))
func (i *Interfaces) Names() []string {
	if i.Items == nil {
		return []string{}
	}

	names := make([]string, 0, len(i.Items))
	for key := range i.Items {
		names = append(names, key)
	}

	return names
}

// Wan returns the WAN interface if it exists, otherwise returns a zero-value Interface and false.
// This is a convenience method for backward compatibility.
func (i *Interfaces) Wan() (Interface, bool) {
	return i.Get("wan")
}

// Lan returns the LAN interface if it exists, otherwise returns a zero-value Interface and false.
// This is a convenience method for backward compatibility.
func (i *Interfaces) Lan() (Interface, bool) {
	return i.Get("lan")
}

// Interface represents a network interface configuration.
type Interface struct {
	Enable              string       `xml:"enable,omitempty"              json:"enable,omitempty"              yaml:"enable,omitempty"`
	If                  string       `xml:"if,omitempty"                  json:"if,omitempty"                  yaml:"if,omitempty"`
	Descr               string       `xml:"descr,omitempty"               json:"descr,omitempty"               yaml:"descr,omitempty"`
	Spoofmac            string       `xml:"spoofmac,omitempty"            json:"spoofmac,omitempty"            yaml:"spoofmac,omitempty"`
	InternalDynamic     int          `xml:"internal_dynamic,omitempty"    json:"internalDynamic,omitempty"     yaml:"internalDynamic,omitempty"`
	Type                string       `xml:"type,omitempty"                json:"type,omitempty"                yaml:"type,omitempty"`
	Virtual             int          `xml:"virtual,omitempty"             json:"virtual,omitempty"             yaml:"virtual,omitempty"`
	Lock                int          `xml:"lock,omitempty"                json:"lock,omitempty"                yaml:"lock,omitempty"`
	MTU                 string       `xml:"mtu,omitempty"                 json:"mtu,omitempty"                 yaml:"mtu,omitempty"`
	IPAddr              string       `xml:"ipaddr,omitempty"              json:"ipaddr,omitempty"              yaml:"ipaddr,omitempty"`
	IPAddrv6            string       `xml:"ipaddrv6,omitempty"            json:"ipaddrv6,omitempty"            yaml:"ipaddrv6,omitempty"`
	Subnet              string       `xml:"subnet,omitempty"              json:"subnet,omitempty"              yaml:"subnet,omitempty"`
	Subnetv6            string       `xml:"subnetv6,omitempty"            json:"subnetv6,omitempty"            yaml:"subnetv6,omitempty"`
	Gateway             string       `xml:"gateway,omitempty"             json:"gateway,omitempty"             yaml:"gateway,omitempty"`
	Gatewayv6           string       `xml:"gatewayv6,omitempty"           json:"gatewayv6,omitempty"           yaml:"gatewayv6,omitempty"`
	BlockPriv           string       `xml:"blockpriv,omitempty"           json:"blockpriv,omitempty"           yaml:"blockpriv,omitempty"`
	BlockBogons         string       `xml:"blockbogons,omitempty"         json:"blockbogons,omitempty"         yaml:"blockbogons,omitempty"`
	DHCPHostname        string       `xml:"dhcphostname,omitempty"        json:"dhcphostname,omitempty"        yaml:"dhcphostname,omitempty"`
	Media               string       `xml:"media,omitempty"               json:"media,omitempty"               yaml:"media,omitempty"`
	MediaOpt            string       `xml:"mediaopt,omitempty"            json:"mediaopt,omitempty"            yaml:"mediaopt,omitempty"`
	DHCP6IaPdLen        int          `xml:"dhcp6-ia-pd-len,omitempty"     json:"dhcp6IaPdLen,omitempty"        yaml:"dhcp6IaPdLen,omitempty"`
	Track6Interface     string       `xml:"track6-interface,omitempty"    json:"track6Interface,omitempty"     yaml:"track6Interface,omitempty"`
	Track6PrefixID      string       `xml:"track6-prefix-id,omitempty"    json:"track6PrefixId,omitempty"      yaml:"track6PrefixId,omitempty"`
	AliasAddress        string       `xml:"alias-address,omitempty"       json:"aliasAddress,omitempty"        yaml:"aliasAddress,omitempty"`
	AliasSubnet         string       `xml:"alias-subnet,omitempty"        json:"aliasSubnet,omitempty"         yaml:"aliasSubnet,omitempty"`
	DHCPRejectFrom      string       `xml:"dhcprejectfrom,omitempty"      json:"dhcprejectfrom,omitempty"      yaml:"dhcprejectfrom,omitempty"`
	DDNSDomainAlgorithm string       `xml:"ddnsdomainalgorithm,omitempty" json:"ddnsdomainalgorithm,omitempty" yaml:"ddnsdomainalgorithm,omitempty"`
	NumberOptions       []DhcpOption `xml:"numberoptions,omitempty"       json:"numberoptions,omitempty"       yaml:"numberoptions,omitempty"`
	Range               DhcpRange    `xml:"range,omitempty"               json:"range"                         yaml:"range,omitempty"`
	Winsserver          string       `xml:"winsserver,omitempty"          json:"winsserver,omitempty"          yaml:"winsserver,omitempty"`
	Dnsserver           string       `xml:"dnsserver,omitempty"           json:"dnsserver,omitempty"           yaml:"dnsserver,omitempty"`
	Ntpserver           string       `xml:"ntpserver,omitempty"           json:"ntpserver,omitempty"           yaml:"ntpserver,omitempty"`

	// Advanced DHCP fields for interfaces
	AdvDHCPRequestOptions                    string `xml:"adv_dhcp_request_options,omitempty"                      json:"advDhcpRequestOptions,omitempty"                    yaml:"advDhcpRequestOptions,omitempty"`
	AdvDHCPRequiredOptions                   string `xml:"adv_dhcp_required_options,omitempty"                     json:"advDhcpRequiredOptions,omitempty"                   yaml:"advDhcpRequiredOptions,omitempty"`
	AdvDHCP6InterfaceStatementRequestOptions string `xml:"adv_dhcp6_interface_statement_request_options,omitempty" json:"advDhcp6InterfaceStatementRequestOptions,omitempty" yaml:"advDhcp6InterfaceStatementRequestOptions,omitempty"`
	AdvDHCP6ConfigFileOverride               string `xml:"adv_dhcp6_config_file_override,omitempty"                json:"advDhcp6ConfigFileOverride,omitempty"               yaml:"advDhcp6ConfigFileOverride,omitempty"`
	AdvDHCP6IDAssocStatementPrefixPLTime     string `xml:"adv_dhcp6_id_assoc_statement_prefix_pltime,omitempty"    json:"advDhcp6IdAssocStatementPrefixPltime,omitempty"     yaml:"advDhcp6IdAssocStatementPrefixPltime,omitempty"`
}

// VLANConfig represents a Virtual Local Area Network configuration for network config.
type VLANConfig struct {
	Name              string `xml:"vlanif,omitempty"`
	Tag               string `xml:"tag,omitempty"`
	PhysicalInterface string `xml:"if,omitempty"`
	Enable            string `xml:"enable,omitempty"`
	Description       string `xml:"descr,omitempty"`
}

// VLANs represents a collection of VLAN configurations in the OPNsense document.
type VLANs struct {
	XMLName xml.Name `xml:"vlans"`
	VLAN    []VLAN   `xml:"vlan,omitempty"`
}

// VLAN represents a VLAN configuration in the OPNsense document.
type VLAN struct {
	XMLName xml.Name `xml:"vlan"`
	If      string   `xml:"if,omitempty"`
	Tag     string   `xml:"tag,omitempty"`
	Descr   string   `xml:"descr,omitempty"`
	Vlanif  string   `xml:"vlanif,omitempty"`
	Created string   `xml:"created,omitempty"`
	Updated string   `xml:"updated,omitempty"`
}

// Bridge represents a network bridge configuration.
type Bridge struct {
	XMLName  xml.Name `xml:"bridge"`
	Members  string   `xml:"members,omitempty"`
	Descr    string   `xml:"descr,omitempty"`
	Bridgeif string   `xml:"bridgeif,omitempty"`
	STP      BoolFlag `xml:"stp,omitempty"`
	Created  string   `xml:"created,omitempty"`
	Updated  string   `xml:"updated,omitempty"`
}

// Bridges represents a collection of bridge configurations.
type Bridges struct {
	XMLName xml.Name `xml:"bridges"`
	Bridge  []Bridge `xml:"bridge,omitempty"`
}

// BridgesConfig represents the root-level bridges configuration.
type BridgesConfig struct {
	XMLName xml.Name `xml:"bridges"`
	Bridged string   `xml:"bridged,omitempty"`
}
