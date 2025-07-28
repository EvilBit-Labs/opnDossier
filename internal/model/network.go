// Package model defines the data structures for OPNsense configurations.
package model

import (
	"encoding/xml"
)

// NetworkConfig groups network-related configuration.
type NetworkConfig struct {
	Interfaces Interfaces `json:"interfaces,omitempty" yaml:"interfaces,omitempty" validate:"required"`
	VLANs      []VLAN     `json:"vlans,omitempty" yaml:"vlans,omitempty"`
	Gateways   []Gateway  `json:"gateways,omitempty" yaml:"gateways,omitempty"`
}

// VLAN represents a Virtual Local Area Network configuration.
type VLAN struct {
	Name              string `xml:"vlanif,omitempty"`
	Tag               string `xml:"tag,omitempty"`
	PhysicalInterface string `xml:"if,omitempty"`
	Enable            string `xml:"enable,omitempty"`
	Description       string `xml:"descr,omitempty"`
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

// Interface represents a network interface.
type Interface struct {
	Enable          string `xml:"enable,omitempty"`
	If              string `xml:"if,omitempty"`
	Descr           string `xml:"descr,omitempty"`
	Spoofmac        string `xml:"spoofmac,omitempty"`
	InternalDynamic string `xml:"internal_dynamic,omitempty"`
	Type            string `xml:"type,omitempty"`
	Virtual         string `xml:"virtual,omitempty"`
	Lock            string `xml:"lock,omitempty"`
	MTU             string `xml:"mtu,omitempty"`
	IPAddr          string `xml:"ipaddr,omitempty"`
	IPAddrv6        string `xml:"ipaddrv6,omitempty"`
	Subnet          string `xml:"subnet,omitempty"`
	Subnetv6        string `xml:"subnetv6,omitempty"`
	Gateway         string `xml:"gateway,omitempty"`
	Gatewayv6       string `xml:"gatewayv6,omitempty"`
	BlockPriv       string `xml:"blockpriv,omitempty"`
	BlockBogons     string `xml:"blockbogons,omitempty"`
	DHCPHostname    string `xml:"dhcphostname,omitempty"`
	Media           string `xml:"media,omitempty"`
	MediaOpt        string `xml:"mediaopt,omitempty"`
	DHCP6IaPdLen    string `xml:"dhcp6-ia-pd-len,omitempty"`
	Track6Interface string `xml:"track6-interface,omitempty"`
	Track6PrefixID  string `xml:"track6-prefix-id,omitempty"`
}

// Vlans represents VLAN configuration.
type Vlans struct {
	XMLName xml.Name `xml:"vlans"`
	Vlan    []Vlan   `xml:"vlan,omitempty"`
}

// Vlan struct for individual VLAN configuration.
type Vlan struct {
	XMLName xml.Name `xml:"vlan"`
	If      string   `xml:"if,omitempty"`
	Tag     string   `xml:"tag,omitempty"`
	Descr   string   `xml:"descr,omitempty"`
	Vlanif  string   `xml:"vlanif,omitempty"`
	Created string   `xml:"created,omitempty"`
	Updated string   `xml:"updated,omitempty"`
}

// Bridges represents bridge interface configuration.
type Bridges struct {
	XMLName xml.Name `xml:"bridges"`
	Bridge  []Bridge `xml:"bridge,omitempty"`
}

// Bridge struct for individual bridge configuration.
type Bridge struct {
	XMLName  xml.Name `xml:"bridge"`
	Members  string   `xml:"members,omitempty"`
	Descr    string   `xml:"descr,omitempty"`
	Bridgeif string   `xml:"bridgeif,omitempty"`
	STP      BoolFlag `xml:"stp,omitempty"`
	Created  string   `xml:"created,omitempty"`
	Updated  string   `xml:"updated,omitempty"`
}

// Gateways represents gateway configuration.
type Gateways struct {
	XMLName xml.Name       `xml:"gateways"`
	Gateway []Gateway      `xml:"gateway_item,omitempty"`
	Groups  []GatewayGroup `xml:"gateway_group,omitempty"`
}

// Gateway struct for individual gateway configuration.
type Gateway struct {
	XMLName    xml.Name `xml:"gateway_item"`
	Interface  string   `xml:"interface,omitempty"`
	Gateway    string   `xml:"gateway,omitempty"`
	Name       string   `xml:"name,omitempty"`
	Weight     string   `xml:"weight,omitempty"`
	IPProtocol string   `xml:"ipprotocol,omitempty"`
	Interval   string   `xml:"interval,omitempty"`
	Descr      string   `xml:"descr,omitempty"`
	Monitor    string   `xml:"monitor,omitempty"`
	Disabled   BoolFlag `xml:"disabled,omitempty"`
	Created    string   `xml:"created,omitempty"`
	Updated    string   `xml:"updated,omitempty"`
}

// GatewayGroup represents a group of gateways for OPNsense configuration.
type GatewayGroup struct {
	XMLName xml.Name `xml:"gateway_group"`
	Name    string   `xml:"name,omitempty"`
	Item    []string `xml:"item,omitempty"`
	Trigger string   `xml:"trigger,omitempty"`
	Descr   string   `xml:"descr,omitempty"`
}

// StaticRoutes represents static routing configuration.
type StaticRoutes struct {
	XMLName xml.Name      `xml:"staticroutes"`
	Route   []StaticRoute `xml:"route,omitempty"`
}

// StaticRoute struct for individual static route configuration.
type StaticRoute struct {
	XMLName  xml.Name `xml:"route"`
	Network  string   `xml:"network,omitempty"`
	Gateway  string   `xml:"gateway,omitempty"`
	Descr    string   `xml:"descr,omitempty"`
	Disabled BoolFlag `xml:"disabled,omitempty"`
	Created  string   `xml:"created,omitempty"`
	Updated  string   `xml:"updated,omitempty"`
}

// Constructor functions for network models

// NewNetworkConfig creates a new NetworkConfig with properly initialized slices.
func NewNetworkConfig() NetworkConfig {
	return NetworkConfig{
		VLANs:    make([]VLAN, 0),
		Gateways: make([]Gateway, 0),
		Interfaces: Interfaces{
			Items: make(map[string]Interface),
		},
	}
}

// NewVlans creates a new Vlans configuration with properly initialized slices.
func NewVlans() *Vlans {
	return &Vlans{
		Vlan: make([]Vlan, 0),
	}
}

// NewBridges creates a new Bridges configuration with properly initialized slices.
func NewBridges() *Bridges {
	return &Bridges{
		Bridge: make([]Bridge, 0),
	}
}

// NewGateways creates a new Gateways configuration with properly initialized slices.
func NewGateways() *Gateways {
	return &Gateways{
		Gateway: make([]Gateway, 0),
		Groups:  make([]GatewayGroup, 0),
	}
}

// NewGatewayGroup creates a new GatewayGroup with properly initialized slices.
func NewGatewayGroup() GatewayGroup {
	return GatewayGroup{
		Item: make([]string, 0),
	}
}

// NewStaticRoutes creates a new StaticRoutes configuration with properly initialized slices.
func NewStaticRoutes() *StaticRoutes {
	return &StaticRoutes{
		Route: make([]StaticRoute, 0),
	}
}
