package opnsense

import (
	"encoding/xml"
)

// NetworkConfig groups network-related configuration.
type NetworkConfig struct {
	Interfaces Interfaces   `json:"interfaces"         yaml:"interfaces,omitempty" validate:"required"`
	VLANs      []VLANConfig `json:"vlans,omitempty"    yaml:"vlans,omitempty"`
	Gateways   []Gateway    `json:"gateways,omitempty" yaml:"gateways,omitempty"`
}

// DhcpOption represents a numbered DHCP option with its value, used in interface-level DHCP configuration.
type DhcpOption struct {
	Number string `xml:"number,omitempty" json:"number,omitempty" yaml:"number,omitempty"`
	Value  string `xml:"value,omitempty"  json:"value,omitempty"  yaml:"value,omitempty"`
}

// DhcpRange represents a DHCP address range on an interface, defined by From and To IP addresses.
type DhcpRange struct {
	From string `xml:"from,omitempty" json:"from,omitempty" yaml:"from,omitempty"`
	To   string `xml:"to,omitempty"   json:"to,omitempty"   yaml:"to,omitempty"`
}

// Gateways represents the <gateways> container element holding gateway items and gateway groups.
type Gateways struct {
	XMLName xml.Name       `xml:"gateways"`
	Gateway []Gateway      `xml:"gateway_item,omitempty"`
	Groups  []GatewayGroup `xml:"gateway_group,omitempty"`
}

// Gateway represents an individual gateway configuration entry, including the bound interface,
// gateway address, IP protocol version, monitoring settings, and default gateway designation.
//
// MonitorDisable is a pointer because the two OPNsense stores read an absent element differently:
// the gateway model defaults it to 1, and the legacy element to 0. [Gateway.MonitorDisableValue]
// returns its text.
type Gateway struct {
	XMLName        xml.Name `xml:"gateway_item"`
	Interface      string   `xml:"interface,omitempty"`
	Gateway        string   `xml:"gateway,omitempty"`
	Name           string   `xml:"name,omitempty"`
	Weight         string   `xml:"weight,omitempty"`
	IPProtocol     string   `xml:"ipprotocol,omitempty"`
	Interval       string   `xml:"interval,omitempty"`
	Descr          string   `xml:"descr,omitempty"`
	Monitor        string   `xml:"monitor,omitempty"`
	Disabled       BoolFlag `xml:"disabled,omitempty"`
	Created        string   `xml:"created,omitempty"`
	Updated        string   `xml:"updated,omitempty"`
	DefaultGW      string   `xml:"defaultgw,omitempty"`
	MonitorDisable *string  `xml:"monitor_disable,omitempty"`
	FarGW          string   `xml:"fargw,omitempty"`
}

// MonitorDisableValue returns the text of <monitor_disable>, which is empty for
// an absent element and an empty one alike.
func (g Gateway) MonitorDisableValue() string {
	if g.MonitorDisable == nil {
		return ""
	}

	return *g.MonitorDisable
}

// IsPlaceholder reports whether g is an empty <gateway_item/> marker rather than
// a configured gateway. OPNsense skips that element in both stores: the model
// loader drops an item with no child element, and gatewayIterator drops a
// legacy one from 24.1.3. It does not count when choosing the store either, so
// a model holding nothing else falls back to <gateways>.
//
// The check is deliberately conservative: an entry is dropped only when every
// field is zero. A gateway carrying any data at all -- even just a description
// -- is retained, because under-reporting configured resources is the more
// dangerous direction for an auditing tool. An item holding only elements this
// type does not bind is dropped, although OPNsense loads it; no release writes
// one.
//
// Fields are compared by name rather than against the zero value: encoding/xml
// populates XMLName when it decodes a Gateway, so a <gateway_item/> under
// <gateways> never equals Gateway{}. One in the model does, because the XMLName
// of an embedded struct stays unset, and comparing named fields reads both alike.
func (g Gateway) IsPlaceholder() bool {
	return g.Interface == "" &&
		g.Gateway == "" &&
		g.Name == "" &&
		g.Weight == "" &&
		g.IPProtocol == "" &&
		g.Interval == "" &&
		g.Descr == "" &&
		g.Monitor == "" &&
		!bool(g.Disabled) &&
		g.Created == "" &&
		g.Updated == "" &&
		g.DefaultGW == "" &&
		g.MonitorDisable == nil &&
		g.FarGW == ""
}

// GatewayModelItem is a <gateway_item> of the gateway model at <OPNsense><Gateways>. The model
// keeps its items by the uuid attribute, which neither <gateways> nor pfSense reads, so the
// attribute is bound here and not on the [Gateway] those two share.
//
// A uuid does not make an item configured: OPNsense skips an item with no child element whatever
// its attributes, and the promoted [Gateway.IsPlaceholder] does not look at it.
//
// UUID is a pointer to keep an absent attribute apart from an empty one (GOTCHAS 3.2). OPNsense
// gives an item with no attribute a fresh uuid on every release, while through 25.1.12 it uses an
// empty one as the key.
type GatewayModelItem struct {
	Gateway

	UUID *string `xml:"uuid,attr,omitempty"`
}

// GatewayGroup represents a group of gateways used for multi-WAN failover or load balancing.
type GatewayGroup struct {
	XMLName xml.Name `xml:"gateway_group"`
	Name    string   `xml:"name,omitempty"`
	Item    []string `xml:"item,omitempty"`
	Trigger string   `xml:"trigger,omitempty"`
	Descr   string   `xml:"descr,omitempty"`
}

// StaticRoutes represents the <staticroutes> container element holding all static route entries.
type StaticRoutes struct {
	XMLName xml.Name      `xml:"staticroutes"`
	Route   []StaticRoute `xml:"route,omitempty"`
}

// StaticRoute represents a single static route entry mapping a destination network to a gateway.
type StaticRoute struct {
	XMLName  xml.Name `xml:"route"`
	Network  string   `xml:"network,omitempty"`
	Gateway  string   `xml:"gateway,omitempty"`
	Descr    string   `xml:"descr,omitempty"`
	Disabled BoolFlag `xml:"disabled,omitempty"`
	Created  string   `xml:"created,omitempty"`
	Updated  string   `xml:"updated,omitempty"`
}

// IsPlaceholder reports whether r is an empty <route/> marker rather than a
// configured static route. OPNsense writes that self-closing element inside
// <staticroutes> when nothing is configured, and it unmarshals into an entry
// whose configuration fields are all zero.
//
// The check is deliberately conservative: an entry is dropped only when every
// field is zero. A route carrying any data at all -- even just a description --
// is retained, because under-reporting configured resources is the more
// dangerous direction for an auditing tool.
//
// Fields are compared by name rather than against the zero value: encoding/xml
// populates XMLName on unmarshal, so a decoded <route/> never equals
// StaticRoute{}.
func (r StaticRoute) IsPlaceholder() bool {
	return r.Network == "" &&
		r.Gateway == "" &&
		r.Descr == "" &&
		!bool(r.Disabled) &&
		r.Created == "" &&
		r.Updated == ""
}

// Constructor functions for network models

// NewNetworkConfig returns a NetworkConfig with initialized empty slices for VLANs and Gateways, and an initialized map for Interfaces.
func NewNetworkConfig() NetworkConfig {
	return NetworkConfig{
		VLANs:    make([]VLANConfig, 0),
		Gateways: make([]Gateway, 0),
		Interfaces: Interfaces{
			Items: make(map[string]Interface),
		},
	}
}

// NewVLANs returns a pointer to a VLANs struct with an empty VLAN slice initialized.
func NewVLANs() *VLANs {
	return &VLANs{
		VLAN: make([]VLAN, 0),
	}
}

// NewBridges returns a pointer to a Bridges struct with an initialized empty slice of Bridge.
func NewBridges() *Bridges {
	return &Bridges{
		Bridge: make([]Bridge, 0),
	}
}

// NewGateways returns a pointer to a Gateways struct with empty slices for gateways and gateway groups.
func NewGateways() *Gateways {
	return &Gateways{
		Gateway: make([]Gateway, 0),
		Groups:  make([]GatewayGroup, 0),
	}
}

// NewGatewayGroup returns a GatewayGroup with an initialized empty slice of items.
func NewGatewayGroup() GatewayGroup {
	return GatewayGroup{
		Item: make([]string, 0),
	}
}

// NewStaticRoutes returns a pointer to a StaticRoutes struct with an initialized empty slice of StaticRoute.
func NewStaticRoutes() *StaticRoutes {
	return &StaticRoutes{
		Route: make([]StaticRoute, 0),
	}
}
