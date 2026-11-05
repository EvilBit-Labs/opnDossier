package opnsense

import (
	"encoding/xml"
	"slices"
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

// NewGateways returns a pointer to a Gateways struct with empty slices for gateways and gateway groups.
func NewGateways() *Gateways {
	return &Gateways{
		Gateway: make([]Gateway, 0),
		Groups:  make([]GatewayGroup, 0),
	}
}

// UnmarshalXML decodes <gateways> as encoding/xml would, namespaces aside (GOTCHAS 3.4), and
// sets [Gateway.HasChildElement] on each item. The container decodes the items, so that
// [Gateway], which [GatewayModelItem] embeds and pfSense shares, needs no UnmarshalXML of its own.
//
// No MarshalXML pairs it (GOTCHAS 3.3): HasChildElement is not encoded, so the default encoder
// writes the fields this reads. It does not keep an item whose only children are empty or
// unbound, such as <name/> or <priority>: those are omitted, and the item reads back as a
// placeholder.
func (g *Gateways) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	// Fields is Gateways without this method. Its name is exported because encoding/xml reads the
	// XMLName of an embedded struct through the embedded field, and panics on an unexported one.
	type Fields Gateways

	aux := struct {
		*Fields

		// Items takes every <gateway_item>, in place of the Fields.Gateway it shadows.
		Items []legacyGatewayItem `xml:"gateway_item"`
	}{Fields: (*Fields)(g)}

	if err := d.DecodeElement(&aux, &start); err != nil {
		return err
	}

	// encoding/xml does not set the XMLName of an embedded struct.
	g.XMLName = start.Name

	// Appended, as the default decoder appends, so a second <gateways> adds to the first.
	g.Gateway = slices.Grow(g.Gateway, len(aux.Items))
	for _, item := range aux.Items {
		g.Gateway = append(g.Gateway, Gateway(item))
	}

	return nil
}

// legacyGatewayItem is a <gateway_item> under <gateways>, decoded by [Gateways.UnmarshalXML].
type legacyGatewayItem Gateway

// UnmarshalXML decodes the item into the [Gateway] it converts to and sets HasChildElement.
func (l *legacyGatewayItem) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	return decodeGatewayItem(d, start, (*Gateway)(l), &l.HasChildElement)
}

// decodeGatewayItem decodes the element start opens into v, as encoding/xml would, and sets
// *child when the element holds a child element. OPNsense decides whether a <gateway_item>
// exists with SimpleXML's count(), which counts child elements and nothing else, so text, CDATA,
// comments and processing instructions do not count, and neither do attributes. v must not
// implement [xml.Unmarshaler], or it would be called again here.
//
// Two differences arise only on namespaced input, which OPNsense never writes. count() skips a
// child with a namespace prefix, and this counts it, because the decoder has already resolved the
// prefix. The second decoder also resolves the item's namespaces again, so an item that declares
// a prefix bound to another of its prefixes gets a different XMLName.Space.
func decodeGatewayItem(d *xml.Decoder, start xml.StartElement, v any, child *bool) error {
	return xml.NewTokenDecoder(&childElementTokens{d: d, start: &start, child: child}).Decode(v)
}

// childElementTokens hands the tokens of one element to a second decoder, its start element
// first. Every start element after that one is inside the element, so the first is a child of
// it. The second decoder stops at the element's end element and reads nothing after it.
type childElementTokens struct {
	d     *xml.Decoder
	start *xml.StartElement
	child *bool
}

// Token implements [xml.TokenReader].
func (r *childElementTokens) Token() (xml.Token, error) {
	if start := r.start; start != nil {
		r.start = nil

		return *start, nil
	}

	tok, err := r.d.Token()
	if _, ok := tok.(xml.StartElement); ok {
		*r.child = true
	}

	return tok, err
}

// Gateway represents an individual gateway configuration entry, including the bound interface,
// gateway address, IP protocol version, monitoring settings, and default gateway designation.
//
// MonitorDisable is a pointer because the two OPNsense stores read an absent element differently:
// the gateway model defaults it to 1, and the legacy element to 0. [Gateway.MonitorDisableValue]
// returns its text.
//
// HasChildElement records that the decoded <gateway_item> held a child element, whatever the child
// held. [Gateways.UnmarshalXML] and [GatewayModelItem.UnmarshalXML] set it; nothing encodes it.
// Gateway has no UnmarshalXML or MarshalXML and must not get one: [GatewayModelItem] embeds it, so
// the method would be promoted and would decode or encode a model item without its uuid and its
// <disabled>.
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

	HasChildElement bool `xml:"-" json:"-" yaml:"-"`
}

// MonitorDisableValue returns the text of <monitor_disable>, which is empty for
// an absent element and an empty one alike.
func (g Gateway) MonitorDisableValue() string {
	if g.MonitorDisable == nil {
		return ""
	}

	return *g.MonitorDisable
}

// IsPlaceholder reports whether g is a <gateway_item> with no child element, a
// marker rather than a configured gateway. OPNsense skips such an item in both
// stores: the model loader in every release, and gatewayIterator under
// <gateways> from 24.1.3. Such an item does not count when choosing the store
// either, so a model holding nothing else falls back to <gateways>.
//
// A decoded item that held a child element is a gateway whatever the child
// held, as on the firewall: an item whose only child is an empty <name/>, a
// <disabled>0</disabled>, or an element this type does not bind, such as
// <priority>, is kept. Its fields cannot show that, because each of those
// decodes to the zero value, so HasChildElement records it.
//
// A value built in code has no such record and is a placeholder only when every
// field is zero. The check is deliberately conservative: a gateway carrying any
// data at all -- even just a description -- is retained, because
// under-reporting configured resources is the more dangerous direction for an
// auditing tool.
//
// Fields are compared by name rather than against the zero value: encoding/xml
// populates XMLName when it decodes a Gateway, so a <gateway_item/> under
// <gateways> never equals Gateway{}. One in the model does, because the XMLName
// of an embedded struct stays unset, and comparing named fields reads both alike.
func (g Gateway) IsPlaceholder() bool {
	return !g.HasChildElement &&
		g.Interface == "" &&
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
// its attributes, and [GatewayModelItem.IsPlaceholder] does not look at it.
//
// UUID is a pointer to keep an absent attribute apart from an empty one (GOTCHAS 3.2). OPNsense
// gives an item with no attribute a fresh uuid on every release, while through 25.1.12 it uses an
// empty one as the key.
//
// Disabled takes the <disabled> element in place of the [Gateway.Disabled] it shadows, which is
// neither decoded nor encoded for a model item, and which [GatewayModelItem.IsPlaceholder] and the
// converter do not read either; code that builds a model item sets Disabled. The model writes it
// as 0 or 1 and the firewall reads it with !empty(). It is kept as text, because a [BoolFlag]
// reads <disabled>0</disabled> the same as an absent element, and as a pointer, to keep an empty
// <disabled/> apart from an absent one, so that it is written back as it was read.
type GatewayModelItem struct {
	Gateway

	UUID     *string `xml:"uuid,attr,omitempty"`
	Disabled *string `xml:"disabled,omitempty"`
}

// UnmarshalXML decodes a model <gateway_item> as encoding/xml would and sets
// [Gateway.HasChildElement]. The model block is an anonymous struct, which cannot carry a method,
// so the item does.
//
// No MarshalXML pairs it (GOTCHAS 3.3): HasChildElement is not encoded, so the default encoder
// writes the fields this reads. It does not keep an item whose only children are empty or
// unbound, such as <name/> or <priority>: those are omitted, and the item reads back as a
// placeholder.
func (g *GatewayModelItem) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	// fields is GatewayModelItem without this method. Gateway has none to promote into it.
	type fields GatewayModelItem

	return decodeGatewayItem(d, start, (*fields)(g), &g.HasChildElement)
}

// IsPlaceholder reports whether g is a model <gateway_item> with no child element. The uuid
// does not count, nor does the shadowed [Gateway.Disabled]. A decoded item that held a child
// element is a gateway whatever the child held, and it decides which store the firewall reads.
// For a value built in code, a set Disabled counts, whatever its text.
func (g GatewayModelItem) IsPlaceholder() bool {
	gw := g.Gateway
	gw.Disabled = false

	return g.Disabled == nil && gw.IsPlaceholder()
}

// GatewayGroup represents a group of gateways used for multi-WAN failover or load balancing.
//
// Up to OPNsense 26.1, and on pfSense, Item repeats once per member gateway as
// name|tier (name|tier|vip on pfSense and on OPNsense up to 19.1). From 26.7
// the group is an MVC model: Item holds the tier 1 gateways as one
// comma-separated list and Item2 to Item5 hold tiers 2 to 5.
type GatewayGroup struct {
	XMLName xml.Name `xml:"gateway_group"`
	Name    string   `xml:"name,omitempty"`
	Item    []string `xml:"item,omitempty"`
	Item2   string   `xml:"item2,omitempty"`
	Item3   string   `xml:"item3,omitempty"`
	Item4   string   `xml:"item4,omitempty"`
	Item5   string   `xml:"item5,omitempty"`
	Trigger string   `xml:"trigger,omitempty"`
	Descr   string   `xml:"descr,omitempty"`
}

// StaticRoutes represents the <staticroutes> container element holding all static route entries.
type StaticRoutes struct {
	XMLName xml.Name      `xml:"staticroutes"`
	Version string        `xml:"version,attr,omitempty"`
	Route   []StaticRoute `xml:"route,omitempty"`
}

// StaticRoute represents a single static route entry mapping a destination network to a gateway.
type StaticRoute struct {
	XMLName  xml.Name `xml:"route"`
	Network  string   `xml:"network,omitempty"`
	Gateway  string   `xml:"gateway,omitempty"`
	Descr    string   `xml:"descr,omitempty"`
	Disabled BoolFlag `xml:"disabled,omitempty"`
	// Enabled replaces Disabled from OPNsense 26.1.10 (Routes model 1.0.1), whose
	// migration deletes <disabled>. A pointer, because the firewall falls back to
	// <disabled> only when <enabled> is absent.
	Enabled *string `xml:"enabled,omitempty"`
	Created string  `xml:"created,omitempty"`
	Updated string  `xml:"updated,omitempty"`
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
		r.Enabled == nil &&
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
