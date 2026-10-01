package opnsense

import (
	"encoding/xml"
	"maps"
	"slices"
)

// InterfaceGroups represents interface groups configuration.
type InterfaceGroups struct {
	XMLName      xml.Name       `xml:"ifgroups"               json:"-"                      yaml:"-"`
	Version      string         `xml:"version,attr,omitempty" json:"version,omitempty"      yaml:"version,omitempty"`
	IfGroupEntry []IfGroupEntry `xml:"ifgroupentry,omitempty" json:"ifgroupentry,omitempty" yaml:"ifgroupentry,omitempty"`
}

// GIFInterfaces represents GIF interface configuration.
type GIFInterfaces struct {
	XMLName xml.Name `xml:"gifs"                   json:"-"                 yaml:"-"`
	Version string   `xml:"version,attr,omitempty" json:"version,omitempty" yaml:"version,omitempty"`
	Gif     []GIF    `xml:"gif,omitempty"          json:"gif,omitempty"     yaml:"gif,omitempty"`
}

// GREInterfaces represents GRE interface configuration.
type GREInterfaces struct {
	XMLName xml.Name `xml:"gres"                   json:"-"                 yaml:"-"`
	Version string   `xml:"version,attr,omitempty" json:"version,omitempty" yaml:"version,omitempty"`
	Gre     []GRE    `xml:"gre,omitempty"          json:"gre,omitempty"     yaml:"gre,omitempty"`
}

// LAGGInterfaces represents LAGG interface configuration.
type LAGGInterfaces struct {
	XMLName xml.Name `xml:"laggs"                  json:"-"                 yaml:"-"`
	Version string   `xml:"version,attr,omitempty" json:"version,omitempty" yaml:"version,omitempty"`
	Lagg    []LAGG   `xml:"lagg,omitempty"         json:"lagg,omitempty"    yaml:"lagg,omitempty"`
}

// VirtualIP represents virtual IP configuration.
type VirtualIP struct {
	XMLName xml.Name `xml:"virtualip"              json:"-"                 yaml:"-"`
	Version string   `xml:"version,attr,omitempty" json:"version,omitempty" yaml:"version,omitempty"`
	Vip     []VIP    `xml:"vip,omitempty"          json:"vip,omitempty"     yaml:"vip,omitempty"`
}

// PPPInterfaces represents PPP interface configuration.
type PPPInterfaces struct {
	XMLName xml.Name `xml:"ppps"          json:"-"             yaml:"-"`
	Ppp     []PPP    `xml:"ppp,omitempty" json:"ppp,omitempty" yaml:"ppp,omitempty"`
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

	// Encode interfaces in sorted key order for deterministic output (GOTCHAS §3.1).
	for _, key := range slices.Sorted(maps.Keys(i.Items)) {
		iface := i.Items[key]
		ifaceStart := xml.StartElement{Name: xml.Name{Local: key}}
		if err := e.EncodeElement(&iface, ifaceStart); err != nil {
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

	return slices.Sorted(maps.Keys(i.Items))
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

// Interface represents a single network interface configuration, including IP addressing,
// VLAN settings, gateway bindings, DHCP options, and advanced DHCPv6 fields.
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
	// Not mapped into the common model, so a scalar is accurate today. Make it
	// []string before mapping it: <dnsserver> repeats (GOTCHAS 3.3).
	Dnsserver string `xml:"dnsserver,omitempty" json:"dnsserver,omitempty" yaml:"dnsserver,omitempty"`
	Ntpserver string `xml:"ntpserver,omitempty" json:"ntpserver,omitempty" yaml:"ntpserver,omitempty"`

	// Advanced DHCPv4 client fields, set on the interface by the DHCP client tab.
	AdvDHCPPTTimeout              string `xml:"adv_dhcp_pt_timeout,omitempty"                json:"advDhcpPtTimeout,omitempty"              yaml:"advDhcpPtTimeout,omitempty"`
	AdvDHCPPTRetry                string `xml:"adv_dhcp_pt_retry,omitempty"                  json:"advDhcpPtRetry,omitempty"                yaml:"advDhcpPtRetry,omitempty"`
	AdvDHCPPTSelectTimeout        string `xml:"adv_dhcp_pt_select_timeout,omitempty"         json:"advDhcpPtSelectTimeout,omitempty"        yaml:"advDhcpPtSelectTimeout,omitempty"`
	AdvDHCPPTReboot               string `xml:"adv_dhcp_pt_reboot,omitempty"                 json:"advDhcpPtReboot,omitempty"               yaml:"advDhcpPtReboot,omitempty"`
	AdvDHCPPTBackoffCutoff        string `xml:"adv_dhcp_pt_backoff_cutoff,omitempty"         json:"advDhcpPtBackoffCutoff,omitempty"        yaml:"advDhcpPtBackoffCutoff,omitempty"`
	AdvDHCPPTInitialInterval      string `xml:"adv_dhcp_pt_initial_interval,omitempty"       json:"advDhcpPtInitialInterval,omitempty"      yaml:"advDhcpPtInitialInterval,omitempty"`
	AdvDHCPPTValues               string `xml:"adv_dhcp_pt_values,omitempty"                 json:"advDhcpPtValues,omitempty"               yaml:"advDhcpPtValues,omitempty"`
	AdvDHCPSendOptions            string `xml:"adv_dhcp_send_options,omitempty"              json:"advDhcpSendOptions,omitempty"            yaml:"advDhcpSendOptions,omitempty"`
	AdvDHCPRequestOptions         string `xml:"adv_dhcp_request_options,omitempty"           json:"advDhcpRequestOptions,omitempty"         yaml:"advDhcpRequestOptions,omitempty"`
	AdvDHCPRequiredOptions        string `xml:"adv_dhcp_required_options,omitempty"          json:"advDhcpRequiredOptions,omitempty"        yaml:"advDhcpRequiredOptions,omitempty"`
	AdvDHCPOptionModifiers        string `xml:"adv_dhcp_option_modifiers,omitempty"          json:"advDhcpOptionModifiers,omitempty"        yaml:"advDhcpOptionModifiers,omitempty"`
	AdvDHCPConfigAdvanced         string `xml:"adv_dhcp_config_advanced,omitempty"           json:"advDhcpConfigAdvanced,omitempty"         yaml:"advDhcpConfigAdvanced,omitempty"`
	AdvDHCPConfigFileOverride     string `xml:"adv_dhcp_config_file_override,omitempty"      json:"advDhcpConfigFileOverride,omitempty"     yaml:"advDhcpConfigFileOverride,omitempty"`
	AdvDHCPConfigFileOverridePath string `xml:"adv_dhcp_config_file_override_path,omitempty" json:"advDhcpConfigFileOverridePath,omitempty" yaml:"advDhcpConfigFileOverridePath,omitempty"`

	// Advanced DHCPv6 client fields, set on the interface by the DHCPv6 client tab.
	//
	// The three *Enable checkboxes are strings, not BoolFlag. OPNsense 16.1 and
	// later store a ticked box as "on", 15.x stored "Selected", and releases
	// through 26.7.4 write an unticked one as a self-closing element. The
	// converters treat any non-empty value as ticked, as interfaces.inc does for
	// every value the GUI writes. Some of its checks use !empty(), which also
	// treats "0" as unticked, but the GUI never writes "0".
	AdvDHCP6InterfaceStatementSendOptions           string `xml:"adv_dhcp6_interface_statement_send_options,omitempty"            json:"advDhcp6InterfaceStatementSendOptions,omitempty"           yaml:"advDhcp6InterfaceStatementSendOptions,omitempty"`
	AdvDHCP6InterfaceStatementRequestOptions        string `xml:"adv_dhcp6_interface_statement_request_options,omitempty"         json:"advDhcp6InterfaceStatementRequestOptions,omitempty"        yaml:"advDhcp6InterfaceStatementRequestOptions,omitempty"`
	AdvDHCP6InterfaceStatementInformationOnlyEnable string `xml:"adv_dhcp6_interface_statement_information_only_enable,omitempty" json:"advDhcp6InterfaceStatementInformationOnlyEnable,omitempty" yaml:"advDhcp6InterfaceStatementInformationOnlyEnable,omitempty"`
	AdvDHCP6InterfaceStatementScript                string `xml:"adv_dhcp6_interface_statement_script,omitempty"                  json:"advDhcp6InterfaceStatementScript,omitempty"                yaml:"advDhcp6InterfaceStatementScript,omitempty"`
	AdvDHCP6IDAssocStatementAddressEnable           string `xml:"adv_dhcp6_id_assoc_statement_address_enable,omitempty"           json:"advDhcp6IdAssocStatementAddressEnable,omitempty"           yaml:"advDhcp6IdAssocStatementAddressEnable,omitempty"`
	AdvDHCP6IDAssocStatementAddress                 string `xml:"adv_dhcp6_id_assoc_statement_address,omitempty"                  json:"advDhcp6IdAssocStatementAddress,omitempty"                 yaml:"advDhcp6IdAssocStatementAddress,omitempty"`
	AdvDHCP6IDAssocStatementAddressID               string `xml:"adv_dhcp6_id_assoc_statement_address_id,omitempty"               json:"advDhcp6IdAssocStatementAddressId,omitempty"               yaml:"advDhcp6IdAssocStatementAddressId,omitempty"`
	AdvDHCP6IDAssocStatementAddressPLTime           string `xml:"adv_dhcp6_id_assoc_statement_address_pltime,omitempty"           json:"advDhcp6IdAssocStatementAddressPltime,omitempty"           yaml:"advDhcp6IdAssocStatementAddressPltime,omitempty"`
	AdvDHCP6IDAssocStatementAddressVLTime           string `xml:"adv_dhcp6_id_assoc_statement_address_vltime,omitempty"           json:"advDhcp6IdAssocStatementAddressVltime,omitempty"           yaml:"advDhcp6IdAssocStatementAddressVltime,omitempty"`
	AdvDHCP6IDAssocStatementPrefixEnable            string `xml:"adv_dhcp6_id_assoc_statement_prefix_enable,omitempty"            json:"advDhcp6IdAssocStatementPrefixEnable,omitempty"            yaml:"advDhcp6IdAssocStatementPrefixEnable,omitempty"`
	AdvDHCP6IDAssocStatementPrefix                  string `xml:"adv_dhcp6_id_assoc_statement_prefix,omitempty"                   json:"advDhcp6IdAssocStatementPrefix,omitempty"                  yaml:"advDhcp6IdAssocStatementPrefix,omitempty"`
	AdvDHCP6IDAssocStatementPrefixID                string `xml:"adv_dhcp6_id_assoc_statement_prefix_id,omitempty"                json:"advDhcp6IdAssocStatementPrefixId,omitempty"                yaml:"advDhcp6IdAssocStatementPrefixId,omitempty"`
	AdvDHCP6IDAssocStatementPrefixPLTime            string `xml:"adv_dhcp6_id_assoc_statement_prefix_pltime,omitempty"            json:"advDhcp6IdAssocStatementPrefixPltime,omitempty"            yaml:"advDhcp6IdAssocStatementPrefixPltime,omitempty"`
	AdvDHCP6IDAssocStatementPrefixVLTime            string `xml:"adv_dhcp6_id_assoc_statement_prefix_vltime,omitempty"            json:"advDhcp6IdAssocStatementPrefixVltime,omitempty"            yaml:"advDhcp6IdAssocStatementPrefixVltime,omitempty"`
	AdvDHCP6PrefixInterfaceStatementSLALen          string `xml:"adv_dhcp6_prefix_interface_statement_sla_len,omitempty"          json:"advDhcp6PrefixInterfaceStatementSlaLen,omitempty"          yaml:"advDhcp6PrefixInterfaceStatementSlaLen,omitempty"`
	AdvDHCP6AuthenticationStatementAuthName         string `xml:"adv_dhcp6_authentication_statement_authname,omitempty"           json:"advDhcp6AuthenticationStatementAuthName,omitempty"         yaml:"advDhcp6AuthenticationStatementAuthName,omitempty"`
	AdvDHCP6AuthenticationStatementProtocol         string `xml:"adv_dhcp6_authentication_statement_protocol,omitempty"           json:"advDhcp6AuthenticationStatementProtocol,omitempty"         yaml:"advDhcp6AuthenticationStatementProtocol,omitempty"`
	AdvDHCP6AuthenticationStatementAlgorithm        string `xml:"adv_dhcp6_authentication_statement_algorithm,omitempty"          json:"advDhcp6AuthenticationStatementAlgorithm,omitempty"        yaml:"advDhcp6AuthenticationStatementAlgorithm,omitempty"`
	AdvDHCP6AuthenticationStatementRDM              string `xml:"adv_dhcp6_authentication_statement_rdm,omitempty"                json:"advDhcp6AuthenticationStatementRdm,omitempty"              yaml:"advDhcp6AuthenticationStatementRdm,omitempty"`
	AdvDHCP6KeyInfoStatementKeyName                 string `xml:"adv_dhcp6_key_info_statement_keyname,omitempty"                  json:"advDhcp6KeyInfoStatementKeyName,omitempty"                 yaml:"advDhcp6KeyInfoStatementKeyName,omitempty"`
	AdvDHCP6KeyInfoStatementRealm                   string `xml:"adv_dhcp6_key_info_statement_realm,omitempty"                    json:"advDhcp6KeyInfoStatementRealm,omitempty"                   yaml:"advDhcp6KeyInfoStatementRealm,omitempty"`
	AdvDHCP6KeyInfoStatementKeyID                   string `xml:"adv_dhcp6_key_info_statement_keyid,omitempty"                    json:"advDhcp6KeyInfoStatementKeyId,omitempty"                   yaml:"advDhcp6KeyInfoStatementKeyId,omitempty"`
	AdvDHCP6KeyInfoStatementSecret                  string `xml:"adv_dhcp6_key_info_statement_secret,omitempty"                   json:"advDhcp6KeyInfoStatementSecret,omitempty"                  yaml:"advDhcp6KeyInfoStatementSecret,omitempty"`
	AdvDHCP6KeyInfoStatementExpire                  string `xml:"adv_dhcp6_key_info_statement_expire,omitempty"                   json:"advDhcp6KeyInfoStatementExpire,omitempty"                  yaml:"advDhcp6KeyInfoStatementExpire,omitempty"`
	AdvDHCP6ConfigAdvanced                          string `xml:"adv_dhcp6_config_advanced,omitempty"                             json:"advDhcp6ConfigAdvanced,omitempty"                          yaml:"advDhcp6ConfigAdvanced,omitempty"`
	AdvDHCP6ConfigFileOverride                      string `xml:"adv_dhcp6_config_file_override,omitempty"                        json:"advDhcp6ConfigFileOverride,omitempty"                      yaml:"advDhcp6ConfigFileOverride,omitempty"`
	AdvDHCP6ConfigFileOverridePath                  string `xml:"adv_dhcp6_config_file_override_path,omitempty"                   json:"advDhcp6ConfigFileOverridePath,omitempty"                  yaml:"advDhcp6ConfigFileOverridePath,omitempty"`
}

// VLANConfig represents a Virtual Local Area Network configuration used in [NetworkConfig].
// This is a simplified VLAN representation for the common device model.
type VLANConfig struct {
	Name              string `xml:"vlanif,omitempty"`
	Tag               string `xml:"tag,omitempty"`
	PhysicalInterface string `xml:"if,omitempty"`
	Enable            string `xml:"enable,omitempty"`
	Description       string `xml:"descr,omitempty"`
}

// VLANs represents the <vlans> container element holding all VLAN configurations in the OPNsense document.
type VLANs struct {
	XMLName xml.Name `xml:"vlans"`
	VLAN    []VLAN   `xml:"vlan,omitempty"`
}

// VLAN represents a single VLAN configuration entry with its parent physical interface,
// 802.1Q tag, virtual interface name (vlanif), and creation/update timestamps.
type VLAN struct {
	XMLName xml.Name `xml:"vlan"`
	If      string   `xml:"if,omitempty"`
	Tag     string   `xml:"tag,omitempty"`
	Descr   string   `xml:"descr,omitempty"`
	Vlanif  string   `xml:"vlanif,omitempty"`
	Created string   `xml:"created,omitempty"`
	Updated string   `xml:"updated,omitempty"`
}

// IsPlaceholder reports whether the value is an empty <vlan/> marker rather
// than a configured VLAN. OPNsense writes that self-closing element inside
// <vlans> when nothing is configured -- testdata/opnsense-config.dtd
// declares it as "<!ELEMENT vlan EMPTY>" -- and it unmarshals into an entry whose
// configuration fields are all zero.
//
// The check is deliberately conservative: an entry is dropped only when every
// field is zero. See GOTCHAS.md section 3.4 for why fields are compared by name
// rather than against the zero value.
func (v VLAN) IsPlaceholder() bool {
	return v.If == "" &&
		v.Tag == "" &&
		v.Descr == "" &&
		v.Vlanif == "" &&
		v.Created == "" &&
		v.Updated == ""
}

// Bridge represents a network bridge configuration, combining multiple interfaces
// into a single Layer 2 broadcast domain with optional STP (Spanning Tree Protocol).
type Bridge struct {
	XMLName  xml.Name `xml:"bridged"`
	Members  string   `xml:"members,omitempty"`
	Descr    string   `xml:"descr,omitempty"`
	Bridgeif string   `xml:"bridgeif,omitempty"`
	STP      BoolFlag `xml:"stp,omitempty"`
	Created  string   `xml:"created,omitempty"`
	Updated  string   `xml:"updated,omitempty"`
}

// IsPlaceholder reports whether b is an empty <bridged/> marker rather than a
// configured bridge. OPNsense writes that self-closing element inside <bridges>
// when nothing is configured -- the shipped testdata/opnsense-config.dtd
// declares it as "<!ELEMENT bridged EMPTY>" for exactly this reason -- and it
// unmarshals into an entry whose configuration fields are all zero.
//
// The check is deliberately conservative: an entry is dropped only when every
// field is zero. A bridge carrying any data at all -- even just a description --
// is retained, because under-reporting configured resources is the more
// dangerous direction for an auditing tool.
//
// Fields are compared by name rather than against the zero value: encoding/xml
// populates XMLName on unmarshal, so a decoded <bridged/> never equals Bridge{}.
func (b Bridge) IsPlaceholder() bool {
	return b.Bridgeif == "" &&
		b.Members == "" &&
		b.Descr == "" &&
		!bool(b.STP) &&
		b.Created == "" &&
		b.Updated == ""
}

// Bridges represents the <bridges> container element holding all bridge configurations.
// OPNsense stores each entry as <bridged>, not <bridge>.
type Bridges struct {
	XMLName xml.Name `xml:"bridges"`
	Bridge  []Bridge `xml:"bridged,omitempty"`
}

// GIF represents a GIF (Generic Tunnel Interface) configuration entry for IPv4/IPv6-in-IPv4/IPv6 tunneling.
type GIF struct {
	XMLName xml.Name `xml:"gif"`
	Gifif   string   `xml:"gifif,omitempty"`
	If      string   `xml:"if,omitempty"`
	Remote  string   `xml:"remote,omitempty"`
	Descr   string   `xml:"descr,omitempty"`
	Created string   `xml:"created,omitempty"`
	Updated string   `xml:"updated,omitempty"`
}

// IsPlaceholder reports whether the value is an empty <gif/> marker rather
// than a configured tunnel. OPNsense writes that self-closing element inside
// <gifs> when nothing is configured -- testdata/opnsense-config.dtd
// declares it as "<!ELEMENT gif EMPTY>" -- and it unmarshals into an entry whose
// configuration fields are all zero.
//
// The check is deliberately conservative: an entry is dropped only when every
// field is zero. See GOTCHAS.md section 3.4 for why fields are compared by name
// rather than against the zero value.
func (g GIF) IsPlaceholder() bool {
	return g.Gifif == "" &&
		g.If == "" &&
		g.Remote == "" &&
		g.Descr == "" &&
		g.Created == "" &&
		g.Updated == ""
}

// GRE represents a GRE (Generic Routing Encapsulation) tunnel configuration entry for point-to-point encapsulation.
type GRE struct {
	XMLName xml.Name `xml:"gre"`
	Greif   string   `xml:"greif,omitempty"`
	If      string   `xml:"if,omitempty"`
	Remote  string   `xml:"remote,omitempty"`
	Descr   string   `xml:"descr,omitempty"`
	Created string   `xml:"created,omitempty"`
	Updated string   `xml:"updated,omitempty"`
}

// IsPlaceholder reports whether the value is an empty <gre/> marker rather
// than a configured tunnel. OPNsense writes that self-closing element inside
// <gres> when nothing is configured -- testdata/opnsense-config.dtd
// declares it as "<!ELEMENT gre EMPTY>" -- and it unmarshals into an entry whose
// configuration fields are all zero.
//
// The check is deliberately conservative: an entry is dropped only when every
// field is zero. See GOTCHAS.md section 3.4 for why fields are compared by name
// rather than against the zero value.
func (g GRE) IsPlaceholder() bool {
	return g.Greif == "" &&
		g.If == "" &&
		g.Remote == "" &&
		g.Descr == "" &&
		g.Created == "" &&
		g.Updated == ""
}

// LAGG represents a LAGG (Link Aggregation) interface configuration entry for bonding
// multiple physical interfaces using protocols like LACP, failover, or round-robin.
type LAGG struct {
	XMLName xml.Name `xml:"lagg"`
	Laggif  string   `xml:"laggif,omitempty"`
	Members string   `xml:"members,omitempty"`
	Proto   string   `xml:"proto,omitempty"`
	Descr   string   `xml:"descr,omitempty"`
	Created string   `xml:"created,omitempty"`
	Updated string   `xml:"updated,omitempty"`
}

// IsPlaceholder reports whether the value is an empty <lagg/> marker rather
// than a configured link aggregation. OPNsense writes that self-closing element inside
// <laggs> when nothing is configured -- testdata/opnsense-config.dtd
// declares it as "<!ELEMENT lagg EMPTY>" -- and it unmarshals into an entry whose
// configuration fields are all zero.
//
// The check is deliberately conservative: an entry is dropped only when every
// field is zero. See GOTCHAS.md section 3.4 for why fields are compared by name
// rather than against the zero value.
func (l LAGG) IsPlaceholder() bool {
	return l.Laggif == "" &&
		l.Members == "" &&
		l.Proto == "" &&
		l.Descr == "" &&
		l.Created == "" &&
		l.Updated == ""
}

// VIP represents a virtual IP address configuration entry used for CARP, IP alias,
// proxy ARP, or other virtual address modes bound to a specific interface.
type VIP struct {
	XMLName   xml.Name `xml:"vip"`
	Mode      string   `xml:"mode,omitempty"`
	Interface string   `xml:"interface,omitempty"`
	Subnet    string   `xml:"subnet,omitempty"`
	Descr     string   `xml:"descr,omitempty"`
}

// IsPlaceholder reports whether the value is an empty <vip/> marker rather
// than a configured virtual IP. OPNsense writes that self-closing element inside
// <virtualip> when nothing is configured -- testdata/opnsense-config.dtd
// declares it as "<!ELEMENT vip EMPTY>" -- and it unmarshals into an entry whose
// configuration fields are all zero.
//
// The check is deliberately conservative: an entry is dropped only when every
// field is zero. See GOTCHAS.md section 3.4 for why fields are compared by name
// rather than against the zero value.
func (v VIP) IsPlaceholder() bool {
	return v.Mode == "" &&
		v.Interface == "" &&
		v.Subnet == "" &&
		v.Descr == ""
}

// PPP represents a PPP (Point-to-Point Protocol) interface configuration entry,
// covering PPPoE, PPTP, and L2TP connection types.
type PPP struct {
	XMLName xml.Name `xml:"ppp"`
	If      string   `xml:"if,omitempty"`
	Type    string   `xml:"type,omitempty"`
	Descr   string   `xml:"descr,omitempty"`
}

// IsPlaceholder reports whether p is an empty <ppp/> marker rather than a
// configured PPP link. OPNsense writes that self-closing element inside <ppps>
// when nothing is configured, and it unmarshals into an entry whose
// configuration fields are all zero.
//
// The check is deliberately conservative: an entry is dropped only when every
// field is zero. A link carrying any data at all -- even just a description --
// is retained, because under-reporting configured resources is the more
// dangerous direction for an auditing tool.
//
// Fields are compared by name rather than against the zero value: encoding/xml
// populates XMLName on unmarshal, so a decoded <ppp/> never equals PPP{}.
//
// The pfSense parser shares this type, and pkg/schema/pfsense/README.md records
// <ppps> as an "Identical base" rather than a full mirror: real pfSense entries
// can also carry ptpid, ports, username, password, provider, and mtu, none of
// which this struct declares. An entry populating only those unparsed fields
// would be read as a placeholder. No committed fixture exhibits that shape, and
// a usable PPP link sets if and type in practice, so this is an accepted
// assumption rather than a known defect -- but a fuller pfSense PPP fork must
// extend this predicate along with the struct.
func (p PPP) IsPlaceholder() bool {
	return p.If == "" &&
		p.Type == "" &&
		p.Descr == ""
}

// IfGroupEntry represents an interface group entry, binding a group name to its member interfaces.
type IfGroupEntry struct {
	XMLName xml.Name `xml:"ifgroupentry"`
	IfName  string   `xml:"ifname,omitempty"`
	Members string   `xml:"members,omitempty"`
}
