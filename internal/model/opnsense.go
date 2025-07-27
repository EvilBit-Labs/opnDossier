// Package model defines the data structures for OPNsense configurations.
package model

import (
	"encoding/xml"
)

// SystemConfig groups system-related configuration.
type SystemConfig struct {
	System System       `json:"system,omitempty" yaml:"system,omitempty" validate:"required"`
	Sysctl []SysctlItem `json:"sysctl,omitempty" yaml:"sysctl,omitempty"`
}

// NetworkConfig groups network-related configuration.
type NetworkConfig struct {
	Interfaces Interfaces `json:"interfaces,omitempty" yaml:"interfaces,omitempty" validate:"required"`
	// TODO: Add VLANs, Gateways, and DHCP when these fields are added to the model
	VLANs    []VLAN    `json:"vlans,omitempty" yaml:"vlans,omitempty"`
	Gateways []Gateway `json:"gateways,omitempty" yaml:"gateways,omitempty"`
	// DHCP      Dhcpd       `json:"dhcp,omitempty" yaml:"dhcp,omitempty"`
}

// VLAN represents a Virtual Local Area Network configuration.
type VLAN struct {
	Name              string `xml:"vlanif,omitempty"`
	Tag               string `xml:"tag,omitempty"`
	PhysicalInterface string `xml:"if,omitempty"`
	Enable            string `xml:"enable,omitempty"`
	Description       string `xml:"descr,omitempty"`
}

// Bridge represents a network bridge configuration.
type Bridge struct {
	Name        string   `xml:"bridgeif,omitempty"`
	Members     []string `xml:"members,omitempty"`
	Description string   `xml:"descr,omitempty"`
	Interface   string   `xml:"if,omitempty"`
}

// Gateway represents a network gateway configuration.
type Gateway struct {
	DefaultGateway string `xml:"defaultgw,omitempty"`
	Name           string `xml:"name,omitempty"`
	Interface      string `xml:"if,omitempty"`
	Gateway        string `xml:"gateway,omitempty"`
	Weight         string `xml:"weight,omitempty"`
	IPAddress      string `xml:"ipprotocol,omitempty"`
	Description    string `xml:"descr,omitempty"`
}

// StaticRoute represents a network static route configuration.
type StaticRoute struct {
	Disabled    string `xml:"disabled,omitempty"`
	Network     string `xml:"network,omitempty"`
	Gateway     string `xml:"gateway,omitempty"`
	Description string `xml:"descr,omitempty"`
}

// SecurityConfig groups security-related configuration.
type SecurityConfig struct {
	Nat    Nat    `json:"nat,omitempty" yaml:"nat,omitempty"`
	Filter Filter `json:"filter,omitempty" yaml:"filter,omitempty"`
	// TODO: Add Aliases, IDS/IPS, VPNs when these fields are added to the model
	// Aliases []Alias    `json:"aliases,omitempty" yaml:"aliases,omitempty"`
	// IDS     IDSConfig  `json:"ids,omitempty" yaml:"ids,omitempty"`
	// IPS     IPSConfig  `json:"ips,omitempty" yaml:"ips,omitempty"`
	// VPNs    VPNConfig  `json:"vpns,omitempty" yaml:"vpns,omitempty"`
}

// ServiceConfig groups service-related configuration.
type ServiceConfig struct {
	Dhcpd        Dhcpd        `json:"dhcpd,omitempty" yaml:"dhcpd,omitempty"`
	Unbound      Unbound      `json:"unbound,omitempty" yaml:"unbound,omitempty"`
	Snmpd        Snmpd        `json:"snmpd,omitempty" yaml:"snmpd,omitempty"`
	Rrd          Rrd          `json:"rrd,omitempty" yaml:"rrd,omitempty"`
	LoadBalancer LoadBalancer `json:"loadBalancer,omitempty" yaml:"loadBalancer,omitempty"`
	Ntpd         Ntpd         `json:"ntpd,omitempty" yaml:"ntpd,omitempty"`
	SSH          SSH          `json:"ssh,omitempty" yaml:"ssh,omitempty"`
	// TODO: Add OpenVPN and other VPN services when these fields are added to the model
	// OpenVPN   OpenVPNConfig `json:"openvpn,omitempty" yaml:"openvpn,omitempty"`
	// HAProxy   HAProxyConfig `json:"haproxy,omitempty" yaml:"haproxy,omitempty"`
}

// Opnsense is the root of the OPNsense configuration.
type Opnsense struct {
	XMLName              xml.Name     `xml:"opnsense" json:"-" yaml:"-"`
	Version              string       `xml:"version,omitempty" json:"version,omitempty" yaml:"version,omitempty" validate:"omitempty,semver"`
	TriggerInitialWizard struct{}     `xml:"trigger_initial_wizard,omitempty" json:"triggerInitialWizard,omitempty" yaml:"triggerInitialWizard,omitempty"`
	Theme                string       `xml:"theme,omitempty" json:"theme,omitempty" yaml:"theme,omitempty" validate:"omitempty,oneof=opnsense opnsense-ng bootstrap"`
	Sysctl               []SysctlItem `xml:"sysctl,omitempty" json:"sysctl,omitempty" yaml:"sysctl,omitempty" validate:"dive"`
	System               System       `xml:"system,omitempty" json:"system,omitempty" yaml:"system,omitempty" validate:"required"`
	Interfaces           Interfaces   `xml:"interfaces,omitempty" json:"interfaces,omitempty" yaml:"interfaces,omitempty" validate:"required"`
	Dhcpd                Dhcpd        `xml:"dhcpd,omitempty" json:"dhcpd,omitempty" yaml:"dhcpd,omitempty"`
	Unbound              Unbound      `xml:"unbound,omitempty" json:"unbound,omitempty" yaml:"unbound,omitempty"`
	Snmpd                Snmpd        `xml:"snmpd,omitempty" json:"snmpd,omitempty" yaml:"snmpd,omitempty"`
	Nat                  Nat          `xml:"nat,omitempty" json:"nat,omitempty" yaml:"nat,omitempty"`
	Filter               Filter       `xml:"filter,omitempty" json:"filter,omitempty" yaml:"filter,omitempty"`
	Rrd                  Rrd          `xml:"rrd,omitempty" json:"rrd,omitempty" yaml:"rrd,omitempty"`
	LoadBalancer         LoadBalancer `xml:"load_balancer,omitempty" json:"loadBalancer,omitempty" yaml:"loadBalancer,omitempty"`
	Ntpd                 Ntpd         `xml:"ntpd,omitempty" json:"ntpd,omitempty" yaml:"ntpd,omitempty"`
	Widgets              Widgets      `xml:"widgets,omitempty" json:"widgets,omitempty" yaml:"widgets,omitempty"`
}

// Helper methods for Opnsense

// Hostname returns the configured hostname from the system configuration.
// This is a convenience method that extracts the hostname field from the nested System struct.
//
// Example:
//
//	hostname := config.Hostname()
//	fmt.Printf("Firewall hostname: %s\n", hostname)
func (o *Opnsense) Hostname() string {
	return o.System.Hostname
}

// InterfaceByName returns a network interface by its interface name (e.g., "em0", "igb0").
// It searches through all interfaces in the map-based Interfaces struct and returns a pointer
// to the matching interface, or nil if no interface with the given name is found.
//
// Parameters:
//   - name: The interface name to search for (e.g., "em0", "igb0", "vtnet0")
//
// Returns:
//   - *Interface: Pointer to the matching interface, or nil if not found
//
// Example:
//
//	iface := config.InterfaceByName("em0")
//	if iface != nil {
//		fmt.Printf("Interface %s has IP: %s\n", iface.If, iface.IPAddr)
//	}
func (o *Opnsense) InterfaceByName(name string) *Interface {
	for _, iface := range o.Interfaces.Items {
		if iface.If == name {
			return &iface
		}
	}
	return nil
}

// FilterRules returns a slice of all firewall filter rules configured in the system.
// This provides direct access to the firewall rules for analysis, processing, or iteration.
//
// Returns:
//   - []Rule: Slice of all firewall rules, may be empty if no rules are configured
//
// Example:
//
//	rules := config.FilterRules()
//	fmt.Printf("Found %d firewall rules\n", len(rules))
//	for i, rule := range rules {
//		fmt.Printf("Rule %d: %s %s on %s\n", i+1, rule.Type, rule.IPProtocol, rule.Interface)
//	}
func (o *Opnsense) FilterRules() []Rule {
	return o.Filter.Rule
}

// SystemConfig returns the system configuration grouped by functionality.
// This groups system-level settings including core system configuration and sysctl tunables
// into a single structured object for easier access and processing.
//
// Returns:
//   - SystemConfig: Grouped system configuration containing System and Sysctl fields
//
// Example:
//
//	sysConfig := config.SystemConfig()
//	fmt.Printf("Hostname: %s\n", sysConfig.System.Hostname)
//	fmt.Printf("Sysctl items: %d\n", len(sysConfig.Sysctl))
func (o *Opnsense) SystemConfig() SystemConfig {
	return SystemConfig{
		System: o.System,
		Sysctl: o.Sysctl,
	}
}

// NetworkConfig returns the network configuration grouped by functionality.
// This provides a focused view of network-related settings including all interface configurations.
//
// Returns:
//   - NetworkConfig: Grouped network configuration containing interface definitions
//
// Example:
//
//	netConfig := config.NetworkConfig()
//	fmt.Printf("WAN IP: %s\n", netConfig.Interfaces.Wan.IPAddr)
//	fmt.Printf("LAN IP: %s\n", netConfig.Interfaces.Lan.IPAddr)
func (o *Opnsense) NetworkConfig() NetworkConfig {
	return NetworkConfig{
		Interfaces: o.Interfaces,
	}
}

// SecurityConfig returns the security configuration grouped by functionality.
// This groups security-related settings including firewall rules and NAT configuration
// into a single structured object for security analysis and processing.
//
// Returns:
//   - SecurityConfig: Grouped security configuration containing NAT and Filter settings
//
// Example:
//
//	secConfig := config.SecurityConfig()
//	fmt.Printf("NAT mode: %s\n", secConfig.Nat.Outbound.Mode)
//	fmt.Printf("Filter rules: %d\n", len(secConfig.Filter.Rule))
func (o *Opnsense) SecurityConfig() SecurityConfig {
	return SecurityConfig{
		Nat:    o.Nat,
		Filter: o.Filter,
	}
}

// ServiceConfig returns the service configuration grouped by functionality.
// This groups all service-related settings including DHCP, DNS, SNMP, monitoring,
// load balancing, and time services into a single structured object.
//
// Returns:
//   - ServiceConfig: Grouped service configuration containing all service settings
//
// Example:
//
//	svcConfig := config.ServiceConfig()
//	if lanDhcp, ok := svcConfig.Dhcpd.Get("lan"); ok && lanDhcp.Range.From != "" {
//		fmt.Printf("DHCP range: %s - %s\n", lanDhcp.Range.From, lanDhcp.Range.To)
//	}
//	fmt.Printf("SNMP community: %s\n", svcConfig.Snmpd.ROCommunity)
func (o *Opnsense) ServiceConfig() ServiceConfig {
	return ServiceConfig{
		Dhcpd:        o.Dhcpd,
		Unbound:      o.Unbound,
		Snmpd:        o.Snmpd,
		Rrd:          o.Rrd,
		LoadBalancer: o.LoadBalancer,
		Ntpd:         o.Ntpd,
		SSH:          o.System.SSH,
	}
}

// SysctlItem represents a single sysctl item.
// This supports both the simple format (direct elements) and nested item format.
type SysctlItem struct {
	Descr   string `xml:"descr" json:"description,omitempty" yaml:"description,omitempty"`
	Tunable string `xml:"tunable" json:"tunable" yaml:"tunable" validate:"required"`
	Value   string `xml:"value" json:"value" yaml:"value" validate:"required"`
}

// System contains the system configuration.
type System struct {
	Optimization                  string   `xml:"optimization" json:"optimization,omitempty" yaml:"optimization,omitempty" validate:"omitempty,oneof=normal high-latency conservative aggressive"`
	Hostname                      string   `xml:"hostname" json:"hostname" yaml:"hostname" validate:"required,hostname"`
	Domain                        string   `xml:"domain" json:"domain" yaml:"domain" validate:"required,fqdn"`
	DNSAllowOverride              string   `xml:"dnsallowoverride" json:"dnsAllowOverride,omitempty" yaml:"dnsAllowOverride,omitempty"`
	DNSServer                     string   `xml:"dnsserver" json:"dnsServer,omitempty" yaml:"dnsServer,omitempty"`
	Language                      string   `xml:"language" json:"language,omitempty" yaml:"language,omitempty"`
	Firmware                      Firmware `xml:"firmware" json:"firmware,omitempty" yaml:"firmware,omitempty"`
	Group                         []Group  `xml:"group" json:"groups,omitempty" yaml:"groups,omitempty" validate:"dive"`
	User                          []User   `xml:"user" json:"users,omitempty" yaml:"users,omitempty" validate:"dive"`
	NextUID                       string   `xml:"nextuid" json:"nextUid,omitempty" yaml:"nextUid,omitempty" validate:"omitempty,numeric,min=1000"`
	NextGID                       string   `xml:"nextgid" json:"nextGid,omitempty" yaml:"nextGid,omitempty" validate:"omitempty,numeric,min=1000"`
	Timezone                      string   `xml:"timezone" json:"timezone,omitempty" yaml:"timezone,omitempty"`
	Timeservers                   string   `xml:"timeservers" json:"timeservers,omitempty" yaml:"timeservers,omitempty"`
	Webgui                        Webgui   `xml:"webgui" json:"webgui,omitempty" yaml:"webgui,omitempty"`
	DisableNATReflection          string   `xml:"disablenatreflection" json:"disableNatReflection,omitempty" yaml:"disableNatReflection,omitempty"`
	UseVirtualTerminal            string   `xml:"usevirtualterminal" json:"useVirtualTerminal,omitempty" yaml:"useVirtualTerminal,omitempty"`
	DisableConsoleMenu            struct{} `xml:"disableconsolemenu" json:"disableConsoleMenu,omitempty" yaml:"disableConsoleMenu,omitempty"`
	DisableVLANHWFilter           string   `xml:"disablevlanhwfilter" json:"disableVlanHwFilter,omitempty" yaml:"disableVlanHwFilter,omitempty"`
	DisableChecksumOffloading     string   `xml:"disablechecksumoffloading" json:"disableChecksumOffloading,omitempty" yaml:"disableChecksumOffloading,omitempty"`
	DisableSegmentationOffloading string   `xml:"disablesegmentationoffloading" json:"disableSegmentationOffloading,omitempty" yaml:"disableSegmentationOffloading,omitempty"`
	DisableLargeReceiveOffloading string   `xml:"disablelargereceiveoffloading" json:"disableLargeReceiveOffloading,omitempty" yaml:"disableLargeReceiveOffloading,omitempty"`
	IPv6Allow                     struct{} `xml:"ipv6allow" json:"ipv6Allow,omitempty" yaml:"ipv6Allow,omitempty"`
	PowerdAcMode                  string   `xml:"powerd_ac_mode" json:"powerdAcMode,omitempty" yaml:"powerdAcMode,omitempty" validate:"omitempty,oneof=hadp hiadp adaptive minimum maximum"`
	PowerdBatteryMode             string   `xml:"powerd_battery_mode" json:"powerdBatteryMode,omitempty" yaml:"powerdBatteryMode,omitempty" validate:"omitempty,oneof=hadp hiadp adaptive minimum maximum"`
	PowerdNormalMode              string   `xml:"powerd_normal_mode" json:"powerdNormalMode,omitempty" yaml:"powerdNormalMode,omitempty" validate:"omitempty,oneof=hadp hiadp adaptive minimum maximum"`
	Bogons                        Bogons   `xml:"bogons" json:"bogons,omitempty" yaml:"bogons,omitempty"`
	PfShareForward                string   `xml:"pf_share_forward" json:"pfShareForward,omitempty" yaml:"pfShareForward,omitempty"`
	LbUseSticky                   string   `xml:"lb_use_sticky" json:"lbUseSticky,omitempty" yaml:"lbUseSticky,omitempty"`
	SSH                           SSH      `xml:"ssh" json:"ssh,omitempty" yaml:"ssh,omitempty"`
	RrdBackup                     string   `xml:"rrdbackup" json:"rrdBackup,omitempty" yaml:"rrdBackup,omitempty"`
	NetflowBackup                 string   `xml:"netflowbackup" json:"netflowBackup,omitempty" yaml:"netflowBackup,omitempty"`
}

// Group represents a user group.
type Group struct {
	Name        string `xml:"name" json:"name" yaml:"name" validate:"required,alphanum"`
	Description string `xml:"description" json:"description,omitempty" yaml:"description,omitempty"`
	Scope       string `xml:"scope" json:"scope" yaml:"scope" validate:"required,oneof=system local"`
	Gid         string `xml:"gid" json:"gid" yaml:"gid" validate:"required,numeric"`
	Member      string `xml:"member" json:"member,omitempty" yaml:"member,omitempty"`
	Priv        string `xml:"priv" json:"privileges,omitempty" yaml:"privileges,omitempty"`
}

// Firmware represents the firmware configuration.
type Firmware struct {
	Version string `xml:"version,attr" json:"version,omitempty" yaml:"version,omitempty"`
	Mirror  string `xml:"mirror" json:"mirror,omitempty" yaml:"mirror,omitempty"`
	Flavour string `xml:"flavour" json:"flavour,omitempty" yaml:"flavour,omitempty"`
	Plugins string `xml:"plugins" json:"plugins,omitempty" yaml:"plugins,omitempty"`
}

// User represents a user.
type User struct {
	Name           string   `xml:"name" json:"name" yaml:"name" validate:"required,alphanum"`
	Descr          string   `xml:"descr" json:"description,omitempty" yaml:"description,omitempty"`
	Scope          string   `xml:"scope" json:"scope" yaml:"scope" validate:"required,oneof=system local"`
	Groupname      string   `xml:"groupname" json:"groupname" yaml:"groupname" validate:"required"`
	Password       string   `xml:"password" json:"password" yaml:"password" validate:"required"`
	UID            string   `xml:"uid" json:"uid" yaml:"uid" validate:"required,numeric"`
	APIKeys        []APIKey `xml:"apikeys>item" json:"apiKeys,omitempty" yaml:"apiKeys,omitempty"`
	Expires        struct{} `xml:"expires" json:"expires,omitempty" yaml:"expires,omitempty"`
	AuthorizedKeys struct{} `xml:"authorizedkeys" json:"authorizedKeys,omitempty" yaml:"authorizedKeys,omitempty"`
	IPSecPSK       struct{} `xml:"ipsecpsk" json:"ipsecPsk,omitempty" yaml:"ipsecPsk,omitempty"`
	OTPSeed        struct{} `xml:"otp_seed" json:"otpSeed,omitempty" yaml:"otpSeed,omitempty"`
}

// APIKey represents a user API key.
type APIKey struct {
	Key    string `xml:"key" json:"key" yaml:"key"`
	Secret string `xml:"secret" json:"secret" yaml:"secret"`
}

// Webgui contains the web GUI configuration.
type Webgui struct {
	Protocol string `xml:"protocol" json:"protocol" yaml:"protocol" validate:"required,oneof=http https"`
}

// Bogons contains the bogons configuration.
type Bogons struct {
	Interval string `xml:"interval" json:"interval,omitempty" yaml:"interval,omitempty" validate:"omitempty,oneof=monthly weekly daily never"`
}

// SSH contains the SSH configuration.
type SSH struct {
	Group string `xml:"group" json:"group" yaml:"group" validate:"required"`
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

// Unbound contains the Unbound DNS resolver configuration.
type Unbound struct {
	Enable string `xml:"enable"`
}

// Snmpd contains the SNMP daemon configuration.
type Snmpd struct {
	SysLocation string `xml:"syslocation"`
	SysContact  string `xml:"syscontact"`
	ROCommunity string `xml:"rocommunity"`
}

// Nat contains the NAT configuration.
type Nat struct {
	Outbound Outbound `xml:"outbound"`
}

// Outbound contains the outbound NAT configuration.
type Outbound struct {
	Mode string `xml:"mode"`
}

// Filter contains the firewall filter rules.
type Filter struct {
	Rule []Rule `xml:"rule"`
}

// Rule represents a firewall filter rule.
type Rule struct {
	Type        string      `xml:"type"`
	IPProtocol  string      `xml:"ipprotocol"`
	Descr       string      `xml:"descr"`
	Interface   string      `xml:"interface"`
	Source      Source      `xml:"source"`
	Destination Destination `xml:"destination"`
}

// Source represents the source of a firewall rule.
type Source struct {
	Network string `xml:"network"`
}

// Destination represents the destination of a firewall rule.
// TODO: More Granular Destination Analysis - Expand destination model to include:
//   - Port specifications (single port, port ranges, aliases)
//   - Protocol-specific destination options
//   - Network aliases and address groups
//   - IPv6 destination support
//   - Negation support (not destination)
//
// This would enable more comprehensive firewall rule analysis and comparison.
type Destination struct {
	Any     struct{} `xml:"any"`
	Network string   `xml:"network"`
	// TODO: Add missing destination fields for enhanced analysis:
	// Port    string   `xml:"port,omitempty" json:"port,omitempty" yaml:"port,omitempty"`
	// Address string   `xml:"address,omitempty" json:"address,omitempty" yaml:"address,omitempty"`
	// Not     string   `xml:"not,omitempty" json:"not,omitempty" yaml:"not,omitempty"`
}

// Rrd contains the RRDtool configuration.
type Rrd struct {
	Enable struct{} `xml:"enable"`
}

// LoadBalancer contains the load balancer configuration.
type LoadBalancer struct {
	MonitorType []MonitorType `xml:"monitor_type"`
}

// MonitorType represents a load balancer monitor type.
type MonitorType struct {
	Name    string  `xml:"name"`
	Type    string  `xml:"type"`
	Descr   string  `xml:"descr"`
	Options Options `xml:"options"`
}

// Options contains the options for a load balancer monitor type.
type Options struct {
	Path   string `xml:"path"`
	Host   string `xml:"host"`
	Code   string `xml:"code"`
	Send   string `xml:"send"`
	Expect string `xml:"expect"`
}

// Ntpd contains the NTP daemon configuration.
type Ntpd struct {
	Prefer string `xml:"prefer"`
}

// Widgets contains the dashboard widget configuration.
type Widgets struct {
	Sequence    string `xml:"sequence"`
	ColumnCount string `xml:"column_count"`
}
