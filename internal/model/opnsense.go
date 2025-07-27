// Package model defines the data structures for OPNsense configurations.
package model

import "encoding/xml"

// SystemConfig groups system-related configuration.
type SystemConfig struct {
	System System       `json:"system,omitempty" yaml:"system,omitempty" validate:"required"`
	Sysctl []SysctlItem `json:"sysctl,omitempty" yaml:"sysctl,omitempty"`
}

// NetworkConfig groups network-related configuration.
type NetworkConfig struct {
	Interfaces Interfaces `json:"interfaces,omitempty" yaml:"interfaces,omitempty" validate:"required"`
}

// SecurityConfig groups security-related configuration.
type SecurityConfig struct {
	Nat    Nat    `json:"nat,omitempty" yaml:"nat,omitempty"`
	Filter Filter `json:"filter,omitempty" yaml:"filter,omitempty"`
}

// ServiceConfig groups service-related configuration.
type ServiceConfig struct {
	Dhcpd        Dhcpd        `json:"dhcpd,omitempty" yaml:"dhcpd,omitempty"`
	Unbound      Unbound      `json:"unbound,omitempty" yaml:"unbound,omitempty"`
	Snmpd        Snmpd        `json:"snmpd,omitempty" yaml:"snmpd,omitempty"`
	Rrd          Rrd          `json:"rrd,omitempty" yaml:"rrd,omitempty"`
	LoadBalancer LoadBalancer `json:"loadBalancer,omitempty" yaml:"loadBalancer,omitempty"`
	Ntpd         Ntpd         `json:"ntpd,omitempty" yaml:"ntpd,omitempty"`
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
// It searches through the WAN and LAN interfaces and returns a pointer to the matching interface,
// or nil if no interface with the given name is found.
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
	if o.Interfaces.Wan.If == name {
		return &o.Interfaces.Wan
	}
	if o.Interfaces.Lan.If == name {
		return &o.Interfaces.Lan
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
//	if svcConfig.Dhcpd.Lan.Range.From != "" {
//		fmt.Printf("DHCP range: %s - %s\n", svcConfig.Dhcpd.Lan.Range.From, svcConfig.Dhcpd.Lan.Range.To)
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
	}
}

// SysctlItem represents a single sysctl item.
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

// User represents a user.
type User struct {
	Name      string `xml:"name" json:"name" yaml:"name" validate:"required,alphanum"`
	Descr     string `xml:"descr" json:"description,omitempty" yaml:"description,omitempty"`
	Scope     string `xml:"scope" json:"scope" yaml:"scope" validate:"required,oneof=system local"`
	Groupname string `xml:"groupname" json:"groupname" yaml:"groupname" validate:"required"`
	Password  string `xml:"password" json:"password" yaml:"password" validate:"required"`
	UID       string `xml:"uid" json:"uid" yaml:"uid" validate:"required,numeric"`
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
type Interfaces struct {
	Wan Interface `xml:"wan"`
	Lan Interface `xml:"lan"`
}

// Interface represents a network interface.
type Interface struct {
	Enable          string `xml:"enable,omitempty"`
	If              string `xml:"if,omitempty"`
	MTU             string `xml:"mtu,omitempty"`
	IPAddr          string `xml:"ipaddr,omitempty"`
	IPAddrv6        string `xml:"ipaddrv6,omitempty"`
	Subnet          string `xml:"subnet,omitempty"`
	Subnetv6        string `xml:"subnetv6,omitempty"`
	Gateway         string `xml:"gateway,omitempty"`
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
type Dhcpd struct {
	Lan DhcpdInterface `xml:"lan,omitempty"`
	Wan DhcpdInterface `xml:"wan,omitempty"`
	// Add other interfaces as needed
}

// DhcpdInterface contains the DHCP server configuration for a specific interface.
type DhcpdInterface struct {
	Enable string `xml:"enable,omitempty"`
	Range  Range  `xml:"range,omitempty"`
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
type Destination struct {
	Any struct{} `xml:"any"`
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
