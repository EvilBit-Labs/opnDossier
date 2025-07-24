// Package model defines the data structures for OPNsense configurations.
package model

import "encoding/xml"

// Opnsense is the root of the OPNsense configuration.
type Opnsense struct {
	XMLName              xml.Name     `xml:"opnsense"`
	Version              string       `xml:"version,omitempty"`
	TriggerInitialWizard struct{}     `xml:"trigger_initial_wizard,omitempty"`
	Theme                string       `xml:"theme,omitempty"`
	Sysctl               []SysctlItem `xml:"sysctl>item,omitempty"`
	System               System       `xml:"system,omitempty"`
	Interfaces           Interfaces   `xml:"interfaces,omitempty"`
	Dhcpd                Dhcpd        `xml:"dhcpd,omitempty"`
	Unbound              Unbound      `xml:"unbound,omitempty"`
	Snmpd                Snmpd        `xml:"snmpd,omitempty"`
	Nat                  Nat          `xml:"nat,omitempty"`
	Filter               Filter       `xml:"filter,omitempty"`
	Rrd                  Rrd          `xml:"rrd,omitempty"`
	LoadBalancer         LoadBalancer `xml:"load_balancer,omitempty"`
	Ntpd                 Ntpd         `xml:"ntpd,omitempty"`
	Widgets              Widgets      `xml:"widgets,omitempty"`
}

// SysctlItem represents a single sysctl item.
type SysctlItem struct {
	Descr   string `xml:"descr"`
	Tunable string `xml:"tunable"`
	Value   string `xml:"value"`
}

// System contains the system configuration.
type System struct {
	Optimization                  string   `xml:"optimization"`
	Hostname                      string   `xml:"hostname"`
	Domain                        string   `xml:"domain"`
	Dnsallowoverride              string   `xml:"dnsallowoverride"`
	Group                         []Group  `xml:"group"`
	User                          []User   `xml:"user"`
	Nextuid                       string   `xml:"nextuid"`
	Nextgid                       string   `xml:"nextgid"`
	Timezone                      string   `xml:"timezone"`
	Timeservers                   string   `xml:"timeservers"`
	Webgui                        Webgui   `xml:"webgui"`
	Disablenatreflection          string   `xml:"disablenatreflection"`
	Usevirtualterminal            string   `xml:"usevirtualterminal"`
	Disableconsolemenu            struct{} `xml:"disableconsolemenu"`
	Disablevlanhwfilter           string   `xml:"disablevlanhwfilter"`
	Disablechecksumoffloading     string   `xml:"disablechecksumoffloading"`
	Disablesegmentationoffloading string   `xml:"disablesegmentationoffloading"`
	Disablelargereceiveoffloading string   `xml:"disablelargereceiveoffloading"`
	Ipv6allow                     struct{} `xml:"ipv6allow"`
	PowerdAcMode                  string   `xml:"powerd_ac_mode"`
	PowerdBatteryMode             string   `xml:"powerd_battery_mode"`
	PowerdNormalMode              string   `xml:"powerd_normal_mode"`
	Bogons                        Bogons   `xml:"bogons"`
	PfShareForward                string   `xml:"pf_share_forward"`
	LbUseSticky                   string   `xml:"lb_use_sticky"`
	SSH                           SSH      `xml:"ssh"`
	Rrdbackup                     string   `xml:"rrdbackup"`
	Netflowbackup                 string   `xml:"netflowbackup"`
}

// Group represents a user group.
type Group struct {
	Name        string `xml:"name"`
	Description string `xml:"description"`
	Scope       string `xml:"scope"`
	Gid         string `xml:"gid"`
	Member      string `xml:"member"`
	Priv        string `xml:"priv"`
}

// User represents a user.
type User struct {
	Name      string `xml:"name"`
	Descr     string `xml:"descr"`
	Scope     string `xml:"scope"`
	Groupname string `xml:"groupname"`
	Password  string `xml:"password"`
	UID       string `xml:"uid"`
}

// Webgui contains the web GUI configuration.
type Webgui struct {
	Protocol string `xml:"protocol"`
}

// Bogons contains the bogons configuration.
type Bogons struct {
	Interval string `xml:"interval"`
}

// SSH contains the SSH configuration.
type SSH struct {
	Group string `xml:"group"`
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
	Mtu             string `xml:"mtu,omitempty"`
	Ipaddr          string `xml:"ipaddr,omitempty"`
	Ipaddrv6        string `xml:"ipaddrv6,omitempty"`
	Subnet          string `xml:"subnet,omitempty"`
	Subnetv6        string `xml:"subnetv6,omitempty"`
	Gateway         string `xml:"gateway,omitempty"`
	Blockpriv       string `xml:"blockpriv,omitempty"`
	Blockbogons     string `xml:"blockbogons,omitempty"`
	Dhcphostname    string `xml:"dhcphostname,omitempty"`
	Media           string `xml:"media,omitempty"`
	Mediaopt        string `xml:"mediaopt,omitempty"`
	Dhcp6IaPdLen    string `xml:"dhcp6-ia-pd-len,omitempty"`
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
	Syslocation string `xml:"syslocation"`
	Syscontact  string `xml:"syscontact"`
	Rocommunity string `xml:"rocommunity"`
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
	Ipprotocol  string      `xml:"ipprotocol"`
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
