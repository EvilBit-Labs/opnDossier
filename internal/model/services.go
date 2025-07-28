// Package model defines the data structures for OPNsense configurations.
package model

import "encoding/xml"

// ServiceConfig groups service-related configuration.
type ServiceConfig struct {
	Dhcpd        Dhcpd        `json:"dhcpd,omitempty" yaml:"dhcpd,omitempty"`
	Unbound      Unbound      `json:"unbound,omitempty" yaml:"unbound,omitempty"`
	Snmpd        Snmpd        `json:"snmpd,omitempty" yaml:"snmpd,omitempty"`
	Rrd          Rrd          `json:"rrd,omitempty" yaml:"rrd,omitempty"`
	LoadBalancer LoadBalancer `json:"loadBalancer,omitempty" yaml:"loadBalancer,omitempty"`
	Ntpd         Ntpd         `json:"ntpd,omitempty" yaml:"ntpd,omitempty"`
	SSH          SSH          `json:"ssh,omitempty" yaml:"ssh,omitempty"`
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

// DNSMasq represents DNS masquerading configuration.
type DNSMasq struct {
	XMLName            xml.Name         `xml:"dnsmasq"`
	Enable             BoolFlag         `xml:"enable,omitempty"`
	Regdhcp            BoolFlag         `xml:"regdhcp,omitempty"`
	Regdhcpstatic      BoolFlag         `xml:"regdhcpstatic,omitempty"`
	Dhcpfirst          BoolFlag         `xml:"dhcpfirst,omitempty"`
	Strict_order       BoolFlag         `xml:"strict_order,omitempty"`       //nolint:revive // XML field name requires underscore
	Domain_needed      BoolFlag         `xml:"domain_needed,omitempty"`      //nolint:revive // XML field name requires underscore
	No_private_reverse BoolFlag         `xml:"no_private_reverse,omitempty"` //nolint:revive // XML field name requires underscore
	Port               string           `xml:"port,omitempty"`
	Custom_options     string           `xml:"custom_options,omitempty"` //nolint:revive // XML field name requires underscore
	Hosts              []DNSMasqHost    `xml:"hosts>host,omitempty"`
	DomainOverrides    []DomainOverride `xml:"domainoverrides>domainoverride,omitempty"`
	Created            string           `xml:"created,omitempty"`
	Updated            string           `xml:"updated,omitempty"`
}

// DNSMasqHost represents a DNSMasq host entry.
type DNSMasqHost struct {
	XMLName xml.Name `xml:"host"`
	Host    string   `xml:"host,omitempty"`
	Domain  string   `xml:"domain,omitempty"`
	IP      string   `xml:"ip,omitempty"`
	Descr   string   `xml:"descr,omitempty"`
	Aliases []string `xml:"aliases,omitempty"`
}

// DomainOverride represents a domain override entry.
type DomainOverride struct {
	XMLName xml.Name `xml:"domainoverride"`
	Domain  string   `xml:"domain,omitempty"`
	IP      string   `xml:"ip,omitempty"`
	Descr   string   `xml:"descr,omitempty"`
}

// Syslog represents system logging configuration.
type Syslog struct {
	XMLName       xml.Name `xml:"syslog"`
	Reverse       []string `xml:"reverse,omitempty"`
	Nentries      string   `xml:"nentries,omitempty"`
	Remoteserver  string   `xml:"remoteserver,omitempty"`
	Remoteserver2 string   `xml:"remoteserver2,omitempty"`
	Remoteserver3 string   `xml:"remoteserver3,omitempty"`
	Sourceip      string   `xml:"sourceip,omitempty"`
	IPProtocol    string   `xml:"ipprotocol,omitempty"`
	Filter        BoolFlag `xml:"filter,omitempty"`
	Dhcp          BoolFlag `xml:"dhcp,omitempty"`
	Auth          BoolFlag `xml:"auth,omitempty"`
	Portalauth    BoolFlag `xml:"portalauth,omitempty"`
	VPN           BoolFlag `xml:"vpn,omitempty"`
	DPinger       BoolFlag `xml:"dpinger,omitempty"`
	Hostapd       BoolFlag `xml:"hostapd,omitempty"`
	System        BoolFlag `xml:"system,omitempty"`
	Resolver      BoolFlag `xml:"resolver,omitempty"`
	PPP           BoolFlag `xml:"ppp,omitempty"`
	Enable        BoolFlag `xml:"enable,omitempty"`
	LogFilesize   string   `xml:"logfilesize,omitempty"`
	RotateCount   string   `xml:"rotatecount,omitempty"`
	Format        string   `xml:"format,omitempty"`
	IgmpProxy     BoolFlag `xml:"igmpproxy,omitempty"`
	Created       string   `xml:"created,omitempty"`
	Updated       string   `xml:"updated,omitempty"`
}

// Constructor functions for service models

// NewDNSMasq creates a new DNSMasq configuration with properly initialized slices.
func NewDNSMasq() *DNSMasq {
	return &DNSMasq{
		Hosts:           make([]DNSMasqHost, 0),
		DomainOverrides: make([]DomainOverride, 0),
	}
}

// NewDNSMasqHost creates a new DNSMasqHost with properly initialized slices.
func NewDNSMasqHost() DNSMasqHost {
	return DNSMasqHost{
		Aliases: make([]string, 0),
	}
}

// NewSyslog creates a new Syslog configuration with properly initialized slices.
func NewSyslog() *Syslog {
	return &Syslog{
		Reverse: make([]string, 0),
	}
}
