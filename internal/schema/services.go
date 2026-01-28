// Package schema defines the data structures for OPNsense configurations.
package schema

import "encoding/xml"

// ServiceConfig groups service-related configuration.
type ServiceConfig struct {
	Dhcpd        Dhcpd        `json:"dhcpd"        yaml:"dhcpd,omitempty"`
	Unbound      Unbound      `json:"unbound"      yaml:"unbound,omitempty"`
	Snmpd        Snmpd        `json:"snmpd"        yaml:"snmpd,omitempty"`
	Rrd          Rrd          `json:"rrd"          yaml:"rrd,omitempty"`
	LoadBalancer LoadBalancer `json:"loadBalancer" yaml:"loadBalancer,omitempty"`
	Ntpd         Ntpd         `json:"ntpd"         yaml:"ntpd,omitempty"`
}

// Unbound represents the Unbound DNS resolver configuration.
type Unbound struct {
	Enable         string `xml:"enable"                   json:"enable"                   yaml:"enable"`
	Dnssec         string `xml:"dnssec,omitempty"         json:"dnssec,omitempty"         yaml:"dnssec,omitempty"`
	Dnssecstripped string `xml:"dnssecstripped,omitempty" json:"dnssecstripped,omitempty" yaml:"dnssecstripped,omitempty"`
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
	Path   string `xml:"path,omitempty"`
	Host   string `xml:"host,omitempty"`
	Code   string `xml:"code,omitempty"`
	Send   string `xml:"send,omitempty"`
	Expect string `xml:"expect,omitempty"`
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
	Strict_order       BoolFlag         `xml:"strict_order,omitempty"`       //nolint:revive,staticcheck // XML field name requires underscore
	Domain_needed      BoolFlag         `xml:"domain_needed,omitempty"`      //nolint:revive,staticcheck // XML field name requires underscore
	No_private_reverse BoolFlag         `xml:"no_private_reverse,omitempty"` //nolint:revive,staticcheck // XML field name requires underscore
	Forwarders         []ForwarderGroup `xml:"forwarders,omitempty"`
	Custom_options     string           `xml:"custom_options,omitempty"` //nolint:revive,staticcheck // XML field name requires underscore
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

// ForwarderGroup represents a DNS forwarder group configuration.
type ForwarderGroup struct {
	XMLName xml.Name `xml:"forwarder"`
	IP      string   `xml:"ip,omitempty"`
	Port    string   `xml:"port,omitempty"`
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

// Monit represents system monitoring configuration.
type Monit struct {
	XMLName xml.Name `xml:"monit"`
	Text    string   `xml:",chardata"    json:"text,omitempty"`
	Version string   `xml:"version,attr" json:"version,omitempty"`
	General struct {
		Text                      string `xml:",chardata" json:"text,omitempty"`
		Enabled                   string `xml:"enabled"`
		Interval                  string `xml:"interval"`
		Startdelay                string `xml:"startdelay"`
		Mailserver                string `xml:"mailserver"`
		Port                      string `xml:"port"`
		Username                  string `xml:"username"`
		Password                  string `xml:"password"`
		Ssl                       string `xml:"ssl"`
		Sslversion                string `xml:"sslversion"`
		Sslverify                 string `xml:"sslverify"`
		Logfile                   string `xml:"logfile"`
		Statefile                 string `xml:"statefile"`
		EventqueuePath            string `xml:"eventqueuePath"`
		EventqueueSlots           string `xml:"eventqueueSlots"`
		HttpdEnabled              string `xml:"httpdEnabled"`
		HttpdUsername             string `xml:"httpdUsername"`
		HttpdPassword             string `xml:"httpdPassword"`
		HttpdPort                 string `xml:"httpdPort"`
		HttpdAllow                string `xml:"httpdAllow"`
		MmonitURL                 string `xml:"mmonitUrl"`
		MmonitTimeout             string `xml:"mmonitTimeout"`
		MmonitRegisterCredentials string `xml:"mmonitRegisterCredentials"`
	} `xml:"general"      json:"general"`
	Alert struct {
		Text        string `xml:",chardata" json:"text,omitempty"`
		UUID        string `xml:"uuid,attr" json:"uuid,omitempty"`
		Enabled     string `xml:"enabled"`
		Recipient   string `xml:"recipient"`
		Noton       string `xml:"noton"`
		Events      string `xml:"events"`
		Format      string `xml:"format"`
		Reminder    string `xml:"reminder"`
		Description string `xml:"description"`
	} `xml:"alert"        json:"alert"`
	Service []MonitService `xml:"service"      json:"service,omitempty"`
	Test    []MonitTest    `xml:"test"         json:"test,omitempty"`
}

// MonitService represents a monitored service.
type MonitService struct {
	Text         string `xml:",chardata"    json:"text,omitempty"`
	UUID         string `xml:"uuid,attr"    json:"uuid,omitempty"`
	Enabled      string `xml:"enabled"`
	Name         string `xml:"name"`
	Description  string `xml:"description"`
	Type         string `xml:"type"`
	Pidfile      string `xml:"pidfile"`
	Match        string `xml:"match"`
	Path         string `xml:"path"`
	Timeout      string `xml:"timeout"`
	Starttimeout string `xml:"starttimeout"`
	Address      string `xml:"address"`
	Interface    string `xml:"interface"`
	Start        string `xml:"start"`
	Stop         string `xml:"stop"`
	Tests        string `xml:"tests"`
	Depends      string `xml:"depends"`
	Polltime     string `xml:"polltime"`
}

// MonitTest represents a monitoring test.
type MonitTest struct {
	Text      string `xml:",chardata" json:"text,omitempty"`
	UUID      string `xml:"uuid,attr" json:"uuid,omitempty"`
	Name      string `xml:"name"`
	Type      string `xml:"type"`
	Condition string `xml:"condition"`
	Action    string `xml:"action"`
	Path      string `xml:"path"`
}

// Constructor functions

// NewDNSMasq returns a new DNSMasq configuration with initialized empty slices for hosts, forwarders, and domain overrides.
func NewDNSMasq() *DNSMasq {
	return &DNSMasq{
		Forwarders:      make([]ForwarderGroup, 0),
		Hosts:           make([]DNSMasqHost, 0),
		DomainOverrides: make([]DomainOverride, 0),
	}
}

// NewDNSMasqHost returns a DNSMasqHost instance with an initialized empty Aliases slice.
func NewDNSMasqHost() DNSMasqHost {
	return DNSMasqHost{
		Aliases: make([]string, 0),
	}
}

// NewSyslog returns a pointer to a new Syslog configuration with an initialized empty Reverse slice.
func NewSyslog() *Syslog {
	return &Syslog{
		Reverse: make([]string, 0),
	}
}

// NewMonit returns a pointer to a new Monit configuration with initialized empty slices for services and tests.
func NewMonit() *Monit {
	return &Monit{
		Service: make([]MonitService, 0),
		Test:    make([]MonitTest, 0),
	}
}
