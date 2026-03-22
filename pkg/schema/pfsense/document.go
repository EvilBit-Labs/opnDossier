// Package pfsense defines the data structures for pfSense configurations.
package pfsense

import (
	"encoding/xml"

	opnsense "github.com/EvilBit-Labs/opnDossier/pkg/schema/opnsense"
)

// Document is the root of the pfSense configuration.
type Document struct {
	XMLName      xml.Name                        `xml:"pfsense"                 json:"-"                    yaml:"-"`
	Version      string                          `xml:"version,omitempty"       json:"version,omitempty"    yaml:"version,omitempty"`
	LastChange   string                          `xml:"lastchange,omitempty"    json:"lastChange,omitempty" yaml:"lastChange,omitempty"`
	System       System                          `xml:"system,omitempty"        json:"system"               yaml:"system,omitempty"`
	Interfaces   opnsense.Interfaces             `xml:"interfaces,omitempty"    json:"interfaces"           yaml:"interfaces,omitempty"`
	Dhcpd        opnsense.Dhcpd                  `xml:"dhcpd,omitempty"         json:"dhcpd"                yaml:"dhcpd,omitempty"`
	DHCPv6Server DHCPv6                          `xml:"dhcpdv6,omitempty"       json:"dhcpdv6"              yaml:"dhcpdv6,omitempty"`
	Snmpd        opnsense.Snmpd                  `xml:"snmpd,omitempty"         json:"snmpd"                yaml:"snmpd,omitempty"`
	Diag         Diag                            `xml:"diag,omitempty"          json:"diag"                 yaml:"diag,omitempty"`
	Syslog       SyslogConfig                    `xml:"syslog,omitempty"        json:"syslog"               yaml:"syslog,omitempty"`
	Nat          Nat                             `xml:"nat,omitempty"           json:"nat"                  yaml:"nat,omitempty"`
	Filter       Filter                          `xml:"filter,omitempty"        json:"filter"               yaml:"filter,omitempty"`
	Cron         Cron                            `xml:"cron,omitempty"          json:"cron"                 yaml:"cron,omitempty"`
	Rrd          opnsense.Rrd                    `xml:"rrd,omitempty"           json:"rrd"                  yaml:"rrd,omitempty"`
	LoadBalancer opnsense.LoadBalancer           `xml:"load_balancer,omitempty" json:"loadBalancer"         yaml:"loadBalancer,omitempty"`
	Widgets      Widgets                         `xml:"widgets,omitempty"       json:"widgets"              yaml:"widgets,omitempty"`
	OpenVPN      opnsense.OpenVPN                `xml:"openvpn,omitempty"       json:"openvpn"              yaml:"openvpn,omitempty"`
	Unbound      UnboundConfig                   `xml:"unbound,omitempty"       json:"unbound"              yaml:"unbound,omitempty"`
	Revision     opnsense.Revision               `xml:"revision,omitempty"      json:"revision"             yaml:"revision,omitempty"`
	StaticRoutes opnsense.StaticRoutes           `xml:"staticroutes,omitempty"  json:"staticroutes"         yaml:"staticroutes,omitempty"`
	PPPs         opnsense.PPPInterfaces          `xml:"ppps,omitempty"          json:"ppps"                 yaml:"ppps,omitempty"`
	Gateways     opnsense.Gateways               `xml:"gateways,omitempty"      json:"gateways"             yaml:"gateways,omitempty"`
	CAs          []opnsense.CertificateAuthority `xml:"ca,omitempty"            json:"ca,omitempty"         yaml:"ca,omitempty"`
	Certs        []opnsense.Cert                 `xml:"cert,omitempty"          json:"cert,omitempty"       yaml:"cert,omitempty"`
	VLANs        opnsense.VLANs                  `xml:"vlans,omitempty"         json:"vlans"                yaml:"vlans,omitempty"`
}

// NewDocument returns a new Document with all slice and map fields initialized for safe use.
func NewDocument() *Document {
	return &Document{
		System: System{
			Group:      make([]Group, 0),
			User:       make([]User, 0),
			DNSServers: make([]string, 0),
		},
		Interfaces: opnsense.Interfaces{
			Items: make(map[string]opnsense.Interface),
		},
		Dhcpd: opnsense.Dhcpd{
			Items: make(map[string]opnsense.DhcpdInterface),
		},
		DHCPv6Server: DHCPv6{
			Items: make(map[string]DHCPv6Interface),
		},
		Filter: Filter{
			Rule: make([]FilterRule, 0),
		},
		Nat: Nat{
			Outbound: opnsense.Outbound{
				Rule: make([]opnsense.NATRule, 0),
			},
			Inbound: make([]InboundRule, 0),
		},
		LoadBalancer: opnsense.LoadBalancer{
			MonitorType: make([]opnsense.MonitorType, 0),
		},
		Cron: Cron{
			Items: make([]CronItem, 0),
		},
	}
}

// Hostname returns the configured hostname from the system configuration.
func (p *Document) Hostname() string {
	return p.System.Hostname
}

// InterfaceByName returns a network interface by its interface name (e.g., "em0", "igb0").
func (p *Document) InterfaceByName(name string) *opnsense.Interface {
	for _, iface := range p.Interfaces.Items {
		if iface.If == name {
			return &iface
		}
	}

	return nil
}

// FilterRules returns a slice of all firewall filter rules configured in the system.
func (p *Document) FilterRules() []FilterRule {
	return p.Filter.Rule
}
