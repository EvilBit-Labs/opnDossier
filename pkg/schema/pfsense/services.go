// Package pfsense defines the data structures for pfSense configurations.
package pfsense

import (
	opnsense "github.com/EvilBit-Labs/opnDossier/pkg/schema/opnsense"
)

// SyslogConfig represents the pfSense syslog configuration.
// It differs from OPNsense by including a filterdescriptions field.
type SyslogConfig struct {
	FilterDescriptions string `xml:"filterdescriptions,omitempty" json:"filterDescriptions,omitempty" yaml:"filterDescriptions,omitempty"`
}

// UnboundConfig represents the pfSense Unbound DNS resolver configuration.
// It includes more fields than the OPNsense Unbound type, covering interface
// bindings, security options, and port configuration.
type UnboundConfig struct {
	Enable                    opnsense.BoolFlag `xml:"enable,omitempty"                        json:"enable"                              yaml:"enable,omitempty"`
	DNSSEC                    opnsense.BoolFlag `xml:"dnssec,omitempty"                        json:"dnssec"                              yaml:"dnssec,omitempty"`
	ActiveInterface           string            `xml:"active_interface,omitempty"              json:"activeInterface,omitempty"           yaml:"activeInterface,omitempty"`
	OutgoingInterface         string            `xml:"outgoing_interface,omitempty"            json:"outgoingInterface,omitempty"         yaml:"outgoingInterface,omitempty"`
	CustomOptions             string            `xml:"custom_options,omitempty"                json:"customOptions,omitempty"             yaml:"customOptions,omitempty"`
	HideIdentity              opnsense.BoolFlag `xml:"hideidentity,omitempty"                  json:"hideIdentity"                        yaml:"hideIdentity,omitempty"`
	HideVersion               opnsense.BoolFlag `xml:"hideversion,omitempty"                   json:"hideVersion"                         yaml:"hideVersion,omitempty"`
	DNSSECStripped            opnsense.BoolFlag `xml:"dnssecstripped,omitempty"                json:"dnssecStripped"                      yaml:"dnssecStripped,omitempty"`
	Port                      string            `xml:"port,omitempty"                          json:"port,omitempty"                      yaml:"port,omitempty"`
	SSLPort                   string            `xml:"sslport,omitempty"                       json:"sslPort,omitempty"                   yaml:"sslPort,omitempty"`
	SSLCertRef                string            `xml:"sslcertref,omitempty"                    json:"sslCertRef,omitempty"                yaml:"sslCertRef,omitempty"`
	SystemDomainLocalZoneType string            `xml:"system_domain_local_zone_type,omitempty" json:"systemDomainLocalZoneType,omitempty" yaml:"systemDomainLocalZoneType,omitempty"`
}

// Widgets represents the pfSense dashboard widgets configuration.
// It extends the OPNsense Widgets with a pfSense-specific refresh period field.
type Widgets struct {
	Sequence    string `xml:"sequence,omitempty"     json:"sequence,omitempty"    yaml:"sequence,omitempty"`
	ColumnCount string `xml:"column_count,omitempty" json:"columnCount,omitempty" yaml:"columnCount,omitempty"`
	Period      string `xml:"period,omitempty"       json:"period,omitempty"      yaml:"period,omitempty"`
}

// Cron represents the pfSense cron configuration.
type Cron struct {
	Items []CronItem `xml:"item,omitempty" json:"items,omitempty" yaml:"items,omitempty"`
}

// CronItem represents a single pfSense cron job entry.
type CronItem struct {
	Minute  string `xml:"minute"  json:"minute"  yaml:"minute"`
	Hour    string `xml:"hour"    json:"hour"    yaml:"hour"`
	MDay    string `xml:"mday"    json:"mday"    yaml:"mday"`
	Month   string `xml:"month"   json:"month"   yaml:"month"`
	WDay    string `xml:"wday"    json:"wday"    yaml:"wday"`
	Who     string `xml:"who"     json:"who"     yaml:"who"`
	Command string `xml:"command" json:"command" yaml:"command"`
}

// Diag represents the pfSense diagnostics configuration.
type Diag struct {
	IPv6NAT IPv6NAT `xml:"ipv6nat,omitempty" json:"ipv6nat" yaml:"ipv6nat,omitempty"`
}

// IPv6NAT represents the pfSense IPv6 NAT diagnostics configuration.
type IPv6NAT struct {
	IPAddr string `xml:"ipaddr,omitempty" json:"ipaddr,omitempty" yaml:"ipaddr,omitempty"`
}
