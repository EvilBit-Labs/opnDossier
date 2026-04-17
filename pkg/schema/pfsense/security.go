// Package pfsense defines the XML schema types for pfSense configuration files.
package pfsense

import (
	"encoding/xml"

	opnsense "github.com/EvilBit-Labs/opnDossier/pkg/schema/opnsense"
)

// Nat represents the pfSense NAT configuration.
// The key structural difference from OPNsense is that inbound (port-forward) rules
// are direct children of <nat> rather than nested under <nat><inbound>.
type Nat struct {
	Outbound  opnsense.Outbound `xml:"outbound"            json:"outbound"            yaml:"outbound"`
	Inbound   []InboundRule     `xml:"rule"                json:"inbound,omitempty"   yaml:"inbound,omitempty"`
	Separator string            `xml:"separator,omitempty" json:"separator,omitempty" yaml:"separator,omitempty"`
}

// InboundRule represents a pfSense inbound NAT rule (port forwarding).
// This is a copy-on-write fork of opnsense.InboundRule because pfSense uses a
// <target> element for the internal redirect IP, whereas OPNsense uses <internalip>.
type InboundRule struct {
	XMLName          xml.Name               `xml:"rule"`
	Interface        opnsense.InterfaceList `xml:"interface,omitempty"          json:"interface,omitempty"        yaml:"interface,omitempty"`
	IPProtocol       string                 `xml:"ipprotocol,omitempty"         json:"ipProtocol,omitempty"       yaml:"ipProtocol,omitempty"`
	Protocol         string                 `xml:"protocol,omitempty"           json:"protocol,omitempty"         yaml:"protocol,omitempty"`
	Source           opnsense.Source        `xml:"source"                       json:"source"                     yaml:"source"`
	Destination      opnsense.Destination   `xml:"destination"                  json:"destination"                yaml:"destination"`
	ExternalPort     string                 `xml:"externalport,omitempty"       json:"externalPort,omitempty"     yaml:"externalPort,omitempty"`
	Target           string                 `xml:"target,omitempty"             json:"target,omitempty"           yaml:"target,omitempty"`
	InternalIP       string                 `xml:"internalip,omitempty"         json:"internalIP,omitempty"       yaml:"internalIP,omitempty"`
	InternalPort     string                 `xml:"internalport,omitempty"       json:"internalPort,omitempty"     yaml:"internalPort,omitempty"`
	LocalPort        string                 `xml:"local-port,omitempty"         json:"localPort,omitempty"        yaml:"localPort,omitempty"`
	Reflection       string                 `xml:"reflection,omitempty"         json:"reflection,omitempty"       yaml:"reflection,omitempty"`
	NATReflection    string                 `xml:"natreflection,omitempty"      json:"natReflection,omitempty"    yaml:"natReflection,omitempty"`
	AssociatedRuleID string                 `xml:"associated-rule-id,omitempty" json:"associatedRuleID,omitempty" yaml:"associatedRuleID,omitempty"`
	Priority         int                    `xml:"priority,omitempty"           json:"priority,omitempty"         yaml:"priority,omitempty"`
	NoRDR            opnsense.BoolFlag      `xml:"nordr,omitempty"              json:"noRDR,omitempty"            yaml:"noRDR,omitempty"`
	NoSync           opnsense.BoolFlag      `xml:"nosync,omitempty"             json:"noSync,omitempty"           yaml:"noSync,omitempty"`
	Disabled         opnsense.BoolFlag      `xml:"disabled,omitempty"           json:"disabled,omitempty"         yaml:"disabled,omitempty"`
	Log              opnsense.BoolFlag      `xml:"log,omitempty"                json:"log,omitempty"              yaml:"log,omitempty"`
	Descr            string                 `xml:"descr,omitempty"              json:"description,omitempty"      yaml:"description,omitempty"`
	Updated          *opnsense.Updated      `xml:"updated,omitempty"            json:"updated,omitempty"          yaml:"updated,omitempty"`
	Created          *opnsense.Created      `xml:"created,omitempty"            json:"created,omitempty"          yaml:"created,omitempty"`
	UUID             string                 `xml:"uuid,attr,omitempty"          json:"uuid,omitempty"             yaml:"uuid,omitempty"`
}

// Filter represents the pfSense firewall filter configuration.
// It maps to the <filter> XML element and contains an ordered list of firewall rules.
type Filter struct {
	Separator string       `xml:"separator,omitempty" json:"separator,omitempty" yaml:"separator,omitempty"`
	Rule      []FilterRule `xml:"rule"                json:"rules,omitempty"     yaml:"rules,omitempty"`
}

// FilterRule represents a pfSense firewall rule.
// It extends the base OPNsense Rule fields with pfSense-specific attributes
// such as rule ID, pf tags, state limits, OS fingerprinting, and NAT association.
type FilterRule struct {
	XMLName     xml.Name               `xml:"rule"`
	Type        string                 `xml:"type"                 json:"type"                  yaml:"type"`
	Descr       string                 `xml:"descr,omitempty"      json:"description,omitempty" yaml:"description,omitempty"`
	Interface   opnsense.InterfaceList `xml:"interface,omitempty"  json:"interface,omitempty"   yaml:"interface,omitempty"`
	IPProtocol  string                 `xml:"ipprotocol,omitempty" json:"ipProtocol,omitempty"  yaml:"ipProtocol,omitempty"`
	StateType   string                 `xml:"statetype,omitempty"  json:"stateType,omitempty"   yaml:"stateType,omitempty"`
	Direction   string                 `xml:"direction,omitempty"  json:"direction,omitempty"   yaml:"direction,omitempty"`
	Floating    string                 `xml:"floating,omitempty"   json:"floating,omitempty"    yaml:"floating,omitempty"`
	Quick       opnsense.BoolFlag      `xml:"quick,omitempty"      json:"quick"                 yaml:"quick,omitempty"`
	Protocol    string                 `xml:"protocol,omitempty"   json:"protocol,omitempty"    yaml:"protocol,omitempty"`
	Source      opnsense.Source        `xml:"source"               json:"source"                yaml:"source"`
	Destination opnsense.Destination   `xml:"destination"          json:"destination"           yaml:"destination"`
	Target      string                 `xml:"target,omitempty"     json:"target,omitempty"      yaml:"target,omitempty"`
	Gateway     string                 `xml:"gateway,omitempty"    json:"gateway,omitempty"     yaml:"gateway,omitempty"`
	SourcePort  string                 `xml:"sourceport,omitempty" json:"sourcePort,omitempty"  yaml:"sourcePort,omitempty"`
	Log         opnsense.BoolFlag      `xml:"log,omitempty"        json:"log"                   yaml:"log,omitempty"`
	Disabled    opnsense.BoolFlag      `xml:"disabled,omitempty"   json:"disabled"              yaml:"disabled,omitempty"`
	Tracker     string                 `xml:"tracker,omitempty"    json:"tracker,omitempty"     yaml:"tracker,omitempty"`
	// Rate-limiting fields (DoS protection)
	MaxSrcNodes     string `xml:"max-src-nodes,omitempty"      json:"maxSrcNodes,omitempty"     yaml:"maxSrcNodes,omitempty"`
	MaxSrcConn      string `xml:"max-src-conn,omitempty"       json:"maxSrcConn,omitempty"      yaml:"maxSrcConn,omitempty"`
	MaxSrcConnRate  string `xml:"max-src-conn-rate,omitempty"  json:"maxSrcConnRate,omitempty"  yaml:"maxSrcConnRate,omitempty"`
	MaxSrcConnRates string `xml:"max-src-conn-rates,omitempty" json:"maxSrcConnRates,omitempty" yaml:"maxSrcConnRates,omitempty"`
	// TCP/ICMP fields
	TCPFlags1   string            `xml:"tcpflags1,omitempty"    json:"tcpFlags1,omitempty" yaml:"tcpFlags1,omitempty"`
	TCPFlags2   string            `xml:"tcpflags2,omitempty"    json:"tcpFlags2,omitempty" yaml:"tcpFlags2,omitempty"`
	TCPFlagsAny opnsense.BoolFlag `xml:"tcpflags_any,omitempty" json:"tcpFlagsAny"         yaml:"tcpFlagsAny,omitempty"`
	ICMPType    string            `xml:"icmptype,omitempty"     json:"icmpType,omitempty"  yaml:"icmpType,omitempty"`
	ICMP6Type   string            `xml:"icmp6-type,omitempty"   json:"icmp6Type,omitempty" yaml:"icmp6Type,omitempty"`
	// State and advanced fields
	StateTimeout   string            `xml:"statetimeout,omitempty"   json:"stateTimeout,omitempty" yaml:"stateTimeout,omitempty"`
	AllowOpts      opnsense.BoolFlag `xml:"allowopts,omitempty"      json:"allowOpts"              yaml:"allowOpts,omitempty"`
	DisableReplyTo opnsense.BoolFlag `xml:"disablereplyto,omitempty" json:"disableReplyTo"         yaml:"disableReplyTo,omitempty"`
	NoPfSync       opnsense.BoolFlag `xml:"nopfsync,omitempty"       json:"noPfSync"               yaml:"noPfSync,omitempty"`
	NoSync         opnsense.BoolFlag `xml:"nosync,omitempty"         json:"noSync"                 yaml:"noSync,omitempty"`
	Updated        *opnsense.Updated `xml:"updated,omitempty"        json:"updated,omitempty"      yaml:"updated,omitempty"`
	Created        *opnsense.Created `xml:"created,omitempty"        json:"created,omitempty"      yaml:"created,omitempty"`
	UUID           string            `xml:"uuid,attr,omitempty"      json:"uuid,omitempty"         yaml:"uuid,omitempty"`
	// pfSense-specific fields
	ID               string `xml:"id,omitempty"                 json:"id,omitempty"               yaml:"id,omitempty"`
	Tag              string `xml:"tag,omitempty"                json:"tag,omitempty"              yaml:"tag,omitempty"`
	Tagged           string `xml:"tagged,omitempty"             json:"tagged,omitempty"           yaml:"tagged,omitempty"`
	Max              string `xml:"max,omitempty"                json:"max,omitempty"              yaml:"max,omitempty"`
	MaxSrcStates     string `xml:"max-src-states,omitempty"     json:"maxSrcStates,omitempty"     yaml:"maxSrcStates,omitempty"`
	OS               string `xml:"os,omitempty"                 json:"os,omitempty"               yaml:"os,omitempty"`
	AssociatedRuleID string `xml:"associated-rule-id,omitempty" json:"associatedRuleID,omitempty" yaml:"associatedRuleID,omitempty"`
}
