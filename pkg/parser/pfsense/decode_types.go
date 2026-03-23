// Package pfsense provides a pfSense-specific parser and converter that
// transforms pfsense.Document into the platform-agnostic CommonDevice.
package pfsense

import (
	"encoding/xml"

	opnsense "github.com/EvilBit-Labs/opnDossier/pkg/schema/opnsense"
	pfsenseSchema "github.com/EvilBit-Labs/opnDossier/pkg/schema/pfsense"
)

// enabledValue is the canonical string representation of a presence-based
// enabled flag after BoolFlag→string conversion. isPfSenseValueTrue("1") == true.
const enabledValue = "1"

// decodeDocument is a parser-local intermediate type for XML decode that uses
// BoolFlag-aware types for Interfaces and Dhcpd. This keeps pfsense.Document's
// exported API backward-compatible (opnsense.Interfaces/opnsense.Dhcpd) while
// correctly decoding pfSense presence-based <enable/> elements.
type decodeDocument struct {
	XMLName      xml.Name                        `xml:"pfsense"`
	Version      string                          `xml:"version,omitempty"`
	LastChange   string                          `xml:"lastchange,omitempty"`
	System       pfsenseSchema.System            `xml:"system,omitempty"`
	Interfaces   pfsenseSchema.Interfaces        `xml:"interfaces,omitempty"`
	Dhcpd        pfsenseSchema.Dhcpd             `xml:"dhcpd,omitempty"`
	DHCPv6Server pfsenseSchema.DHCPv6            `xml:"dhcpdv6,omitempty"`
	Snmpd        opnsense.Snmpd                  `xml:"snmpd,omitempty"`
	Diag         pfsenseSchema.Diag              `xml:"diag,omitempty"`
	Syslog       pfsenseSchema.SyslogConfig      `xml:"syslog,omitempty"`
	Nat          pfsenseSchema.Nat               `xml:"nat,omitempty"`
	Filter       pfsenseSchema.Filter            `xml:"filter,omitempty"`
	Cron         pfsenseSchema.Cron              `xml:"cron,omitempty"`
	Rrd          opnsense.Rrd                    `xml:"rrd,omitempty"`
	LoadBalancer opnsense.LoadBalancer           `xml:"load_balancer,omitempty"`
	Widgets      pfsenseSchema.Widgets           `xml:"widgets,omitempty"`
	OpenVPN      opnsense.OpenVPN                `xml:"openvpn,omitempty"`
	Unbound      pfsenseSchema.UnboundConfig     `xml:"unbound,omitempty"`
	Revision     opnsense.Revision               `xml:"revision,omitempty"`
	StaticRoutes opnsense.StaticRoutes           `xml:"staticroutes,omitempty"`
	PPPs         opnsense.PPPInterfaces          `xml:"ppps,omitempty"`
	Gateways     opnsense.Gateways               `xml:"gateways,omitempty"`
	CAs          []opnsense.CertificateAuthority `xml:"ca,omitempty"`
	Certs        []opnsense.Cert                 `xml:"cert,omitempty"`
	VLANs        opnsense.VLANs                  `xml:"vlans,omitempty"`
}

// toDocument converts the decode-only intermediate representation into a
// pfsense.Document with backward-compatible opnsense types. BoolFlag Enable
// values are mapped to "1" (enabled) or "" (disabled) in the opnsense types.
func (dd *decodeDocument) toDocument() *pfsenseSchema.Document {
	return &pfsenseSchema.Document{
		XMLName:      dd.XMLName,
		Version:      dd.Version,
		LastChange:   dd.LastChange,
		System:       dd.System,
		Interfaces:   convertInterfacesToOpnsense(dd.Interfaces),
		Dhcpd:        convertDhcpdToOpnsense(dd.Dhcpd),
		DHCPv6Server: dd.DHCPv6Server,
		Snmpd:        dd.Snmpd,
		Diag:         dd.Diag,
		Syslog:       dd.Syslog,
		Nat:          dd.Nat,
		Filter:       dd.Filter,
		Cron:         dd.Cron,
		Rrd:          dd.Rrd,
		LoadBalancer: dd.LoadBalancer,
		Widgets:      dd.Widgets,
		OpenVPN:      dd.OpenVPN,
		Unbound:      dd.Unbound,
		Revision:     dd.Revision,
		StaticRoutes: dd.StaticRoutes,
		PPPs:         dd.PPPs,
		Gateways:     dd.Gateways,
		CAs:          dd.CAs,
		Certs:        dd.Certs,
		VLANs:        dd.VLANs,
	}
}

// convertInterfacesToOpnsense maps BoolFlag-aware pfsense.Interfaces to
// opnsense.Interfaces, converting Enable from BoolFlag to string.
func convertInterfacesToOpnsense(src pfsenseSchema.Interfaces) opnsense.Interfaces {
	if src.Items == nil {
		return opnsense.Interfaces{}
	}

	items := make(map[string]opnsense.Interface, len(src.Items))
	for key, iface := range src.Items {
		items[key] = convertInterfaceToOpnsense(iface)
	}

	return opnsense.Interfaces{Items: items}
}

// convertInterfaceToOpnsense maps a single pfsense.Interface to opnsense.Interface.
func convertInterfaceToOpnsense(src pfsenseSchema.Interface) opnsense.Interface {
	enable := ""
	if src.Enable.Bool() {
		enable = enabledValue
	}

	return opnsense.Interface{
		Enable:              enable,
		If:                  src.If,
		Descr:               src.Descr,
		Spoofmac:            src.Spoofmac,
		InternalDynamic:     src.InternalDynamic,
		Type:                src.Type,
		Virtual:             src.Virtual,
		Lock:                src.Lock,
		MTU:                 src.MTU,
		IPAddr:              src.IPAddr,
		IPAddrv6:            src.IPAddrv6,
		Subnet:              src.Subnet,
		Subnetv6:            src.Subnetv6,
		Gateway:             src.Gateway,
		Gatewayv6:           src.Gatewayv6,
		BlockPriv:           src.BlockPriv,
		BlockBogons:         src.BlockBogons,
		DHCPHostname:        src.DHCPHostname,
		Media:               src.Media,
		MediaOpt:            src.MediaOpt,
		DHCP6IaPdLen:        src.DHCP6IaPdLen,
		Track6Interface:     src.Track6Interface,
		Track6PrefixID:      src.Track6PrefixID,
		AliasAddress:        src.AliasAddress,
		AliasSubnet:         src.AliasSubnet,
		DHCPRejectFrom:      src.DHCPRejectFrom,
		DDNSDomainAlgorithm: src.DDNSDomainAlgorithm,
		NumberOptions:       src.NumberOptions,
		Range:               src.Range,
		Winsserver:          src.Winsserver,
		Dnsserver:           src.Dnsserver,
		Ntpserver:           src.Ntpserver,

		AdvDHCPRequestOptions:                    src.AdvDHCPRequestOptions,
		AdvDHCPRequiredOptions:                   src.AdvDHCPRequiredOptions,
		AdvDHCP6InterfaceStatementRequestOptions: src.AdvDHCP6InterfaceStatementRequestOptions,
		AdvDHCP6ConfigFileOverride:               src.AdvDHCP6ConfigFileOverride,
		AdvDHCP6IDAssocStatementPrefixPLTime:     src.AdvDHCP6IDAssocStatementPrefixPLTime,
	}
}

// convertDhcpdToOpnsense maps BoolFlag-aware pfsense.Dhcpd to opnsense.Dhcpd,
// converting Enable from BoolFlag to string.
func convertDhcpdToOpnsense(src pfsenseSchema.Dhcpd) opnsense.Dhcpd {
	if src.Items == nil {
		return opnsense.Dhcpd{}
	}

	items := make(map[string]opnsense.DhcpdInterface, len(src.Items))
	for key, d := range src.Items {
		items[key] = convertDhcpdInterfaceToOpnsense(d)
	}

	return opnsense.Dhcpd{Items: items}
}

// convertDhcpdInterfaceToOpnsense maps a single pfsense.DhcpdInterface to opnsense.DhcpdInterface.
func convertDhcpdInterfaceToOpnsense(src pfsenseSchema.DhcpdInterface) opnsense.DhcpdInterface {
	enable := ""
	if src.Enable.Bool() {
		enable = enabledValue
	}

	return opnsense.DhcpdInterface{
		Enable:              enable,
		Range:               src.Range,
		Gateway:             src.Gateway,
		DdnsDomainAlgorithm: src.DdnsDomainAlgorithm,
		NumberOptions:       src.NumberOptions,
		Winsserver:          src.Winsserver,
		Dnsserver:           src.Dnsserver,
		Ntpserver:           src.Ntpserver,
		Staticmap:           src.Staticmap,
	}
}
