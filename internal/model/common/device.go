// Package common provides platform-agnostic domain structs for representing
// firewall device configurations. These types normalize XML-specific quirks
// (presence-based booleans, *string pointers, map-keyed collections) into
// clean Go types suitable for analysis, reporting, and multi-device support.
package common

import "slices"

// DeviceType identifies the platform that produced a configuration.
type DeviceType string

const (
	// DeviceTypeOPNsense represents an OPNsense device.
	DeviceTypeOPNsense DeviceType = "opnsense"
	// DeviceTypePfSense represents a pfSense device.
	DeviceTypePfSense DeviceType = "pfsense"
	// DeviceTypeUnknown represents an unrecognized device type.
	DeviceTypeUnknown DeviceType = ""
)

// CommonDevice is the platform-agnostic root struct for a firewall device
// configuration. All downstream consumers (processor, builder, plugins, diff
// engine) operate against this type rather than XML-shaped DTOs.
//
//nolint:revive // CommonDevice is the canonical name established by the architecture spec
type CommonDevice struct {
	// DeviceType identifies the platform (OPNsense, pfSense, etc.) that produced this configuration.
	DeviceType DeviceType `json:"device_type" yaml:"device_type"`
	// Version is the firmware or configuration version string.
	Version string `json:"version,omitempty" yaml:"version,omitempty"`
	// Theme is the web GUI theme name.
	Theme string `json:"theme,omitempty" yaml:"theme,omitempty"`

	// System contains system-level settings such as hostname, DNS, and web GUI configuration.
	System System `json:"system" yaml:"system,omitempty"`
	// Interfaces contains all configured network interfaces.
	Interfaces []Interface `json:"interfaces,omitempty" yaml:"interfaces,omitempty"`
	// VLANs contains VLAN configurations.
	VLANs []VLAN `json:"vlans,omitempty" yaml:"vlans,omitempty"`
	// Bridges contains network bridge configurations.
	Bridges []Bridge `json:"bridges,omitempty" yaml:"bridges,omitempty"`
	// PPPs contains point-to-point protocol connection configurations.
	PPPs []PPP `json:"ppps,omitempty" yaml:"ppps,omitempty"`
	// GIFs contains GIF (Generic Tunneling Interface) tunnel configurations.
	GIFs []GIF `json:"gifs,omitempty" yaml:"gifs,omitempty"`
	// GREs contains GRE (Generic Routing Encapsulation) tunnel configurations.
	GREs []GRE `json:"gres,omitempty" yaml:"gres,omitempty"`
	// LAGGs contains link aggregation (LACP/failover) configurations.
	LAGGs []LAGG `json:"laggs,omitempty" yaml:"laggs,omitempty"`
	// VirtualIPs contains CARP, IP alias, and other virtual IP configurations.
	VirtualIPs []VirtualIP `json:"virtualIps,omitempty" yaml:"virtualIps,omitempty"`
	// InterfaceGroups contains logical groupings of interfaces.
	InterfaceGroups []InterfaceGroups `json:"interfaceGroups,omitempty" yaml:"interfaceGroups,omitempty"`
	// FirewallRules contains normalized firewall filter rules.
	FirewallRules []FirewallRule `json:"firewallRules,omitempty" yaml:"firewallRules,omitempty"`
	// NAT contains all NAT-related configuration including inbound and outbound rules.
	NAT NATConfig `json:"nat" yaml:"nat,omitempty"`
	// DHCP contains DHCP server scopes, one per interface.
	DHCP []DHCPScope `json:"dhcp,omitempty" yaml:"dhcp,omitempty"`
	// DNS contains aggregated DNS resolver and forwarder configuration.
	DNS DNSConfig `json:"dns" yaml:"dns,omitempty"`
	// NTP contains NTP time synchronization settings.
	NTP NTPConfig `json:"ntp" yaml:"ntp,omitempty"`
	// SNMP contains SNMP service configuration.
	SNMP SNMPConfig `json:"snmp" yaml:"snmp,omitempty"`
	// LoadBalancer contains load balancer and health monitor configuration.
	LoadBalancer LoadBalancerConfig `json:"loadBalancer" yaml:"loadBalancer,omitempty"`
	// VPN contains all VPN subsystem configurations (OpenVPN, WireGuard, IPsec).
	VPN VPN `json:"vpn" yaml:"vpn,omitempty"`
	// Routing contains gateways, gateway groups, and static routes.
	Routing Routing `json:"routing" yaml:"routing,omitempty"`
	// Certificates contains TLS/SSL certificates.
	Certificates []Certificate `json:"certificates,omitempty" yaml:"certificates,omitempty"`
	// CAs contains certificate authorities.
	CAs []CertificateAuthority `json:"cas,omitempty" yaml:"cas,omitempty"`
	// HighAvailability contains CARP/pfsync high-availability settings.
	HighAvailability HighAvailability `json:"highAvailability" yaml:"highAvailability,omitempty"`
	// IDS contains intrusion detection/prevention (Suricata) configuration.
	IDS *IDSConfig `json:"ids,omitempty" yaml:"ids,omitempty"`
	// Syslog contains remote syslog forwarding configuration.
	Syslog SyslogConfig `json:"syslog" yaml:"syslog,omitempty"`
	// Users contains system user accounts.
	Users []User `json:"users,omitempty" yaml:"users,omitempty"`
	// Groups contains system groups.
	Groups []Group `json:"groups,omitempty" yaml:"groups,omitempty"`
	// Sysctl contains kernel tunable parameters.
	Sysctl []SysctlItem `json:"sysctl,omitempty" yaml:"sysctl,omitempty"`
	// Packages contains installed or available software packages.
	Packages []Package `json:"packages,omitempty" yaml:"packages,omitempty"`
	// Revision contains configuration revision metadata.
	Revision Revision `json:"revision" yaml:"revision,omitempty"`

	// Computed/enrichment fields — populated by prepareForExport in the converter
	// package for JSON/YAML exports. Not set by the parser or converter directly.

	// Statistics contains calculated statistics about the device configuration.
	Statistics *Statistics `json:"statistics,omitempty" yaml:"statistics,omitempty"`
	// Analysis contains analysis findings and insights.
	Analysis *Analysis `json:"analysis,omitempty" yaml:"analysis,omitempty"`
	// SecurityAssessment contains security assessment scores and recommendations.
	SecurityAssessment *SecurityAssessment `json:"securityAssessment,omitempty" yaml:"securityAssessment,omitempty"`
	// PerformanceMetrics contains performance-related metrics.
	PerformanceMetrics *PerformanceMetrics `json:"performanceMetrics,omitempty" yaml:"performanceMetrics,omitempty"`
	// ComplianceChecks contains compliance check results.
	ComplianceChecks *ComplianceChecks `json:"complianceChecks,omitempty" yaml:"complianceChecks,omitempty"`
}

// NATSummary returns a convenience view of the device's NAT configuration.
// Slice fields are cloned to prevent callers from mutating the original device.
// Returns a zero-value NATSummary if d is nil.
func (d *CommonDevice) NATSummary() NATSummary {
	if d == nil {
		return NATSummary{}
	}

	return NATSummary{
		Mode:               d.NAT.OutboundMode,
		ReflectionDisabled: d.NAT.ReflectionDisabled,
		PfShareForward:     d.NAT.PfShareForward,
		OutboundRules:      slices.Clone(d.NAT.OutboundRules),
		InboundRules:       slices.Clone(d.NAT.InboundRules),
	}
}
