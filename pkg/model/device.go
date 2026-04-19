// Package model provides platform-agnostic domain structs for representing
// firewall device configurations. These types normalize XML-specific quirks
// (presence-based booleans, *string pointers, map-keyed collections) into
// clean Go types suitable for analysis, reporting, and multi-device support.
package model

import (
	"slices"
	"strings"
)

// DeviceType identifies the platform that produced a configuration.
type DeviceType string

// Recognized device type constants used to identify the platform that produced a configuration.
const (
	// DeviceTypeOPNsense represents an OPNsense device.
	DeviceTypeOPNsense DeviceType = "opnsense"
	// DeviceTypePfSense represents a pfSense device.
	DeviceTypePfSense DeviceType = "pfsense"
	// DeviceTypeUnknown represents an unrecognized device type.
	DeviceTypeUnknown DeviceType = ""
)

// IsValid reports whether d is a recognized, non-empty device type.
func (d DeviceType) IsValid() bool {
	switch d {
	case DeviceTypeOPNsense, DeviceTypePfSense:
		return true
	default:
		return false
	}
}

// String returns the string representation of the DeviceType.
func (d DeviceType) String() string {
	return string(d)
}

// DisplayName returns the human-readable, properly-cased platform name
// for use in report titles and UI labels (e.g. "OPNsense", "pfSense").
// Unrecognized or empty values return "Device" as a generic fallback.
func (d DeviceType) DisplayName() string {
	switch d {
	case DeviceTypeOPNsense:
		return "OPNsense"
	case DeviceTypePfSense:
		return "pfSense"
	default:
		return "Device"
	}
}

// ParseDeviceType normalizes a raw string into a recognized DeviceType.
// Unrecognized values return DeviceTypeUnknown.
func ParseDeviceType(s string) DeviceType {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "opnsense":
		return DeviceTypeOPNsense
	case "pfsense":
		return DeviceTypePfSense
	default:
		return DeviceTypeUnknown
	}
}

// CommonDevice is the platform-agnostic device model. It flows through
// the following pipeline stages:
//
//	device config file (XML) -> xml.Unmarshal -> vendor DTO
//	  -> parser / converter -> CommonDevice
//	  -> enrichment (statistics, compliance results, etc.)
//	  -> redact / sanitize
//	  -> reporting (JSON / YAML / markdown / etc.)
//
// Fields are partitioned into two groups:
//
//   - Parser-populated: set by the parser/converter stage from the
//     vendor DTO. These reflect the original configuration.
//   - Enrichment-populated: set by a later pipeline stage (currently
//     prepareForExport) for JSON/YAML exports. Not set by the parser
//     or converter.
//
// Parsers produce CommonDevice values by converting platform-specific XML
// schemas (OPNsense, pfSense) into this normalized form. All downstream
// consumers (processor, builder, plugins, diff engine, JSON/YAML exporters)
// operate against this type rather than XML-shaped DTOs.
//
// Has* methods report whether specific configuration sections are populated,
// and NATSummary returns a convenience snapshot of NAT configuration with
// cloned slices to prevent mutation of the original device.
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
	// GIFs contains gif (generic tunnel interface) configurations.
	GIFs []GIF `json:"gifs,omitempty" yaml:"gifs,omitempty"`
	// GREs contains GRE (Generic Routing Encapsulation) tunnel configurations.
	GREs []GRE `json:"gres,omitempty" yaml:"gres,omitempty"`
	// LAGGs contains link aggregation (LACP/failover) configurations.
	LAGGs []LAGG `json:"laggs,omitempty" yaml:"laggs,omitempty"`
	// VirtualIPs contains CARP, IP alias, and other virtual IP configurations.
	VirtualIPs []VirtualIP `json:"virtualIps,omitempty" yaml:"virtualIps,omitempty"`
	// InterfaceGroups contains logical groupings of interfaces.
	InterfaceGroups []InterfaceGroup `json:"interfaceGroups,omitempty" yaml:"interfaceGroups,omitempty"`
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
	// Monit contains process monitoring (Monit) configuration.
	Monit *MonitConfig `json:"monit,omitempty" yaml:"monit,omitempty"`
	// Netflow contains NetFlow/IPFIX traffic accounting configuration.
	Netflow *NetflowConfig `json:"netflow,omitempty" yaml:"netflow,omitempty"`
	// TrafficShaper contains QoS/traffic shaping configuration.
	TrafficShaper *TrafficShaperConfig `json:"trafficShaper,omitempty" yaml:"trafficShaper,omitempty"`
	// CaptivePortal contains captive portal configuration.
	CaptivePortal *CaptivePortalConfig `json:"captivePortal,omitempty" yaml:"captivePortal,omitempty"`
	// Cron contains scheduled task configuration.
	Cron *CronConfig `json:"cron,omitempty" yaml:"cron,omitempty"`
	// Trust contains system-wide TLS and certificate trust settings.
	Trust *TrustConfig `json:"trust,omitempty" yaml:"trust,omitempty"`
	// KeaDHCP contains Kea DHCP server configuration (modern DHCP replacement).
	KeaDHCP *KeaDHCPConfig `json:"keaDhcp,omitempty" yaml:"keaDhcp,omitempty"`
	// Revision contains configuration revision metadata.
	Revision Revision `json:"revision" yaml:"revision,omitempty"`

	// --- Enrichment-populated fields below ---
	// The fields below are populated by prepareForExport in the converter
	// package for JSON/YAML exports, or by the audit handler for compliance
	// results. They are not set by the parser or converter stage directly.

	// Statistics contains calculated statistics about the device configuration.
	Statistics *Statistics `json:"statistics,omitempty" yaml:"statistics,omitempty"`
	// Analysis contains analysis findings and insights.
	Analysis *Analysis `json:"analysis,omitempty" yaml:"analysis,omitempty"`
	// SecurityAssessment contains security assessment scores and recommendations.
	SecurityAssessment *SecurityAssessment `json:"securityAssessment,omitempty" yaml:"securityAssessment,omitempty"`
	// PerformanceMetrics contains performance-related metrics.
	PerformanceMetrics *PerformanceMetrics `json:"performanceMetrics,omitempty" yaml:"performanceMetrics,omitempty"`
	// ComplianceResults contains compliance audit results from plugin-based checks.
	ComplianceResults *ComplianceResults `json:"complianceResults,omitempty" yaml:"complianceResults,omitempty"`
}

// HasDHCP reports whether the device has any DHCP configuration.
// Both ISC and Kea DHCP scopes are normalized into the unified DHCP slice.
// Returns false if d is nil.
func (d *CommonDevice) HasDHCP() bool {
	if d == nil {
		return false
	}
	return len(d.DHCP) > 0
}

// HasInterfaces reports whether the device has any interface configuration.
// Returns false if d is nil.
func (d *CommonDevice) HasInterfaces() bool {
	if d == nil {
		return false
	}
	return len(d.Interfaces) > 0
}

// HasNATConfig reports whether the device has meaningful NAT configuration
// (any non-zero fields in the NAT struct).
// Returns false if d is nil.
func (d *CommonDevice) HasNATConfig() bool {
	if d == nil {
		return false
	}
	return d.NAT.HasData()
}

// HasRoutes reports whether the device has any routing configuration
// (static routes, gateways, or gateway groups).
// Returns false if d is nil.
func (d *CommonDevice) HasRoutes() bool {
	if d == nil {
		return false
	}
	return len(d.Routing.StaticRoutes) > 0 ||
		len(d.Routing.Gateways) > 0 ||
		len(d.Routing.GatewayGroups) > 0
}

// HasVLANs reports whether the device has any VLAN configuration.
// Returns false if d is nil.
func (d *CommonDevice) HasVLANs() bool {
	if d == nil {
		return false
	}
	return len(d.VLANs) > 0
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
