package common

// RuleEndpoint represents a normalized source or destination in a firewall
// or NAT rule. The Address field contains the already-resolved effective
// address ("any", a CIDR, hostname, or empty string).
type RuleEndpoint struct {
	// Address is the resolved effective address (e.g., "any", a CIDR, or hostname).
	Address string `json:"address,omitempty" yaml:"address,omitempty"`
	// Port is the port or port range specification.
	Port string `json:"port,omitempty" yaml:"port,omitempty"`
	// Negated indicates the endpoint match is inverted (NOT logic).
	Negated bool `json:"negated,omitempty" yaml:"negated,omitempty"`
}

// FirewallRule represents a normalized firewall filter rule.
type FirewallRule struct {
	// UUID is the unique identifier for the rule.
	UUID string `json:"uuid,omitempty" yaml:"uuid,omitempty"`
	// Type is the rule action (e.g., "pass", "block", "reject").
	Type string `json:"type,omitempty" yaml:"type,omitempty"`
	// Description is a human-readable description of the rule.
	Description string `json:"description,omitempty" yaml:"description,omitempty"`
	// Interfaces lists the interface names this rule applies to.
	Interfaces []string `json:"interfaces,omitempty" yaml:"interfaces,omitempty"`
	// IPProtocol is the IP address family (e.g., "inet", "inet6").
	IPProtocol string `json:"ipProtocol,omitempty" yaml:"ipProtocol,omitempty"`
	// StateType is the state tracking type (e.g., "keep state", "sloppy state").
	StateType string `json:"stateType,omitempty" yaml:"stateType,omitempty"`
	// Direction is the traffic direction (e.g., "in", "out", "any").
	Direction string `json:"direction,omitempty" yaml:"direction,omitempty"`
	// Floating indicates this is a floating rule not bound to a specific interface.
	Floating bool `json:"floating,omitempty" yaml:"floating,omitempty"`
	// Quick indicates the rule uses quick matching (first match wins).
	Quick bool `json:"quick,omitempty" yaml:"quick,omitempty"`
	// Protocol is the layer-4 protocol (e.g., "tcp", "udp", "icmp").
	Protocol string `json:"protocol,omitempty" yaml:"protocol,omitempty"`

	// Source is the normalized source endpoint for the rule.
	Source RuleEndpoint `json:"source" yaml:"source,omitempty"`
	// Destination is the normalized destination endpoint for the rule.
	Destination RuleEndpoint `json:"destination" yaml:"destination,omitempty"`

	// Target is the redirect target for NAT-associated rules.
	Target string `json:"target,omitempty" yaml:"target,omitempty"`
	// Gateway is the policy-based routing gateway for the rule.
	Gateway string `json:"gateway,omitempty" yaml:"gateway,omitempty"`

	// Log indicates whether matched packets are logged.
	Log bool `json:"log,omitempty" yaml:"log,omitempty"`
	// Disabled indicates the rule is administratively disabled.
	Disabled bool `json:"disabled,omitempty" yaml:"disabled,omitempty"`

	// Tracker is the unique tracking identifier assigned by the firewall.
	Tracker string `json:"tracker,omitempty" yaml:"tracker,omitempty"`
	// MaxSrcNodes is the maximum number of source hosts allowed per rule.
	MaxSrcNodes string `json:"maxSrcNodes,omitempty" yaml:"maxSrcNodes,omitempty"`
	// MaxSrcConn is the maximum number of simultaneous connections per source.
	MaxSrcConn string `json:"maxSrcConn,omitempty" yaml:"maxSrcConn,omitempty"`
	// MaxSrcConnRate is the maximum new connection rate per source (e.g., "15/5").
	MaxSrcConnRate string `json:"maxSrcConnRate,omitempty" yaml:"maxSrcConnRate,omitempty"`
	// MaxSrcConnRates is the rate-limit action interval.
	MaxSrcConnRates string `json:"maxSrcConnRates,omitempty" yaml:"maxSrcConnRates,omitempty"`
	// TCPFlags1 is the first set of TCP flags to match.
	TCPFlags1 string `json:"tcpFlags1,omitempty" yaml:"tcpFlags1,omitempty"`
	// TCPFlags2 is the second set of TCP flags to match (out-of mask).
	TCPFlags2 string `json:"tcpFlags2,omitempty" yaml:"tcpFlags2,omitempty"`
	// TCPFlagsAny enables matching any TCP flag combination.
	TCPFlagsAny bool `json:"tcpFlagsAny,omitempty" yaml:"tcpFlagsAny,omitempty"`
	// ICMPType is the ICMP type to match for IPv4 rules.
	ICMPType string `json:"icmpType,omitempty" yaml:"icmpType,omitempty"`
	// ICMP6Type is the ICMPv6 type to match for IPv6 rules.
	ICMP6Type string `json:"icmp6Type,omitempty" yaml:"icmp6Type,omitempty"`
	// StateTimeout is the custom state timeout in seconds.
	StateTimeout string `json:"stateTimeout,omitempty" yaml:"stateTimeout,omitempty"`
	// AllowOpts permits IP options to pass through the rule.
	AllowOpts bool `json:"allowOpts,omitempty" yaml:"allowOpts,omitempty"`
	// DisableReplyTo disables automatic reply-to routing for the rule.
	DisableReplyTo bool `json:"disableReplyTo,omitempty" yaml:"disableReplyTo,omitempty"`
	// NoPfSync excludes this rule's states from pfsync replication.
	NoPfSync bool `json:"noPfSync,omitempty" yaml:"noPfSync,omitempty"`
	// NoSync excludes the rule from XMLRPC config synchronization.
	NoSync bool `json:"noSync,omitempty" yaml:"noSync,omitempty"`
	// AssociatedRuleID links this rule to an automatically generated companion rule.
	AssociatedRuleID string `json:"associatedRuleId,omitempty" yaml:"associatedRuleId,omitempty"`
}

// NATConfig contains all NAT-related configuration.
type NATConfig struct {
	// OutboundMode is the outbound NAT mode (e.g., "automatic", "hybrid", "advanced").
	OutboundMode string `json:"outboundMode,omitempty" yaml:"outboundMode,omitempty"`
	// ReflectionDisabled indicates NAT reflection is turned off.
	ReflectionDisabled bool `json:"reflectionDisabled,omitempty" yaml:"reflectionDisabled,omitempty"`
	// PfShareForward enables pf share-forward for NAT.
	PfShareForward bool `json:"pfShareForward,omitempty" yaml:"pfShareForward,omitempty"`
	// OutboundRules contains outbound NAT rules.
	OutboundRules []NATRule `json:"outboundRules,omitempty" yaml:"outboundRules,omitempty"`
	// InboundRules contains inbound (port-forward) NAT rules.
	InboundRules []InboundNATRule `json:"inboundRules,omitempty" yaml:"inboundRules,omitempty"`
	// BiNATEnabled indicates bidirectional NAT is active.
	BiNATEnabled bool `json:"biNatEnabled,omitempty" yaml:"biNatEnabled,omitempty"`
}

// NATRule represents an outbound NAT rule.
type NATRule struct {
	// UUID is the unique identifier for the NAT rule.
	UUID string `json:"uuid,omitempty" yaml:"uuid,omitempty"`
	// Interfaces lists the interface names this rule applies to.
	Interfaces []string `json:"interfaces,omitempty" yaml:"interfaces,omitempty"`
	// IPProtocol is the IP address family (e.g., "inet", "inet6").
	IPProtocol string `json:"ipProtocol,omitempty" yaml:"ipProtocol,omitempty"`
	// Protocol is the layer-4 protocol (e.g., "tcp", "udp").
	Protocol string `json:"protocol,omitempty" yaml:"protocol,omitempty"`
	// Source is the source endpoint for the NAT rule.
	Source RuleEndpoint `json:"source" yaml:"source,omitempty"`
	// Destination is the destination endpoint for the NAT rule.
	Destination RuleEndpoint `json:"destination" yaml:"destination,omitempty"`
	// Target is the NAT translation target address.
	Target string `json:"target,omitempty" yaml:"target,omitempty"`
	// SourcePort is the translated source port.
	SourcePort string `json:"sourcePort,omitempty" yaml:"sourcePort,omitempty"`
	// NatPort is the translated destination port.
	NatPort string `json:"natPort,omitempty" yaml:"natPort,omitempty"`
	// PoolOpts specifies the address pool options for NAT translation.
	PoolOpts string `json:"poolOpts,omitempty" yaml:"poolOpts,omitempty"`
	// StaticNatPort preserves the original source port during NAT translation.
	StaticNatPort bool `json:"staticNatPort,omitempty" yaml:"staticNatPort,omitempty"`
	// NoNat disables NAT for matching traffic (exclusion rule).
	NoNat bool `json:"noNat,omitempty" yaml:"noNat,omitempty"`
	// Disabled indicates the NAT rule is administratively disabled.
	Disabled bool `json:"disabled,omitempty" yaml:"disabled,omitempty"`
	// Log indicates whether matched packets are logged.
	Log bool `json:"log,omitempty" yaml:"log,omitempty"`
	// Description is a human-readable description of the NAT rule.
	Description string `json:"description,omitempty" yaml:"description,omitempty"`
	// Category is the classification category for the NAT rule.
	Category string `json:"category,omitempty" yaml:"category,omitempty"`
	// Tag is the pf tag applied to packets matching this rule.
	Tag string `json:"tag,omitempty" yaml:"tag,omitempty"`
	// Tagged matches packets that already carry the specified pf tag.
	Tagged string `json:"tagged,omitempty" yaml:"tagged,omitempty"`
}

// InboundNATRule represents an inbound (port-forward) NAT rule.
type InboundNATRule struct {
	// UUID is the unique identifier for the port-forward rule.
	UUID string `json:"uuid,omitempty" yaml:"uuid,omitempty"`
	// Interfaces lists the interface names this rule applies to.
	Interfaces []string `json:"interfaces,omitempty" yaml:"interfaces,omitempty"`
	// IPProtocol is the IP address family (e.g., "inet", "inet6").
	IPProtocol string `json:"ipProtocol,omitempty" yaml:"ipProtocol,omitempty"`
	// Protocol is the layer-4 protocol (e.g., "tcp", "udp").
	Protocol string `json:"protocol,omitempty" yaml:"protocol,omitempty"`
	// Source is the source endpoint for the port-forward rule.
	Source RuleEndpoint `json:"source" yaml:"source,omitempty"`
	// Destination is the destination endpoint for the port-forward rule.
	Destination RuleEndpoint `json:"destination" yaml:"destination,omitempty"`
	// ExternalPort is the external port or range to forward.
	ExternalPort string `json:"externalPort,omitempty" yaml:"externalPort,omitempty"`
	// InternalIP is the internal target IP address for port forwarding.
	InternalIP string `json:"internalIp,omitempty" yaml:"internalIp,omitempty"`
	// InternalPort is the internal target port for port forwarding.
	InternalPort string `json:"internalPort,omitempty" yaml:"internalPort,omitempty"`
	// LocalPort is the local port used for NAT reflection.
	LocalPort string `json:"localPort,omitempty" yaml:"localPort,omitempty"`
	// Reflection is the NAT reflection setting for this rule.
	Reflection string `json:"reflection,omitempty" yaml:"reflection,omitempty"`
	// NATReflection is the NAT reflection mode (e.g., "enable", "disable", "purenat").
	NATReflection string `json:"natReflection,omitempty" yaml:"natReflection,omitempty"`
	// AssociatedRuleID links this rule to an automatically generated filter rule.
	AssociatedRuleID string `json:"associatedRuleId,omitempty" yaml:"associatedRuleId,omitempty"`
	// Priority is the rule evaluation priority.
	Priority int `json:"priority,omitempty" yaml:"priority,omitempty"`
	// NoRDR disables the redirect for matching traffic.
	NoRDR bool `json:"noRdr,omitempty" yaml:"noRdr,omitempty"`
	// NoSync excludes the rule from XMLRPC config synchronization.
	NoSync bool `json:"noSync,omitempty" yaml:"noSync,omitempty"`
	// Disabled indicates the port-forward rule is administratively disabled.
	Disabled bool `json:"disabled,omitempty" yaml:"disabled,omitempty"`
	// Log indicates whether matched packets are logged.
	Log bool `json:"log,omitempty" yaml:"log,omitempty"`
	// Description is a human-readable description of the port-forward rule.
	Description string `json:"description,omitempty" yaml:"description,omitempty"`
}

// NATSummary is a convenience view of a device's NAT configuration for
// report generation.
type NATSummary struct {
	// Mode is the outbound NAT mode.
	Mode string `json:"mode,omitempty" yaml:"mode,omitempty"`
	// ReflectionDisabled indicates NAT reflection is turned off.
	ReflectionDisabled bool `json:"reflectionDisabled,omitempty" yaml:"reflectionDisabled,omitempty"`
	// PfShareForward enables pf share-forward for NAT.
	PfShareForward bool `json:"pfShareForward,omitempty" yaml:"pfShareForward,omitempty"`
	// OutboundRules contains outbound NAT rules.
	OutboundRules []NATRule `json:"outboundRules,omitempty" yaml:"outboundRules,omitempty"`
	// InboundRules contains inbound (port-forward) NAT rules.
	InboundRules []InboundNATRule `json:"inboundRules,omitempty" yaml:"inboundRules,omitempty"`
}
