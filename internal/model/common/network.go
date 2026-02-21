package common

// Interface represents a network interface with normalized fields.
type Interface struct {
	// Name is the logical interface name (e.g., "lan", "wan", "opt1").
	Name string `json:"name,omitempty" yaml:"name,omitempty"`
	// PhysicalIf is the physical device identifier (e.g., "igb0", "em0").
	PhysicalIf string `json:"physicalIf,omitempty" yaml:"physicalIf,omitempty"`
	// Description is a human-readable label for the interface.
	Description string `json:"description,omitempty" yaml:"description,omitempty"`
	// Enabled indicates whether the interface is administratively up.
	Enabled bool `json:"enabled,omitempty" yaml:"enabled,omitempty"`
	// IPAddress is the IPv4 address assigned to the interface.
	IPAddress string `json:"ipAddress,omitempty" yaml:"ipAddress,omitempty"`
	// IPv6Address is the IPv6 address assigned to the interface.
	IPv6Address string `json:"ipv6Address,omitempty" yaml:"ipv6Address,omitempty"`
	// Subnet is the IPv4 subnet prefix length.
	Subnet string `json:"subnet,omitempty" yaml:"subnet,omitempty"`
	// SubnetV6 is the IPv6 subnet prefix length.
	SubnetV6 string `json:"subnetV6,omitempty" yaml:"subnetV6,omitempty"`
	// Gateway is the IPv4 gateway for the interface.
	Gateway string `json:"gateway,omitempty" yaml:"gateway,omitempty"`
	// GatewayV6 is the IPv6 gateway for the interface.
	GatewayV6 string `json:"gatewayV6,omitempty" yaml:"gatewayV6,omitempty"`
	// BlockPrivate enables blocking of RFC 1918 private network traffic.
	BlockPrivate bool `json:"blockPrivate,omitempty" yaml:"blockPrivate,omitempty"`
	// BlockBogons enables blocking of bogon (unassigned/reserved) network traffic.
	BlockBogons bool `json:"blockBogons,omitempty" yaml:"blockBogons,omitempty"`
	// Type is the interface type (e.g., "dhcp", "static", "none").
	Type string `json:"type,omitempty" yaml:"type,omitempty"`
	// MTU is the maximum transmission unit size.
	MTU string `json:"mtu,omitempty" yaml:"mtu,omitempty"`
	// SpoofMAC is an overridden MAC address for the interface.
	SpoofMAC string `json:"spoofMac,omitempty" yaml:"spoofMac,omitempty"`
	// DHCPHostname is the hostname sent in DHCP requests.
	DHCPHostname string `json:"dhcpHostname,omitempty" yaml:"dhcpHostname,omitempty"`
	// Media is the interface media type (e.g., "autoselect").
	Media string `json:"media,omitempty" yaml:"media,omitempty"`
	// MediaOpt is the interface media option (e.g., "full-duplex").
	MediaOpt string `json:"mediaOpt,omitempty" yaml:"mediaOpt,omitempty"`
	// Virtual indicates this is a virtual rather than physical interface.
	Virtual bool `json:"virtual,omitempty" yaml:"virtual,omitempty"`
	// Lock prevents the interface from being accidentally deleted or modified.
	Lock bool `json:"lock,omitempty" yaml:"lock,omitempty"`
}

// VLAN represents a VLAN configuration.
type VLAN struct {
	// VLANIf is the VLAN interface name (e.g., "igb0_vlan100").
	VLANIf string `json:"vlanIf,omitempty" yaml:"vlanIf,omitempty"`
	// PhysicalIf is the parent physical interface carrying the VLAN.
	PhysicalIf string `json:"physicalIf,omitempty" yaml:"physicalIf,omitempty"`
	// Tag is the 802.1Q VLAN tag identifier.
	Tag string `json:"tag,omitempty" yaml:"tag,omitempty"`
	// Description is a human-readable description of the VLAN.
	Description string `json:"description,omitempty" yaml:"description,omitempty"`
	// Created is the timestamp when the VLAN was created.
	Created string `json:"created,omitempty" yaml:"created,omitempty"`
	// Updated is the timestamp when the VLAN was last modified.
	Updated string `json:"updated,omitempty" yaml:"updated,omitempty"`
}

// Bridge represents a network bridge configuration.
type Bridge struct {
	// Members is a comma-separated list of member interface names.
	Members string `json:"members,omitempty" yaml:"members,omitempty"`
	// Description is a human-readable description of the bridge.
	Description string `json:"description,omitempty" yaml:"description,omitempty"`
	// BridgeIf is the bridge interface name (e.g., "bridge0").
	BridgeIf string `json:"bridgeIf,omitempty" yaml:"bridgeIf,omitempty"`
	// STP indicates whether Spanning Tree Protocol is enabled.
	STP bool `json:"stp,omitempty" yaml:"stp,omitempty"`
	// Created is the timestamp when the bridge was created.
	Created string `json:"created,omitempty" yaml:"created,omitempty"`
	// Updated is the timestamp when the bridge was last modified.
	Updated string `json:"updated,omitempty" yaml:"updated,omitempty"`
}

// PPP represents a PPP connection configuration.
type PPP struct {
	// Interface is the PPP interface name (e.g., "pppoe0").
	Interface string `json:"interface,omitempty" yaml:"interface,omitempty"`
	// Type is the PPP connection type (e.g., "pppoe", "pptp", "l2tp").
	Type string `json:"type,omitempty" yaml:"type,omitempty"`
	// Description is a human-readable description of the PPP connection.
	Description string `json:"description,omitempty" yaml:"description,omitempty"`
}

// GIF represents a GIF (Generic Tunneling Interface) tunnel configuration.
type GIF struct {
	// Interface is the GIF tunnel interface name (e.g., "gif0").
	Interface string `json:"interface,omitempty" yaml:"interface,omitempty"`
	// Remote is the remote endpoint address for the tunnel.
	Remote string `json:"remote,omitempty" yaml:"remote,omitempty"`
	// Description is a human-readable description of the GIF tunnel.
	Description string `json:"description,omitempty" yaml:"description,omitempty"`
}

// GRE represents a GRE (Generic Routing Encapsulation) tunnel configuration.
type GRE struct {
	// Interface is the GRE tunnel interface name (e.g., "gre0").
	Interface string `json:"interface,omitempty" yaml:"interface,omitempty"`
	// Remote is the remote endpoint address for the tunnel.
	Remote string `json:"remote,omitempty" yaml:"remote,omitempty"`
	// Description is a human-readable description of the GRE tunnel.
	Description string `json:"description,omitempty" yaml:"description,omitempty"`
}

// LAGG represents a link aggregation configuration.
type LAGG struct {
	// Members is a comma-separated list of member physical interface names.
	Members string `json:"members,omitempty" yaml:"members,omitempty"`
	// Protocol is the aggregation protocol (e.g., "lacp", "failover", "roundrobin").
	Protocol string `json:"protocol,omitempty" yaml:"protocol,omitempty"`
	// Description is a human-readable description of the LAGG.
	Description string `json:"description,omitempty" yaml:"description,omitempty"`
}

// VirtualIP represents a virtual IP address configuration.
type VirtualIP struct {
	// Mode is the virtual IP mode (e.g., "carp", "ipalias", "proxyarp").
	Mode string `json:"mode,omitempty" yaml:"mode,omitempty"`
	// Interface is the interface the virtual IP is bound to.
	Interface string `json:"interface,omitempty" yaml:"interface,omitempty"`
	// Subnet is the virtual IP address with prefix length.
	Subnet string `json:"subnet,omitempty" yaml:"subnet,omitempty"`
	// Description is a human-readable description of the virtual IP.
	Description string `json:"description,omitempty" yaml:"description,omitempty"`
}

// InterfaceGroups represents a logical grouping of interfaces.
type InterfaceGroups struct {
	// Name is the interface group name.
	Name string `json:"name,omitempty" yaml:"name,omitempty"`
	// Members contains the interface names belonging to this group.
	Members []string `json:"members,omitempty" yaml:"members,omitempty"`
}
