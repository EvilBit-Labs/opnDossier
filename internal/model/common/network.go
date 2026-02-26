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
	// Members contains the member interface names belonging to this bridge.
	Members []string `json:"members,omitempty" yaml:"members,omitempty"`
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
	// Ports lists the physical interface(s) the PPP connection operates over.
	// May contain multiple entries for multi-link PPP (MLPPP).
	Ports string `json:"ports,omitempty" yaml:"ports,omitempty"`
	// Username is the authentication username for the PPP connection.
	Username string `json:"username,omitempty" yaml:"username,omitempty"`
	// AuthMethod is the PPP authentication method (e.g., "chap", "pap", "mschap").
	AuthMethod string `json:"authMethod,omitempty" yaml:"authMethod,omitempty"`
	// MTU is the maximum transmission unit for the PPP link.
	MTU string `json:"mtu,omitempty" yaml:"mtu,omitempty"`
	// Provider is the ISP or service provider identifier.
	Provider string `json:"provider,omitempty" yaml:"provider,omitempty"`
}

// GIF represents a GIF (generic tunnel interface) tunnel configuration.
type GIF struct {
	// Interface is the GIF tunnel interface name (e.g., "gif0").
	Interface string `json:"interface,omitempty" yaml:"interface,omitempty"`
	// Local is the parent physical interface name (e.g., "wan").
	Local string `json:"local,omitempty" yaml:"local,omitempty"`
	// Remote is the remote outer endpoint address for the tunnel.
	Remote string `json:"remote,omitempty" yaml:"remote,omitempty"`
	// TunnelLocalAddress is the local inner tunnel address.
	TunnelLocalAddress string `json:"tunnelLocalAddress,omitempty" yaml:"tunnelLocalAddress,omitempty"`
	// TunnelRemoteAddress is the remote inner tunnel address.
	TunnelRemoteAddress string `json:"tunnelRemoteAddress,omitempty" yaml:"tunnelRemoteAddress,omitempty"`
	// TunnelSubnetBits is the tunnel subnet mask prefix length.
	TunnelSubnetBits string `json:"tunnelSubnetBits,omitempty" yaml:"tunnelSubnetBits,omitempty"`
	// Description is a human-readable description of the GIF tunnel.
	Description string `json:"description,omitempty" yaml:"description,omitempty"`
	// Created is the timestamp when the GIF tunnel was created.
	Created string `json:"created,omitempty" yaml:"created,omitempty"`
	// Updated is the timestamp when the GIF tunnel was last modified.
	Updated string `json:"updated,omitempty" yaml:"updated,omitempty"`
}

// GRE represents a GRE (Generic Routing Encapsulation) tunnel configuration.
type GRE struct {
	// Interface is the GRE tunnel interface name (e.g., "gre0").
	Interface string `json:"interface,omitempty" yaml:"interface,omitempty"`
	// Local is the parent physical interface name (e.g., "wan").
	Local string `json:"local,omitempty" yaml:"local,omitempty"`
	// Remote is the remote outer endpoint address for the tunnel.
	Remote string `json:"remote,omitempty" yaml:"remote,omitempty"`
	// TunnelLocalAddress is the local inner tunnel address.
	TunnelLocalAddress string `json:"tunnelLocalAddress,omitempty" yaml:"tunnelLocalAddress,omitempty"`
	// TunnelRemoteAddress is the remote inner tunnel address.
	TunnelRemoteAddress string `json:"tunnelRemoteAddress,omitempty" yaml:"tunnelRemoteAddress,omitempty"`
	// TunnelSubnetBits is the tunnel subnet mask prefix length.
	TunnelSubnetBits string `json:"tunnelSubnetBits,omitempty" yaml:"tunnelSubnetBits,omitempty"`
	// Description is a human-readable description of the GRE tunnel.
	Description string `json:"description,omitempty" yaml:"description,omitempty"`
	// Created is the timestamp when the GRE tunnel was created.
	Created string `json:"created,omitempty" yaml:"created,omitempty"`
	// Updated is the timestamp when the GRE tunnel was last modified.
	Updated string `json:"updated,omitempty" yaml:"updated,omitempty"`
}

// LAGG represents a link aggregation configuration.
type LAGG struct {
	// Interface is the LAGG interface name (e.g., "lagg0", "Port-channel1").
	Interface string `json:"interface,omitempty" yaml:"interface,omitempty"`
	// Members contains the member physical interface names.
	Members []string `json:"members,omitempty" yaml:"members,omitempty"`
	// Protocol is the aggregation protocol (e.g., "lacp", "failover", "roundrobin").
	Protocol string `json:"protocol,omitempty" yaml:"protocol,omitempty"`
	// Description is a human-readable description of the LAGG.
	Description string `json:"description,omitempty" yaml:"description,omitempty"`
	// Created is the timestamp when the LAGG was created.
	Created string `json:"created,omitempty" yaml:"created,omitempty"`
	// Updated is the timestamp when the LAGG was last modified.
	Updated string `json:"updated,omitempty" yaml:"updated,omitempty"`
}

// VirtualIP represents a virtual IP address configuration.
type VirtualIP struct {
	// Mode is the virtual IP mode (e.g., "carp", "ipalias", "proxyarp").
	Mode string `json:"mode,omitempty" yaml:"mode,omitempty"`
	// Interface is the interface the virtual IP is bound to.
	Interface string `json:"interface,omitempty" yaml:"interface,omitempty"`
	// Subnet is the virtual IP address.
	Subnet string `json:"subnet,omitempty" yaml:"subnet,omitempty"`
	// SubnetBits is the CIDR subnet mask length.
	SubnetBits string `json:"subnetBits,omitempty" yaml:"subnetBits,omitempty"`
	// Description is a human-readable description of the virtual IP.
	Description string `json:"description,omitempty" yaml:"description,omitempty"`
	// UniqueID is a platform-generated unique identifier for the VIP entry.
	UniqueID string `json:"uniqueId,omitempty" yaml:"uniqueId,omitempty"`
	// VHID is the Virtual Host ID for CARP (1-255, unique per interface).
	VHID string `json:"vhid,omitempty" yaml:"vhid,omitempty"`
	// AdvSkew is the CARP advertisement skew (0-254, lower = higher priority).
	AdvSkew string `json:"advSkew,omitempty" yaml:"advSkew,omitempty"`
	// AdvBase is the CARP advertisement base interval in seconds.
	AdvBase string `json:"advBase,omitempty" yaml:"advBase,omitempty"`
}

// InterfaceGroup represents a logical grouping of interfaces.
type InterfaceGroup struct {
	// Name is the interface group name.
	Name string `json:"name,omitempty" yaml:"name,omitempty"`
	// Members contains the interface names belonging to this group.
	Members []string `json:"members,omitempty" yaml:"members,omitempty"`
	// Description is a human-readable description of the interface group.
	Description string `json:"description,omitempty" yaml:"description,omitempty"`
}
