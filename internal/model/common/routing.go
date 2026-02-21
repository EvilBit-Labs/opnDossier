package common

// Routing contains gateway and static route configuration.
type Routing struct {
	// Gateways contains configured network gateways.
	Gateways []Gateway `json:"gateways,omitempty" yaml:"gateways,omitempty"`
	// GatewayGroups contains gateway groups for failover and load balancing.
	GatewayGroups []GatewayGroup `json:"gatewayGroups,omitempty" yaml:"gatewayGroups,omitempty"`
	// StaticRoutes contains manually configured routes.
	StaticRoutes []StaticRoute `json:"staticRoutes,omitempty" yaml:"staticRoutes,omitempty"`
}

// Gateway represents a network gateway.
type Gateway struct {
	// Interface is the interface the gateway is reachable through.
	Interface string `json:"interface,omitempty" yaml:"interface,omitempty"`
	// Address is the gateway IP address.
	Address string `json:"address,omitempty" yaml:"address,omitempty"`
	// Name is the gateway name used for reference in rules and routes.
	Name string `json:"name,omitempty" yaml:"name,omitempty"`
	// Weight is the gateway priority weight for multi-WAN balancing.
	Weight string `json:"weight,omitempty" yaml:"weight,omitempty"`
	// IPProtocol is the IP address family (e.g., "inet", "inet6").
	IPProtocol string `json:"ipProtocol,omitempty" yaml:"ipProtocol,omitempty"`
	// Interval is the monitoring probe interval in milliseconds.
	Interval string `json:"interval,omitempty" yaml:"interval,omitempty"`
	// Description is a human-readable description of the gateway.
	Description string `json:"description,omitempty" yaml:"description,omitempty"`
	// Monitor is the IP address used for gateway health monitoring.
	Monitor string `json:"monitor,omitempty" yaml:"monitor,omitempty"`
	// Disabled indicates the gateway is administratively disabled.
	Disabled bool `json:"disabled,omitempty" yaml:"disabled,omitempty"`
	// DefaultGW marks this gateway as the default route.
	DefaultGW string `json:"defaultGw,omitempty" yaml:"defaultGw,omitempty"`
	// MonitorDisable disables gateway health monitoring.
	MonitorDisable string `json:"monitorDisable,omitempty" yaml:"monitorDisable,omitempty"`
	// FarGW indicates the gateway is on a different subnet than the interface.
	FarGW bool `json:"farGw,omitempty" yaml:"farGw,omitempty"`
}

// GatewayGroup represents a group of gateways for failover or load balancing.
type GatewayGroup struct {
	// Name is the gateway group name.
	Name string `json:"name,omitempty" yaml:"name,omitempty"`
	// Items contains the member gateway entries with tier assignments.
	Items []string `json:"items,omitempty" yaml:"items,omitempty"`
	// Trigger is the condition that causes failover (e.g., "down", "highloss").
	Trigger string `json:"trigger,omitempty" yaml:"trigger,omitempty"`
	// Description is a human-readable description of the gateway group.
	Description string `json:"description,omitempty" yaml:"description,omitempty"`
}

// StaticRoute represents a manually configured route.
type StaticRoute struct {
	// Network is the destination network in CIDR notation.
	Network string `json:"network,omitempty" yaml:"network,omitempty"`
	// Gateway is the next-hop gateway name for the route.
	Gateway string `json:"gateway,omitempty" yaml:"gateway,omitempty"`
	// Description is a human-readable description of the route.
	Description string `json:"description,omitempty" yaml:"description,omitempty"`
	// Disabled indicates the route is administratively disabled.
	Disabled bool `json:"disabled,omitempty" yaml:"disabled,omitempty"`
	// Created is the timestamp when the route was created.
	Created string `json:"created,omitempty" yaml:"created,omitempty"`
	// Updated is the timestamp when the route was last modified.
	Updated string `json:"updated,omitempty" yaml:"updated,omitempty"`
}
