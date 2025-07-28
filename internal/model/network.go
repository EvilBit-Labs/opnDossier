// Package model defines the data structures for OPNsense configurations.
package model

import (
	"encoding/xml"
)

// NetworkConfig groups network-related configuration.
type NetworkConfig struct {
	Interfaces Interfaces   `json:"interfaces,omitempty" yaml:"interfaces,omitempty" validate:"required"`
	VLANs      []VLANConfig `json:"vlans,omitempty" yaml:"vlans,omitempty"`
	Gateways   []Gateway    `json:"gateways,omitempty" yaml:"gateways,omitempty"`
}

// DhcpOption represents a DHCP option.
type DhcpOption struct {
	Number string `xml:"number,omitempty" json:"number,omitempty" yaml:"number,omitempty"`
	Value  string `xml:"value,omitempty" json:"value,omitempty" yaml:"value,omitempty"`
}

// DhcpRange represents a DHCP range.
type DhcpRange struct {
	From string `xml:"from,omitempty" json:"from,omitempty" yaml:"from,omitempty"`
	To   string `xml:"to,omitempty" json:"to,omitempty" yaml:"to,omitempty"`
}

// Vlans represents VLAN configuration.

// Gateways represents gateway configuration.
type Gateways struct {
	XMLName xml.Name       `xml:"gateways"`
	Gateway []Gateway      `xml:"gateway_item,omitempty"`
	Groups  []GatewayGroup `xml:"gateway_group,omitempty"`
}

// Gateway struct for individual gateway configuration.
type Gateway struct {
	XMLName        xml.Name `xml:"gateway_item"`
	Interface      string   `xml:"interface,omitempty"`
	Gateway        string   `xml:"gateway,omitempty"`
	Name           string   `xml:"name,omitempty"`
	Weight         string   `xml:"weight,omitempty"`
	IPProtocol     string   `xml:"ipprotocol,omitempty"`
	Interval       string   `xml:"interval,omitempty"`
	Descr          string   `xml:"descr,omitempty"`
	Monitor        string   `xml:"monitor,omitempty"`
	Disabled       BoolFlag `xml:"disabled,omitempty"`
	Created        string   `xml:"created,omitempty"`
	Updated        string   `xml:"updated,omitempty"`
	DefaultGW      string   `xml:"defaultgw,omitempty"`
	MonitorDisable string   `xml:"monitor_disable,omitempty"`
	FarGW          string   `xml:"fargw,omitempty"`
}

// GatewayGroup represents a group of gateways for OPNsense configuration.
type GatewayGroup struct {
	XMLName xml.Name `xml:"gateway_group"`
	Name    string   `xml:"name,omitempty"`
	Item    []string `xml:"item,omitempty"`
	Trigger string   `xml:"trigger,omitempty"`
	Descr   string   `xml:"descr,omitempty"`
}

// StaticRoutes represents static routing configuration.
type StaticRoutes struct {
	XMLName xml.Name      `xml:"staticroutes"`
	Route   []StaticRoute `xml:"route,omitempty"`
}

// StaticRoute struct for individual static route configuration.
type StaticRoute struct {
	XMLName  xml.Name `xml:"route"`
	Network  string   `xml:"network,omitempty"`
	Gateway  string   `xml:"gateway,omitempty"`
	Descr    string   `xml:"descr,omitempty"`
	Disabled BoolFlag `xml:"disabled,omitempty"`
	Created  string   `xml:"created,omitempty"`
	Updated  string   `xml:"updated,omitempty"`
}

// Constructor functions for network models

// NewNetworkConfig creates a new NetworkConfig with properly initialized slices.
func NewNetworkConfig() NetworkConfig {
	return NetworkConfig{
		VLANs:    make([]VLANConfig, 0),
		Gateways: make([]Gateway, 0),
		Interfaces: Interfaces{
			Items: make(map[string]Interface),
		},
	}
}

// NewVLANs creates a new VLANs configuration with properly initialized slices.
func NewVLANs() *VLANs {
	return &VLANs{
		VLAN: make([]VLAN, 0),
	}
}

// NewBridges creates a new Bridges configuration with properly initialized slices.
func NewBridges() *Bridges {
	return &Bridges{
		Bridge: make([]Bridge, 0),
	}
}

// NewGateways creates a new Gateways configuration with properly initialized slices.
func NewGateways() *Gateways {
	return &Gateways{
		Gateway: make([]Gateway, 0),
		Groups:  make([]GatewayGroup, 0),
	}
}

// NewGatewayGroup creates a new GatewayGroup with properly initialized slices.
func NewGatewayGroup() GatewayGroup {
	return GatewayGroup{
		Item: make([]string, 0),
	}
}

// NewStaticRoutes creates a new StaticRoutes configuration with properly initialized slices.
func NewStaticRoutes() *StaticRoutes {
	return &StaticRoutes{
		Route: make([]StaticRoute, 0),
	}
}
