// Package model re-exports types from internal/schema for backward compatibility.
package model

import (
	"github.com/EvilBit-Labs/opnDossier/internal/schema"
)

// InterfaceGroups represents interface groups configuration.
type InterfaceGroups = schema.InterfaceGroups

// GIFInterfaces represents GIF interface configuration.
type GIFInterfaces = schema.GIFInterfaces

// GREInterfaces represents GRE interface configuration.
type GREInterfaces = schema.GREInterfaces

// LAGGInterfaces represents LAGG interface configuration.
type LAGGInterfaces = schema.LAGGInterfaces

// VirtualIP represents virtual IP configuration.
type VirtualIP = schema.VirtualIP

// PPPInterfaces represents PPP interface configuration.
type PPPInterfaces = schema.PPPInterfaces

// Wireless represents wireless interface configuration.
type Wireless = schema.Wireless

// Interfaces contains the network interface configurations.
// Type alias to schema.Interfaces - all methods are inherited.
type Interfaces = schema.Interfaces

// Interface represents a network interface configuration.
type Interface = schema.Interface

// VLANConfig represents a Virtual Local Area Network configuration.
type VLANConfig = schema.VLANConfig

// VLANs represents a collection of VLAN configurations.
type VLANs = schema.VLANs

// VLAN represents a VLAN configuration.
type VLAN = schema.VLAN

// Bridge represents a network bridge configuration.
type Bridge = schema.Bridge

// Bridges represents a collection of bridge configurations.
type Bridges = schema.Bridges
