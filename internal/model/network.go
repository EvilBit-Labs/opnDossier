// Package model re-exports types from internal/schema for backward compatibility.
package model

import (
	"github.com/EvilBit-Labs/opnDossier/internal/schema"
)

// NetworkConfig groups network-related configuration.
type NetworkConfig = schema.NetworkConfig

// DhcpOption represents a DHCP option configuration.
type DhcpOption = schema.DhcpOption

// DhcpRange represents a DHCP range configuration.
type DhcpRange = schema.DhcpRange

// Gateways represents gateway configurations.
type Gateways = schema.Gateways

// Gateway represents a single gateway configuration.
type Gateway = schema.Gateway

// GatewayGroup represents a gateway group configuration.
type GatewayGroup = schema.GatewayGroup

// StaticRoutes represents static route configurations.
type StaticRoutes = schema.StaticRoutes

// StaticRoute represents a single static route configuration.
type StaticRoute = schema.StaticRoute
