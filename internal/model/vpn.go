// Package model re-exports types from internal/schema for backward compatibility.
package model

import (
	"github.com/EvilBit-Labs/opnDossier/internal/schema"
)

// OpenVPN represents OpenVPN configuration.
type OpenVPN = schema.OpenVPN

// OpenVPNServer represents an OpenVPN server configuration.
type OpenVPNServer = schema.OpenVPNServer

// OpenVPNClient represents an OpenVPN client configuration.
type OpenVPNClient = schema.OpenVPNClient

// ClientExport represents client export options for OpenVPN.
type ClientExport = schema.ClientExport

// OpenVPNCSC represents client-specific configurations for OpenVPN.
type OpenVPNCSC = schema.OpenVPNCSC

// OpenVPNExport represents OpenVPN export configuration.
type OpenVPNExport = schema.OpenVPNExport

// OpenVPNSystem represents OpenVPN system configuration.
type OpenVPNSystem = schema.OpenVPNSystem

// WireGuard represents WireGuard VPN configuration.
type WireGuard = schema.WireGuard

// WireGuardServerItem represents a WireGuard server configuration.
type WireGuardServerItem = schema.WireGuardServerItem

// WireGuardClientItem represents a WireGuard client configuration.
type WireGuardClientItem = schema.WireGuardClientItem

// Constructor functions that delegate to schema package.

// NewOpenVPN returns a new OpenVPN configuration.
func NewOpenVPN() *OpenVPN {
	return schema.NewOpenVPN()
}

// NewClientExport returns a new ClientExport instance.
func NewClientExport() *ClientExport {
	return schema.NewClientExport()
}

// NewOpenVPNExport initializes and returns an empty OpenVPNExport configuration.
func NewOpenVPNExport() *OpenVPNExport {
	return schema.NewOpenVPNExport()
}

// NewOpenVPNSystem returns a new, empty OpenVPNSystem configuration instance.
func NewOpenVPNSystem() *OpenVPNSystem {
	return schema.NewOpenVPNSystem()
}

// NewWireGuard returns a new WireGuard configuration instance.
func NewWireGuard() *WireGuard {
	return schema.NewWireGuard()
}
