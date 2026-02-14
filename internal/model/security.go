// Package model re-exports types from internal/schema for backward compatibility.
package model

import (
	"github.com/EvilBit-Labs/opnDossier/internal/schema"
)

// InterfaceList represents a comma-separated list of interfaces.
// Type alias to schema.InterfaceList - all methods are inherited.
type InterfaceList = schema.InterfaceList

// SecurityConfig groups security-related configuration.
type SecurityConfig = schema.SecurityConfig

// NATSummary provides comprehensive NAT configuration for security analysis.
type NATSummary = schema.NATSummary

// Nat represents NAT configuration.
type Nat = schema.Nat

// Outbound represents outbound NAT configuration.
type Outbound = schema.Outbound

// Filter represents firewall filter configuration.
type Filter = schema.Filter

// NATRule represents a NAT rule.
type NATRule = schema.NATRule

// InboundRule represents an inbound NAT rule (port forwarding).
type InboundRule = schema.InboundRule

// Rule represents a firewall rule.
type Rule = schema.Rule

// Source represents a firewall rule source.
type Source = schema.Source

// Destination represents a firewall rule destination.
type Destination = schema.Destination

// Updated represents update information.
type Updated = schema.Updated

// Created represents creation information.
type Created = schema.Created

// Firewall represents firewall configuration.
type Firewall = schema.Firewall

// IDS represents Intrusion Detection System configuration.
//
//nolint:revive // IDS is the standard acronym for Intrusion Detection System
type IDS = schema.IDS

// IPsec represents IPsec configuration.
type IPsec = schema.IPsec

// Swanctl represents StrongSwan configuration.
type Swanctl = schema.Swanctl

// Constructor functions that delegate to schema package.

// NewSecurityConfig returns a new SecurityConfig instance.
func NewSecurityConfig() SecurityConfig {
	return schema.NewSecurityConfig()
}

// NewFirewall returns a pointer to a new, empty Firewall configuration.
func NewFirewall() *Firewall {
	return schema.NewFirewall()
}

// NewIDS creates a new IDS configuration.
//
//nolint:revive // IDS is the standard acronym for Intrusion Detection System
func NewIDS() *IDS {
	return schema.NewIDS()
}

// NewIPsec returns a pointer to a new IPsec configuration instance.
func NewIPsec() *IPsec {
	return schema.NewIPsec()
}

// NewSwanctl returns a new instance of the Swanctl configuration struct.
func NewSwanctl() *Swanctl {
	return schema.NewSwanctl()
}

// StringPtr returns a pointer to the given string value.
// Convenience wrapper around schema.StringPtr for constructing Source/Destination
// literals with the *string Any field.
func StringPtr(s string) *string {
	return schema.StringPtr(s)
}
