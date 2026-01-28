// Package model re-exports types from internal/schema for backward compatibility.
package model

import (
	"github.com/EvilBit-Labs/opnDossier/internal/schema"
)

// Dhcpd represents DHCP server configuration with interface-keyed entries.
// Type alias to schema.Dhcpd - all methods are inherited.
type Dhcpd = schema.Dhcpd

// DhcpdInterface represents per-interface DHCP configuration.
type DhcpdInterface = schema.DhcpdInterface

// DHCPNumberOption represents a DHCP number option.
type DHCPNumberOption = schema.DHCPNumberOption

// DHCPStaticLease represents a DHCP static lease assignment.
type DHCPStaticLease = schema.DHCPStaticLease

// Range represents a DHCP address range.
type Range = schema.Range
