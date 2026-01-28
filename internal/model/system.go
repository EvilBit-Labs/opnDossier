// Package model re-exports types from internal/schema for backward compatibility.
package model

import (
	"github.com/EvilBit-Labs/opnDossier/internal/schema"
)

// WebGUIConfig represents web GUI configuration.
type WebGUIConfig = schema.WebGUIConfig

// SSHConfig represents SSH configuration.
type SSHConfig = schema.SSHConfig

// SystemConfig groups system-related configuration.
type SystemConfig = schema.SystemConfig

// SysctlItem represents a sysctl configuration item.
type SysctlItem = schema.SysctlItem

// System represents the system configuration.
type System = schema.System

// Widgets represents dashboard widgets configuration.
type Widgets = schema.Widgets

// Group represents a user group.
type Group = schema.Group

// Firmware represents firmware configuration.
type Firmware = schema.Firmware

// User represents a user account.
type User = schema.User

// APIKey represents an API key configuration.
type APIKey = schema.APIKey
