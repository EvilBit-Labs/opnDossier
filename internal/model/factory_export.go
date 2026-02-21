package model

import (
	"github.com/EvilBit-Labs/opnDossier/internal/model/common"
)

// CommonDevice is the platform-agnostic domain model for a firewall device.
type CommonDevice = common.CommonDevice

// DeviceType identifies the platform that produced a configuration.
type DeviceType = common.DeviceType

const (
	// DeviceTypeOPNsense represents an OPNsense device.
	DeviceTypeOPNsense = common.DeviceTypeOPNsense
	// DeviceTypePfSense represents a pfSense device.
	DeviceTypePfSense = common.DeviceTypePfSense
	// DeviceTypeUnknown represents an unrecognized device type.
	DeviceTypeUnknown = common.DeviceTypeUnknown
)
