// Package model defines the data structures for OPNsense configurations.
//
// This package re-exports types from internal/schema for backward compatibility.
// New code should import internal/schema directly.
package model

import (
	"github.com/EvilBit-Labs/opnDossier/internal/schema"
)

// BoolFlag provides custom XML marshaling for OPNsense boolean values.
// Type alias to schema.BoolFlag - all methods are inherited.
type BoolFlag = schema.BoolFlag

// ChangeMeta tracks creation and modification metadata for configuration items.
// Type alias to schema.ChangeMeta.
type ChangeMeta = schema.ChangeMeta

// RuleLocation provides granular source/destination address and port specification.
// Type alias to schema.RuleLocation - all methods are inherited.
type RuleLocation = schema.RuleLocation
