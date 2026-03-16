// Package model re-exports types from internal/schema for backward compatibility.
package model

import (
	schema "github.com/EvilBit-Labs/opnDossier/pkg/schema/opnsense"
)

// HighAvailabilitySync represents high availability sync configuration.
type HighAvailabilitySync = schema.HighAvailabilitySync
