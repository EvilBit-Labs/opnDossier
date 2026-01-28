// Package model re-exports types from internal/schema for backward compatibility.
package model

import (
	"github.com/EvilBit-Labs/opnDossier/internal/schema"
)

// HighAvailabilitySync represents high availability sync configuration.
type HighAvailabilitySync = schema.HighAvailabilitySync
