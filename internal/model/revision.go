// Package model re-exports types from internal/schema for backward compatibility.
package model

import (
	"github.com/EvilBit-Labs/opnDossier/internal/schema"
)

// Revision represents a configuration revision.
type Revision = schema.Revision
