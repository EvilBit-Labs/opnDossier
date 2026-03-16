// Package model re-exports types from internal/schema for backward compatibility.
package model

import (
	schema "github.com/EvilBit-Labs/opnDossier/pkg/schema/opnsense"
)

// Revision represents a configuration revision.
type Revision = schema.Revision
