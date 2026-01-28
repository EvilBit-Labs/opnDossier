// Package model re-exports types from internal/schema for backward compatibility.
package model

import (
	"github.com/EvilBit-Labs/opnDossier/internal/schema"
)

// OpnSenseDocument is the root of the OPNsense configuration.
// Type alias to schema.OpnSenseDocument - all methods are inherited.
type OpnSenseDocument = schema.OpnSenseDocument

// OPNsense represents the main OPNsense system configuration.
type OPNsense = schema.OPNsense

// Cert represents a certificate configuration.
type Cert = schema.Cert

// NewOpnSenseDocument returns a new OpnSenseDocument with all slice and map fields initialized.
func NewOpnSenseDocument() *OpnSenseDocument {
	return schema.NewOpnSenseDocument()
}
