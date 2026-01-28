// Package model re-exports types from internal/schema for backward compatibility.
package model

import (
	"github.com/EvilBit-Labs/opnDossier/internal/schema"
)

// Package represents a software package.
type Package = schema.Package

// Service represents a system service.
type Service = schema.Service

// NewPackage returns a new Package instance.
func NewPackage() Package {
	return schema.NewPackage()
}

// NewService returns a new Service instance.
func NewService() Service {
	return schema.NewService()
}
