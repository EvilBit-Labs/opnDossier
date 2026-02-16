// Package compliance provides error definitions and interfaces for compliance plugins.
package compliance

import "errors"

// Static errors for the plugin package.
var (
	// ErrPluginNotFound is returned when a requested plugin cannot be found in the registry.
	ErrPluginNotFound = errors.New("plugin not found")

	// ErrControlNotFound is returned when a requested control cannot be found in a plugin.
	ErrControlNotFound = errors.New("control not found")

	// ErrNoControlsDefined is returned when a plugin has no controls defined.
	ErrNoControlsDefined = errors.New("no controls defined")

	// ErrPluginValidation is returned when plugin configuration validation fails.
	ErrPluginValidation = errors.New("plugin validation failed")

	// ErrComplianceAudit is returned when a compliance audit operation fails.
	ErrComplianceAudit = errors.New("compliance audit failed")
)
