// Package plugin provides error definitions and interfaces for compliance plugins.
package plugin

import "errors"

// Static errors for the plugin package.
var (
	ErrPluginNotFound    = errors.New("plugin not found")
	ErrControlNotFound   = errors.New("control not found")
	ErrNoControlsDefined = errors.New("no controls defined")
	ErrPluginValidation  = errors.New("plugin validation failed")
	ErrComplianceAudit   = errors.New("compliance audit failed")
)
