package common

// Package represents an installed or available software package.
type Package struct {
	// Name is the package name.
	Name string `json:"name,omitempty" yaml:"name,omitempty"`
	// Version is the package version string.
	Version string `json:"version,omitempty" yaml:"version,omitempty"`
	// Type classifies the package (e.g., "package", "plugin", "module", "license").
	Type string `json:"type,omitempty" yaml:"type,omitempty"`
	// Installed indicates the package is currently installed.
	Installed bool `json:"installed,omitempty" yaml:"installed,omitempty"`
	// Locked indicates the package version is pinned and should not be auto-updated.
	Locked bool `json:"locked,omitempty" yaml:"locked,omitempty"`
	// Automatic indicates the package was installed as a dependency.
	Automatic bool `json:"automatic,omitempty" yaml:"automatic,omitempty"`
	// Description is a human-readable description of the package.
	Description string `json:"description,omitempty" yaml:"description,omitempty"`
}
