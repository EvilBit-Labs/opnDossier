// Package model defines the data structures for OPNsense configurations.
package model

// Package represents a software package in the system.
// This struct is used for aggregating package statistics and filtering.
type Package struct {
	Name      string `xml:"name"      json:"name"                  yaml:"name"                  validate:"required"`
	Version   string `xml:"version"   json:"version,omitempty"     yaml:"version,omitempty"`
	Installed bool   `xml:"installed" json:"installed"             yaml:"installed"`
	Locked    bool   `xml:"locked"    json:"locked"                yaml:"locked"`
	Automatic bool   `xml:"automatic" json:"automatic"             yaml:"automatic"`
	Descr     string `xml:"descr"     json:"description,omitempty" yaml:"description,omitempty"`
}

// Service represents a system service.
// This struct is used for service status grouping and analysis.
type Service struct {
	Name        string `xml:"name"        json:"name"                  yaml:"name"                  validate:"required"`
	Status      string `xml:"status"      json:"status"                yaml:"status"                validate:"required,oneof=running stopped disabled"`
	Description string `xml:"description" json:"description,omitempty" yaml:"description,omitempty"`
	Enabled     bool   `xml:"enabled"     json:"enabled"               yaml:"enabled"`
	PID         int    `xml:"pid"         json:"pid,omitempty"         yaml:"pid,omitempty"`
}

// Constructor functions

// NewPackage returns a new Package instance with default values.
func NewPackage() Package {
	return Package{
		Installed: false,
		Locked:    false,
		Automatic: false,
	}
}

// NewService returns a new Service instance with default values.
func NewService() Service {
	return Service{
		Status:  "stopped",
		Enabled: false,
		PID:     0,
	}
}
