package compliance

import (
	"maps"
	"slices"

	"github.com/EvilBit-Labs/opnDossier/internal/model/common"
)

// Plugin defines the interface that all compliance plugins must implement.
// This interface is designed to be loosely coupled and focused on CommonDevice.
type Plugin interface {
	// Name returns the unique name of the compliance standard
	Name() string

	// Version returns the version of the compliance standard
	Version() string

	// Description returns a brief description of the compliance standard
	Description() string

	// RunChecks performs compliance checks against the device configuration
	// Returns standardized findings that can be processed by the plugin manager
	RunChecks(device *common.CommonDevice) []Finding

	// GetControls returns all controls defined by this compliance standard
	GetControls() []Control

	// GetControlByID returns a specific control by its ID
	GetControlByID(id string) (*Control, error)

	// ValidateConfiguration validates the plugin's configuration
	ValidateConfiguration() error
}

// Control represents a single compliance control.
// This is a standardized structure that all plugins must use.
type Control struct {
	ID          string            `json:"id"`
	Title       string            `json:"title"`
	Description string            `json:"description"`
	Category    string            `json:"category"`
	Severity    string            `json:"severity"`
	Rationale   string            `json:"rationale"`
	Remediation string            `json:"remediation"`
	References  []string          `json:"references,omitempty"`
	Tags        []string          `json:"tags,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

// CloneControl returns a deep copy of a Control, cloning nested reference
// types (References, Tags, Metadata) so mutations to the copy do not affect
// the original.
func CloneControl(c Control) Control {
	clone := c
	clone.References = slices.Clone(c.References)
	clone.Tags = slices.Clone(c.Tags)
	clone.Metadata = maps.Clone(c.Metadata)

	return clone
}

// CloneControls returns a deep copy of a slice of Controls.
func CloneControls(controls []Control) []Control {
	cloned := make([]Control, len(controls))
	for i, c := range controls {
		cloned[i] = CloneControl(c)
	}

	return cloned
}

// Finding represents a standardized finding that all plugins must return.
// This ensures consistent data structure for the plugin manager to process.
type Finding struct {
	// Core finding information
	Type           string `json:"type"`
	Severity       string `json:"severity,omitempty"`
	Title          string `json:"title"`
	Description    string `json:"description"`
	Recommendation string `json:"recommendation"`
	Component      string `json:"component"`
	Reference      string `json:"reference"`

	// Generic references and metadata
	References []string          `json:"references,omitempty"`
	Tags       []string          `json:"tags,omitempty"`
	Metadata   map[string]string `json:"metadata,omitempty"`
}
