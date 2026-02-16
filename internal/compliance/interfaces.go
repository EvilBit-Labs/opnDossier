package compliance

import (
	"github.com/EvilBit-Labs/opnDossier/internal/model"
)

// Plugin defines the interface that all compliance plugins must implement.
// This interface is designed to be loosely coupled and focused only on OpnSenseDocument.
type Plugin interface {
	// Name returns the unique name of the compliance standard
	Name() string

	// Version returns the version of the compliance standard
	Version() string

	// Description returns a brief description of the compliance standard
	Description() string

	// RunChecks performs compliance checks against the OPNsense configuration
	// Returns standardized findings that can be processed by the plugin manager
	RunChecks(config *model.OpnSenseDocument) []Finding

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

// Finding represents a standardized finding that all plugins must return.
// This ensures consistent data structure for the plugin manager to process.
type Finding struct {
	// Core finding information
	Type           string `json:"type"`
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
