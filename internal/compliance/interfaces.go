package compliance

import (
	"maps"
	"slices"

	"github.com/EvilBit-Labs/opnDossier/internal/analysis"
	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
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

	// RunChecks performs compliance checks against the device configuration in a
	// single traversal. Returns:
	//   - findings: standardized findings produced by the evaluation.
	//   - evaluated: IDs of controls this plugin was able to evaluate against
	//     the provided device. Controls returned by GetControls() but NOT in
	//     this list are reported as UNKNOWN in the audit report.
	//   - err: a non-nil error aborts the audit for this plugin and is surfaced
	//     to the caller. Plugins SHOULD return (findings, evaluated, nil) on
	//     the happy path; use err only for unrecoverable conditions.
	//
	// Implementations MUST produce the evaluated slice in the same pass that
	// produces findings — do not re-run checks to rebuild evaluated. This
	// contract is why the legacy separate EvaluatedControlIDs method was
	// removed: two traversals doubled wall-clock cost for blue-mode audits.
	RunChecks(device *common.CommonDevice) (findings []Finding, evaluated []string, err error)

	// GetControls returns all controls defined by this compliance standard.
	// Implementations MUST return a defensive deep copy so callers cannot
	// mutate plugin-internal state (see compliance.CloneControls). Callers
	// therefore do NOT clone again.
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

// Finding is a type alias for the canonical analysis.Finding type.
// All plugins and consumers should use this type for standardized findings.
type Finding = analysis.Finding
