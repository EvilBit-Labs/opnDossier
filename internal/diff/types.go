// Package diff provides configuration comparison functionality for OPNsense configurations.
package diff

import (
	"slices"
	"time"
)

// ChangeType represents the type of configuration change.
type ChangeType string

const (
	// ChangeAdded indicates a new element was added.
	ChangeAdded ChangeType = "added"
	// ChangeRemoved indicates an element was removed.
	ChangeRemoved ChangeType = "removed"
	// ChangeModified indicates an element was modified.
	ChangeModified ChangeType = "modified"
)

// String returns the string representation of the change type.
func (c ChangeType) String() string {
	return string(c)
}

// Symbol returns a single-character symbol for the change type.
func (c ChangeType) Symbol() string {
	switch c {
	case ChangeAdded:
		return "+"
	case ChangeRemoved:
		return "-"
	case ChangeModified:
		return "~"
	default:
		return "?"
	}
}

// Section represents a configuration section.
type Section string

const (
	// SectionSystem represents system configuration.
	SectionSystem Section = "system"
	// SectionFirewall represents firewall rules.
	SectionFirewall Section = "firewall"
	// SectionNAT represents NAT configuration.
	SectionNAT Section = "nat"
	// SectionInterfaces represents interface configuration.
	SectionInterfaces Section = "interfaces"
	// SectionVLANs represents VLAN configuration.
	SectionVLANs Section = "vlans"
	// SectionDHCP represents DHCP configuration.
	SectionDHCP Section = "dhcp"
	// SectionDNS represents DNS configuration.
	SectionDNS Section = "dns"
	// SectionVPN represents VPN configuration.
	SectionVPN Section = "vpn"
	// SectionUsers represents user configuration.
	SectionUsers Section = "users"
	// SectionRouting represents routing configuration.
	SectionRouting Section = "routing"
	// SectionCertificates represents certificate configuration.
	SectionCertificates Section = "certificates"
)

// String returns the string representation of the section.
func (s Section) String() string {
	return string(s)
}

// AllSections returns all available sections.
func AllSections() []Section {
	return []Section{
		SectionSystem,
		SectionFirewall,
		SectionNAT,
		SectionInterfaces,
		SectionVLANs,
		SectionDHCP,
		SectionDNS,
		SectionVPN,
		SectionUsers,
		SectionRouting,
		SectionCertificates,
	}
}

// Change represents a single configuration change.
type Change struct {
	Type           ChangeType `json:"type"`
	Section        Section    `json:"section"`
	Path           string     `json:"path"`
	Description    string     `json:"description"`
	OldValue       string     `json:"old_value,omitempty"`
	NewValue       string     `json:"new_value,omitempty"`
	SecurityImpact string     `json:"security_impact,omitempty"`
}

// Summary contains aggregate statistics about the diff.
type Summary struct {
	Added    int `json:"added"`
	Removed  int `json:"removed"`
	Modified int `json:"modified"`
	Total    int `json:"total"`
}

// Metadata contains comparison metadata.
type Metadata struct {
	OldFile     string    `json:"old_file"`
	NewFile     string    `json:"new_file"`
	OldVersion  string    `json:"old_version,omitempty"`
	NewVersion  string    `json:"new_version,omitempty"`
	ComparedAt  time.Time `json:"compared_at"`
	ToolVersion string    `json:"tool_version"`
}

// Result contains the complete diff result.
type Result struct {
	Summary  Summary  `json:"summary"`
	Metadata Metadata `json:"metadata"`
	Changes  []Change `json:"changes"`
}

// NewResult creates a new Result with initialized slices.
func NewResult() *Result {
	return &Result{
		Changes: make([]Change, 0),
	}
}

// AddChange adds a change to the result and updates the summary.
func (r *Result) AddChange(change Change) {
	r.Changes = append(r.Changes, change)
	switch change.Type {
	case ChangeAdded:
		r.Summary.Added++
	case ChangeRemoved:
		r.Summary.Removed++
	case ChangeModified:
		r.Summary.Modified++
	}
	r.Summary.Total++
}

// ChangesBySection returns changes grouped by section.
func (r *Result) ChangesBySection() map[Section][]Change {
	result := make(map[Section][]Change)
	for _, change := range r.Changes {
		result[change.Section] = append(result[change.Section], change)
	}
	return result
}

// HasChanges returns true if there are any changes.
func (r *Result) HasChanges() bool {
	return r.Summary.Total > 0
}

// Options configures diff behavior.
type Options struct {
	Sections     []string // Filter to specific sections (empty = all)
	SecurityOnly bool     // Show only security-relevant changes
	Format       string   // Output format (terminal, markdown, json)
}

// ShouldIncludeSection returns true if the section should be included.
func (o *Options) ShouldIncludeSection(section Section) bool {
	if len(o.Sections) == 0 {
		return true
	}
	return slices.Contains(o.Sections, section.String())
}
