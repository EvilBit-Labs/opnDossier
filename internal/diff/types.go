// Package diff provides configuration comparison functionality for OPNsense configurations.
package diff

import (
	"slices"
	"strings"
	"time"

	"github.com/EvilBit-Labs/opnDossier/internal/diff/security"
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
	// ChangeReordered indicates an element was moved but not modified.
	ChangeReordered ChangeType = "reordered"
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
	case ChangeReordered:
		return "↕"
	default:
		return "?"
	}
}

// IsValid returns true if the change type is a valid value.
func (c ChangeType) IsValid() bool {
	switch c {
	case ChangeAdded, ChangeRemoved, ChangeModified, ChangeReordered:
		return true
	default:
		return false
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

// ImplementedSections returns sections that have comparison logic implemented.
func ImplementedSections() []Section {
	return []Section{
		SectionSystem,
		SectionFirewall,
		SectionNAT,
		SectionInterfaces,
		SectionVLANs,
		SectionDHCP,
		SectionUsers,
		SectionRouting,
	}
}

// IsValid returns true if the section is a valid value.
func (s Section) IsValid() bool {
	return slices.Contains(AllSections(), s)
}

// IsImplemented returns true if the section has comparison logic implemented.
func (s Section) IsImplemented() bool {
	return slices.Contains(ImplementedSections(), s)
}

// SecurityImpact represents the security impact level of a change.
type SecurityImpact string

const (
	// SecurityImpactHigh indicates a high security impact (e.g., permissive any-any rules).
	SecurityImpactHigh SecurityImpact = "high"
	// SecurityImpactMedium indicates a medium security impact (e.g., user changes, NAT modifications).
	SecurityImpactMedium SecurityImpact = "medium"
	// SecurityImpactLow indicates a low security impact (e.g., minor configuration changes).
	SecurityImpactLow SecurityImpact = "low"
)

// String returns the string representation of the security impact.
func (s SecurityImpact) String() string {
	return string(s)
}

// IsValid returns true if the security impact is a valid value.
func (s SecurityImpact) IsValid() bool {
	switch s {
	case SecurityImpactHigh, SecurityImpactMedium, SecurityImpactLow, "":
		return true
	default:
		return false
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
	Added     int `json:"added"`
	Removed   int `json:"removed"`
	Modified  int `json:"modified"`
	Reordered int `json:"reordered"`
	Total     int `json:"total"`
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

// RiskSummary is an alias for security.RiskSummary to avoid type duplication.
type RiskSummary = security.RiskSummary

// RiskItem is an alias for security.RiskItem to avoid type duplication.
type RiskItem = security.RiskItem

// DeviceTypeInfo records the device types of the compared configurations.
type DeviceTypeInfo struct {
	Old string `json:"old"`
	New string `json:"new"`
}

// Result contains the complete diff result.
type Result struct {
	Summary     Summary        `json:"summary"`
	Metadata    Metadata       `json:"metadata"`
	DeviceType  DeviceTypeInfo `json:"device_type"`
	Changes     []Change       `json:"changes"`
	RiskSummary RiskSummary    `json:"risk_summary"`
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
	case ChangeReordered:
		r.Summary.Reordered++
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
	Format       string   // Output format (terminal, markdown, json, html)
	Normalize    bool     // Normalize displayed values to reduce noise (whitespace, IPs, ports)
	DetectOrder  bool     // Detect reordered rules without content changes
	Mode         string   // Display mode (unified, side-by-side)
}

// ShouldIncludeSection returns true if the section should be included.
// Comparison is case-insensitive to handle user input normalization.
func (o *Options) ShouldIncludeSection(section Section) bool {
	if len(o.Sections) == 0 {
		return true
	}
	return slices.ContainsFunc(o.Sections, func(s string) bool {
		return strings.EqualFold(s, section.String())
	})
}
