// Package formatters provides utility functions for formatting data in markdown reports.
package formatters

import (
	"strings"
)

// Display symbols used for formatting report output.
const (
	checkmark = "✓"
	xMark     = "✗"
)

// FormatInterfacesAsLinks formats a list of interfaces as markdown links pointing to their respective sections.
// Each interface name is converted to a clickable link that references the corresponding interface configuration section.
// The function returns inline markdown links (e.g., [wan](#wan-interface)), which the nao1215/markdown package
// automatically converts to reference-style links when used in table cells.
//
// Implementation note: this is a hot path inside per-row markdown table
// builders. The body uses a pre-grown strings.Builder rather than
// markdown.Link + strings.Join to avoid the intermediate []string and
// the per-link string allocations the markdown helper performs. Output
// is byte-identical to the prior markdown.Link / strings.Join form.
func FormatInterfacesAsLinks(interfaces []string) string {
	if len(interfaces) == 0 {
		return ""
	}

	// Per-link literal overhead: "[](#-interface)" = 15 bytes, plus the
	// interface name appears twice (display label + anchor slug). Inter-
	// link separator ", " adds 2 bytes between entries.
	const (
		perLinkOverhead = 15
		ifaceCopies     = 2
		separatorBytes  = 2
	)
	estimated := 0
	for _, iface := range interfaces {
		estimated += ifaceCopies*len(iface) + perLinkOverhead
	}
	if len(interfaces) > 1 {
		estimated += separatorBytes * (len(interfaces) - 1)
	}

	var b strings.Builder
	b.Grow(estimated)
	for i, iface := range interfaces {
		if i > 0 {
			b.WriteString(", ")
		}
		// The name comes from config.xml, and both halves of a markdown link are
		// breakable: a "]" ends the label early and a ")" ends the destination,
		// after which the rest of the name is parsed as markup. The label is
		// escaped and the destination is reduced to an anchor slug, which can
		// contain neither character. SanitizeID leaves ordinary names such as
		// "wan" untouched, so existing links still resolve.
		b.WriteByte('[')
		b.WriteString(EscapeMarkdownValue(iface))
		b.WriteString("](#")
		b.WriteString(SanitizeID(iface))
		b.WriteString("-interface)")
	}
	return b.String()
}

// FormatBoolInverted formats a boolean with inverted logic for display in markdown tables.
// This is used for fields like "Disabled" where true means disabled (✗) and false means enabled (✓).
func FormatBoolInverted(value bool) string {
	if value {
		return xMark
	}
	return checkmark
}

// FormatBool formats a boolean value for display in markdown tables.
func FormatBool(value bool) string {
	if value {
		return checkmark
	}
	return xMark
}

// FormatBoolStatus formats a boolean value as "Enabled" or "Disabled".
func FormatBoolStatus(value bool) string {
	if value {
		return "Enabled"
	}
	return "Disabled"
}

// GetPowerModeDescriptionCompact returns a compact description of power management modes.
func GetPowerModeDescriptionCompact(mode string) string {
	switch mode {
	case "hadp":
		return "Adaptive (hadp)"
	case "maximum":
		return "Maximum Performance (maximum)"
	case "minimum":
		return "Minimum Power (minimum)"
	case "hiadaptive":
		return "High Adaptive (hiadaptive)"
	case "adaptive":
		return "Adaptive (adaptive)"
	default:
		return mode
	}
}
