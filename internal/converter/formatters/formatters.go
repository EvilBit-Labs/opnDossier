// Package formatters provides utility functions for formatting data in markdown reports.
package formatters

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/EvilBit-Labs/opnDossier/internal/model"
	"github.com/nao1215/markdown"
)

const (
	checkboxChecked   = "[x]"
	checkboxUnchecked = "[ ]"
	checkmark         = "✓"
	xMark             = "✗"
	boolStringOne     = "1"
	boolStringTrue    = "true"
	boolStringOn      = "on"
)

// FormatInterfacesAsLinks formats a list of interfaces as markdown links pointing to their respective sections.
// Each interface name is converted to a clickable link that references the corresponding interface configuration section.
// The function returns inline markdown links (e.g., [wan](#wan-interface)), which the nao1215/markdown package
// automatically converts to reference-style links when used in table cells.
func FormatInterfacesAsLinks(interfaces model.InterfaceList) string {
	if interfaces.IsEmpty() {
		return ""
	}

	links := make([]string, 0, len(interfaces))
	for _, iface := range interfaces {
		anchor := "#" + strings.ToLower(iface) + "-interface"
		links = append(links, markdown.Link(iface, anchor))
	}

	return strings.Join(links, ", ")
}

// FormatBoolean formats a boolean value for display in markdown tables.
func FormatBoolean(value string) string {
	if value == boolStringOne || value == boolStringTrue || value == boolStringOn {
		return checkmark
	}
	return xMark
}

// FormatBoolFlag formats a BoolFlag for display in markdown tables.
// true → ✓, false → ✗.
func FormatBoolFlag(value model.BoolFlag) string {
	if value {
		return checkmark
	}
	return xMark
}

// FormatBoolFlagInverted formats a BoolFlag with inverted logic for display in markdown tables.
// This is used for fields like "Disabled" where true means disabled (✗) and false means enabled (✓).
func FormatBoolFlagInverted(value model.BoolFlag) string {
	if value {
		return xMark
	}
	return checkmark
}

// FormatIntBoolean formats an integer boolean value for display in markdown tables.
func FormatIntBoolean(value int) string {
	if value == 1 {
		return checkmark
	}
	return xMark
}

// FormatIntBooleanWithUnset formats an integer boolean value with support for unset states.
func FormatIntBooleanWithUnset(value int) string {
	if value == 0 {
		return "unset"
	}
	return FormatIntBoolean(value)
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

// GetPowerModeDescription converts power management mode acronyms to their full descriptions for templates.
func GetPowerModeDescription(mode string) string {
	switch mode {
	case "hadp":
		return "High Performance with Dynamic Power Management"
	case "hiadp":
		return "High Performance with Adaptive Dynamic Power Management"
	case "adaptive":
		return "Adaptive Power Management"
	case "minimum":
		return "Minimum Power Consumption"
	case "maximum":
		return "Maximum Performance"
	default:
		return mode
	}
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

// IsTruthy determines if a value represents a "true" or "enabled" state.
// Handles various formats: "1", "yes", "true", "on", "enabled", etc.
// Treats -1 as "unset" and returns false for it.
func IsTruthy(value any) bool {
	if value == nil {
		return false
	}

	str := strings.ToLower(strings.TrimSpace(fmt.Sprintf("%v", value)))

	switch str {
	case "1", "yes", "true", "on", "enabled", "active":
		return true
	case "0", "no", "false", "off", "disabled", "inactive", "", "-1":
		return false
	default:
		if num, err := strconv.ParseFloat(str, 64); err == nil {
			return num > 0
		}
		return false
	}
}

// FormatBooleanCheckbox formats a boolean value consistently using markdown checkboxes.
func FormatBooleanCheckbox(value any) string {
	if IsTruthy(value) {
		return checkboxChecked
	}
	return checkboxUnchecked
}

// FormatBooleanWithUnset formats a boolean value, showing "unset" for -1 values.
func FormatBooleanWithUnset(value any) string {
	if value == nil {
		return checkboxUnchecked
	}

	str := strings.TrimSpace(fmt.Sprintf("%v", value))
	if str == "-1" {
		return "unset"
	}

	if IsTruthy(value) {
		return checkboxChecked
	}
	return checkboxUnchecked
}

// FormatUnixTimestamp converts a Unix timestamp string to an ISO 8601 formatted date.
func FormatUnixTimestamp(timestamp string) string {
	if timestamp == "" {
		return "-"
	}

	ts, err := strconv.ParseFloat(timestamp, 64)
	if err != nil {
		return timestamp
	}

	timeValue := time.Unix(int64(ts), int64((ts-float64(int64(ts)))*float64(time.Second)))

	return timeValue.Format("2006-01-02T15:04:05Z07:00")
}

// FormatWithSuffix appends a suffix to a value, returning "N/A" if the value is empty.
func FormatWithSuffix(value, suffix string) string {
	if value == "" {
		return "N/A"
	}
	return value + suffix
}
