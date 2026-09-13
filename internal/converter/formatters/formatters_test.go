package formatters

import (
	"testing"
)

func TestFormatInterfacesAsLinks(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		interfaces []string
		want       string
	}{
		{
			name:       "empty list",
			interfaces: []string{},
			want:       "",
		},
		{
			name:       "single interface",
			interfaces: []string{"wan"},
			want:       "[wan](#wan-interface)",
		},
		{
			name:       "multiple interfaces",
			interfaces: []string{"wan", "lan"},
			want:       "[wan](#wan-interface), [lan](#lan-interface)",
		},
		{
			name:       "uppercase interface",
			interfaces: []string{"WAN"},
			want:       "[WAN](#wan-interface)",
		},
		{
			// Pins the byte-identity invariant after the strings.Builder
			// rewrite replaced markdown.Link / strings.Join. The output
			// must remain "[<label>](#<lower>-interface), ..." for every
			// element including mixed case.
			name:       "mixed case multi-element",
			interfaces: []string{"WAN", "lan", "OPT1"},
			want:       "[WAN](#wan-interface), [lan](#lan-interface), [OPT1](#opt1-interface)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := FormatInterfacesAsLinks(tt.interfaces)
			if got != tt.want {
				t.Errorf("FormatInterfacesAsLinks() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestFormatBool(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		value bool
		want  string
	}{
		{"true is checkmark", true, "✓"},
		{"false is xmark", false, "✗"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := FormatBool(tt.value)
			if got != tt.want {
				t.Errorf("FormatBool(%v) = %q, want %q", tt.value, got, tt.want)
			}
		})
	}
}

func TestGetPowerModeDescriptionCompact(t *testing.T) {
	t.Parallel()

	tests := []struct {
		mode string
		want string
	}{
		{"hadp", "Adaptive (hadp)"},
		{"maximum", "Maximum Performance (maximum)"},
		{"minimum", "Minimum Power (minimum)"},
		{"hiadaptive", "High Adaptive (hiadaptive)"},
		{"adaptive", "Adaptive (adaptive)"},
		{"unknown", "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.mode, func(t *testing.T) {
			t.Parallel()
			got := GetPowerModeDescriptionCompact(tt.mode)
			if got != tt.want {
				t.Errorf("GetPowerModeDescriptionCompact(%q) = %q, want %q", tt.mode, got, tt.want)
			}
		})
	}
}

func TestFormatBoolStatus(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		value bool
		want  string
	}{
		{"true returns enabled", true, "Enabled"},
		{"false returns disabled", false, "Disabled"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := FormatBoolStatus(tt.value)
			if got != tt.want {
				t.Errorf("FormatBoolStatus(%v) = %q, want %q", tt.value, got, tt.want)
			}
		})
	}
}
