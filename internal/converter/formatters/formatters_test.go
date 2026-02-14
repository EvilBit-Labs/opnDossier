package formatters

import (
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/model"
)

func TestFormatInterfacesAsLinks(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		interfaces model.InterfaceList
		want       string
	}{
		{
			name:       "empty list",
			interfaces: model.InterfaceList{},
			want:       "",
		},
		{
			name:       "single interface",
			interfaces: model.InterfaceList{"wan"},
			want:       "[wan](#wan-interface)",
		},
		{
			name:       "multiple interfaces",
			interfaces: model.InterfaceList{"wan", "lan"},
			want:       "[wan](#wan-interface), [lan](#lan-interface)",
		},
		{
			name:       "uppercase interface",
			interfaces: model.InterfaceList{"WAN"},
			want:       "[WAN](#wan-interface)",
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

func TestFormatBoolean(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		value string
		want  string
	}{
		{"one is checkmark", "1", "✓"},
		{"true is checkmark", "true", "✓"},
		{"on is checkmark", "on", "✓"},
		{"zero is xmark", "0", "✗"},
		{"false is xmark", "false", "✗"},
		{"empty is xmark", "", "✗"},
		{"random is xmark", "random", "✗"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := FormatBoolean(tt.value)
			if got != tt.want {
				t.Errorf("FormatBoolean(%q) = %q, want %q", tt.value, got, tt.want)
			}
		})
	}
}

func TestFormatBooleanInverted(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		value string
		want  string
	}{
		{"one is xmark (inverted)", "1", "✗"},
		{"true is xmark (inverted)", "true", "✗"},
		{"on is xmark (inverted)", "on", "✗"},
		{"zero is checkmark (inverted)", "0", "✓"},
		{"false is checkmark (inverted)", "false", "✓"},
		{"empty is checkmark (inverted)", "", "✓"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := FormatBooleanInverted(tt.value)
			if got != tt.want {
				t.Errorf("FormatBooleanInverted(%q) = %q, want %q", tt.value, got, tt.want)
			}
		})
	}
}

func TestFormatBoolFlag(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		value model.BoolFlag
		want  string
	}{
		{"true returns checkmark", true, "✓"},
		{"false returns x-mark", false, "✗"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := FormatBoolFlag(tt.value); got != tt.want {
				t.Errorf("FormatBoolFlag(%v) = %q, want %q", tt.value, got, tt.want)
			}
		})
	}
}

func TestFormatBoolFlagInverted(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		value model.BoolFlag
		want  string
	}{
		{"true returns x-mark (inverted)", true, "✗"},
		{"false returns checkmark (inverted)", false, "✓"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := FormatBoolFlagInverted(tt.value); got != tt.want {
				t.Errorf("FormatBoolFlagInverted(%v) = %q, want %q", tt.value, got, tt.want)
			}
		})
	}
}

func TestFormatIntBoolean(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		value int
		want  string
	}{
		{"one is checkmark", 1, "✓"},
		{"zero is xmark", 0, "✗"},
		{"negative is xmark", -1, "✗"},
		{"positive is xmark", 2, "✗"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := FormatIntBoolean(tt.value)
			if got != tt.want {
				t.Errorf("FormatIntBoolean(%d) = %q, want %q", tt.value, got, tt.want)
			}
		})
	}
}

func TestFormatIntBooleanWithUnset(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		value int
		want  string
	}{
		{"zero is unset", 0, "unset"},
		{"one is checkmark", 1, "✓"},
		{"negative is xmark", -1, "✗"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := FormatIntBooleanWithUnset(tt.value)
			if got != tt.want {
				t.Errorf("FormatIntBooleanWithUnset(%d) = %q, want %q", tt.value, got, tt.want)
			}
		})
	}
}

func TestFormatStructBoolean(t *testing.T) {
	t.Parallel()

	got := FormatStructBoolean(struct{}{})
	if got != "✓" {
		t.Errorf("FormatStructBoolean() = %q, want %q", got, "✓")
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

func TestGetPowerModeDescription(t *testing.T) {
	t.Parallel()

	tests := []struct {
		mode string
		want string
	}{
		{"hadp", "High Performance with Dynamic Power Management"},
		{"hiadp", "High Performance with Adaptive Dynamic Power Management"},
		{"adaptive", "Adaptive Power Management"},
		{"minimum", "Minimum Power Consumption"},
		{"maximum", "Maximum Performance"},
		{"unknown", "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.mode, func(t *testing.T) {
			t.Parallel()
			got := GetPowerModeDescription(tt.mode)
			if got != tt.want {
				t.Errorf("GetPowerModeDescription(%q) = %q, want %q", tt.mode, got, tt.want)
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

func TestIsTruthy(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		value any
		want  bool
	}{
		// Truthy values
		{"string 1", "1", true},
		{"string yes", "yes", true},
		{"string YES", "YES", true},
		{"string true", "true", true},
		{"string on", "on", true},
		{"string enabled", "enabled", true},
		{"string active", "active", true},
		{"positive number string", "5", true},
		{"positive float string", "0.5", true},

		// Falsy values
		{"nil", nil, false},
		{"string 0", "0", false},
		{"string no", "no", false},
		{"string false", "false", false},
		{"string off", "off", false},
		{"string disabled", "disabled", false},
		{"string inactive", "inactive", false},
		{"empty string", "", false},
		{"string -1", "-1", false},
		{"negative number string", "-5", false},
		{"zero float string", "0.0", false},
		{"random string", "random", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := IsTruthy(tt.value)
			if got != tt.want {
				t.Errorf("IsTruthy(%v) = %v, want %v", tt.value, got, tt.want)
			}
		})
	}
}

func TestFormatBooleanCheckbox(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		value any
		want  string
	}{
		{"truthy 1", "1", "[x]"},
		{"truthy yes", "yes", "[x]"},
		{"falsy 0", "0", "[ ]"},
		{"falsy no", "no", "[ ]"},
		{"nil", nil, "[ ]"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := FormatBooleanCheckbox(tt.value)
			if got != tt.want {
				t.Errorf("FormatBooleanCheckbox(%v) = %q, want %q", tt.value, got, tt.want)
			}
		})
	}
}

func TestFormatBooleanWithUnset(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		value any
		want  string
	}{
		{"truthy 1", "1", "[x]"},
		{"truthy yes", "yes", "[x]"},
		{"falsy 0", "0", "[ ]"},
		{"unset -1", "-1", "unset"},
		{"nil", nil, "[ ]"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := FormatBooleanWithUnset(tt.value)
			if got != tt.want {
				t.Errorf("FormatBooleanWithUnset(%v) = %q, want %q", tt.value, got, tt.want)
			}
		})
	}
}

func TestFormatUnixTimestamp(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		timestamp string
		want      string
	}{
		{"empty timestamp", "", "-"},
		{"valid timestamp", "1609459200", "2021-01-01T00:00:00Z"},
		{"invalid timestamp", "not-a-number", "not-a-number"},
		{"floating point timestamp", "1609459200.5", "2021-01-01T00:00:00Z"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := FormatUnixTimestamp(tt.timestamp)
			// For valid timestamps, just check format is correct (timezone may vary)
			if tt.name == "valid timestamp" || tt.name == "floating point timestamp" {
				if len(got) < 10 || got[4] != '-' || got[7] != '-' {
					t.Errorf("FormatUnixTimestamp(%q) = %q, doesn't look like ISO 8601", tt.timestamp, got)
				}
			} else if got != tt.want {
				t.Errorf("FormatUnixTimestamp(%q) = %q, want %q", tt.timestamp, got, tt.want)
			}
		})
	}
}
