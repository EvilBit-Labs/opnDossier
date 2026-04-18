package model_test

import (
	"fmt"
	"slices"
	"testing"

	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
)

func TestSeverity_String(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		sev      common.Severity
		expected string
	}{
		{"critical", common.SeverityCritical, "critical"},
		{"high", common.SeverityHigh, "high"},
		{"medium", common.SeverityMedium, "medium"},
		{"low", common.SeverityLow, "low"},
		{"info", common.SeverityInfo, "info"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.sev.String(); got != tt.expected {
				t.Errorf("Severity.String() = %q, want %q", got, tt.expected)
			}
		})
	}
}

// TestIsValidSeverity exercises the negative cases for IsValidSeverity. The
// positive cases (every value returned by ValidSeverities must satisfy
// IsValidSeverity) are already covered by TestValidSeverities_Coverage
// given that IsValidSeverity now shares a single source of truth with
// ValidSeverities via slices.Contains.
func TestIsValidSeverity(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		sev  common.Severity
	}{
		{"empty string", common.Severity("")},
		{"uppercase critical", common.Severity("CRITICAL")},
		{"mixed case", common.Severity("Info")},
		{"unknown value", common.Severity("fatal")},
		{"whitespace", common.Severity(" info")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := common.IsValidSeverity(tt.sev); got {
				t.Errorf("IsValidSeverity(%q) = true, want false", tt.sev)
			}
		})
	}
}

// TestValidSeverities_ReturnsFreshCopy protects the invariant that
// ValidSeverities returns a caller-owned slice: mutating the returned slice
// must not affect subsequent calls.
func TestValidSeverities_ReturnsFreshCopy(t *testing.T) {
	t.Parallel()

	first := common.ValidSeverities()
	if len(first) == 0 {
		t.Fatal("ValidSeverities returned empty slice")
	}

	// Mutate the returned slice.
	first[0] = common.Severity("mutated")

	second := common.ValidSeverities()
	if second[0] == common.Severity("mutated") {
		t.Error("ValidSeverities returned a shared slice; mutation bled into subsequent call")
	}

	// All returned values should be valid severities.
	for _, s := range second {
		if !common.IsValidSeverity(s) {
			t.Errorf("ValidSeverities returned unrecognized value %q", s)
		}
	}
}

func TestValidSeverities_Coverage(t *testing.T) {
	t.Parallel()

	got := common.ValidSeverities()
	want := []common.Severity{
		common.SeverityCritical,
		common.SeverityHigh,
		common.SeverityMedium,
		common.SeverityLow,
		common.SeverityInfo,
	}

	if len(got) != len(want) {
		t.Fatalf("ValidSeverities() returned %d values, want %d", len(got), len(want))
	}

	// Compare as sets to avoid coupling to declaration order.
	gotStrs := make([]string, len(got))
	wantStrs := make([]string, len(want))
	for i := range got {
		gotStrs[i] = string(got[i])
		wantStrs[i] = string(want[i])
	}
	slices.Sort(gotStrs)
	slices.Sort(wantStrs)
	for i := range gotStrs {
		if gotStrs[i] != wantStrs[i] {
			t.Errorf("ValidSeverities()[%d] = %q, want %q (after sort)", i, gotStrs[i], wantStrs[i])
		}
	}
}

// ExampleConversionWarning shows the producer/consumer pattern for
// ConversionWarning: converters emit warnings; callers iterate the returned
// slice to surface them. The warning shapes below mirror real converter
// output — the field paths, severities, and messages match what
// opnsense.ConvertDocument actually emits.
func ExampleConversionWarning() {
	warnings := []common.ConversionWarning{
		{
			Field:    "FirewallRules[0].Type",
			Value:    "match",
			Message:  "unrecognized firewall rule type",
			Severity: common.SeverityLow,
		},
		{
			Field:    "kea.dhcp4.subnets.subnet4.pools",
			Value:    "10.20.0.100-10.20.0.150\n10.20.0.200-10.20.0.250",
			Message:  "Kea subnet sub-1 has 2 pools; only the first is represented in the unified scope",
			Severity: common.SeverityInfo,
		},
	}

	for _, w := range warnings {
		fmt.Printf("[%s] %s: %s\n", w.Severity, w.Field, w.Message)
	}

	// Output:
	// [low] FirewallRules[0].Type: unrecognized firewall rule type
	// [info] kea.dhcp4.subnets.subnet4.pools: Kea subnet sub-1 has 2 pools; only the first is represented in the unified scope
}
