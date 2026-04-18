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

func TestIsValidSeverity(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		sev   common.Severity
		valid bool
	}{
		{"critical", common.SeverityCritical, true},
		{"high", common.SeverityHigh, true},
		{"medium", common.SeverityMedium, true},
		{"low", common.SeverityLow, true},
		{"info", common.SeverityInfo, true},
		{"empty string", common.Severity(""), false},
		{"uppercase critical", common.Severity("CRITICAL"), false},
		{"mixed case", common.Severity("Info"), false},
		{"unknown value", common.Severity("fatal"), false},
		{"whitespace", common.Severity(" info"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := common.IsValidSeverity(tt.sev); got != tt.valid {
				t.Errorf("IsValidSeverity(%q) = %v, want %v", tt.sev, got, tt.valid)
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
// slice to surface them.
func ExampleConversionWarning() {
	// Typical converter output.
	warnings := []common.ConversionWarning{
		{
			Field:    "FirewallRules[0].Type",
			Value:    "match",
			Message:  "unrecognized firewall rule type; rule will be skipped",
			Severity: common.SeverityHigh,
		},
		{
			Field:    "DHCP.Subnets[2].Pools",
			Value:    "lan-subnet",
			Message:  "multiple pools declared; only the first is represented in CommonDevice",
			Severity: common.SeverityMedium,
		},
	}

	for _, w := range warnings {
		fmt.Printf("[%s] %s: %s (value=%q)\n", w.Severity, w.Field, w.Message, w.Value)
	}

	// Output:
	// [high] FirewallRules[0].Type: unrecognized firewall rule type; rule will be skipped (value="match")
	// [medium] DHCP.Subnets[2].Pools: multiple pools declared; only the first is represented in CommonDevice (value="lan-subnet")
}
