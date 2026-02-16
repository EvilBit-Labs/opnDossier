package builder

import (
	"testing"
)

func TestConstants(t *testing.T) {
	t.Parallel()

	// Test time constants
	tests := []struct {
		name     string
		constant int
		expected int
	}{
		{"secondsPerMinute", secondsPerMinute, 60},
		{"secondsPerHour", secondsPerHour, 3600},
		{"secondsPerDay", secondsPerDay, 86400},
		{"secondsPerWeek", secondsPerWeek, 604800},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if tt.constant != tt.expected {
				t.Errorf("%s = %d, want %d", tt.name, tt.constant, tt.expected)
			}
		})
	}

	// Test string constant
	if destinationAny != "any" {
		t.Errorf("destinationAny = %q, want %q", destinationAny, "any")
	}

	// Verify time constant relationships
	if secondsPerMinute*60 != secondsPerHour {
		t.Error("secondsPerHour should equal secondsPerMinute * 60")
	}
	if secondsPerHour*24 != secondsPerDay {
		t.Error("secondsPerDay should equal secondsPerHour * 24")
	}
	if secondsPerDay*7 != secondsPerWeek {
		t.Error("secondsPerWeek should equal secondsPerDay * 7")
	}
}
