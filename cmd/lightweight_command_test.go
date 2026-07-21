package cmd

import (
	"testing"
)

// TestLightweightCommands verifies that lightweight commands are identified correctly.
func TestLightweightCommands(t *testing.T) {
	// Do NOT use t.Parallel() — cmd package uses package-level flag globals.
	// See GOTCHAS §1.1.
	tests := []struct {
		name     string
		cmdName  string
		expected bool
	}{
		{"version is lightweight", "version", true},
		{"help is lightweight", "help", true},
		{"completion is lightweight", "completion", true},
		{"convert is not lightweight", "convert", false},
		{"validate is not lightweight", "validate", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Do NOT use t.Parallel() — cmd package uses package-level flag globals.
			// See GOTCHAS §1.1.
			// Check if command name is in lightweight list
			if lightweightCommands[tt.cmdName] != tt.expected {
				t.Errorf("lightweightCommands[%q] = %v, want %v",
					tt.cmdName, lightweightCommands[tt.cmdName], tt.expected)
			}
		})
	}
}

// TestVersionCommandFastPath tests that version command uses fast path.
func TestVersionCommandFastPath(t *testing.T) {
	// Do NOT use t.Parallel() — cmd package uses package-level flag globals.
	// See GOTCHAS §1.1.
	cmd := GetRootCmd()
	versionCmd, _, err := cmd.Find([]string{"version"})
	if err != nil {
		t.Fatalf("failed to find version command: %v", err)
	}

	if !isLightweightCommand(versionCmd) {
		t.Error("version command should be identified as lightweight")
	}
}
