package cmd

import (
	"bytes"
	"testing"
)

// BenchmarkStartupVersion measures startup time for the version command.
// Target: <100ms for lightweight commands.
func BenchmarkStartupVersion(b *testing.B) {
	b.ReportAllocs()

	for b.Loop() {
		cmd := GetRootCmd()
		cmd.SetArgs([]string{"version"})
		cmd.SetOut(&bytes.Buffer{})
		cmd.SetErr(&bytes.Buffer{})
		//nolint:errcheck,gosec // Benchmark doesn't need error handling
		cmd.Execute()
	}
}

// BenchmarkStartupHelp measures startup time for the help command.
// Target: <100ms for lightweight commands.
func BenchmarkStartupHelp(b *testing.B) {
	b.ReportAllocs()

	for b.Loop() {
		cmd := GetRootCmd()
		cmd.SetArgs([]string{"--help"})
		cmd.SetOut(&bytes.Buffer{})
		cmd.SetErr(&bytes.Buffer{})
		//nolint:errcheck,gosec // Benchmark doesn't need error handling
		cmd.Execute()
	}
}

// BenchmarkIsLightweightCommand measures the lightweight check overhead.
func BenchmarkIsLightweightCommand(b *testing.B) {
	cmd := GetRootCmd()
	versionCmd, _, err := cmd.Find([]string{"version"})
	if err != nil {
		b.Fatalf("failed to find version command: %v", err)
	}

	b.ResetTimer()
	for b.Loop() {
		_ = isLightweightCommand(versionCmd)
	}
}

// TestLightweightCommands verifies that lightweight commands are identified correctly.
func TestLightweightCommands(t *testing.T) {
	t.Parallel()

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
			t.Parallel()

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
	t.Parallel()

	cmd := GetRootCmd()
	versionCmd, _, err := cmd.Find([]string{"version"})
	if err != nil {
		t.Fatalf("failed to find version command: %v", err)
	}

	if !isLightweightCommand(versionCmd) {
		t.Error("version command should be identified as lightweight")
	}
}
