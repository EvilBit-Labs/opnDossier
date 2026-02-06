package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/sanitizer"
	"github.com/spf13/cobra"
)

func TestValidSanitizeModes(t *testing.T) {
	completions, directive := ValidSanitizeModes(nil, nil, "")

	if directive != cobra.ShellCompDirectiveNoFileComp {
		t.Errorf("expected ShellCompDirectiveNoFileComp, got %d", directive)
	}

	if len(completions) != 3 {
		t.Errorf("expected 3 completions, got %d", len(completions))
	}

	// Verify all modes are present
	expectedModes := []string{SanitizeModeAggressive, SanitizeModeModerate, SanitizeModeMinimal}
	for _, mode := range expectedModes {
		found := false
		for _, c := range completions {
			if strings.HasPrefix(c, mode) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("mode %q not found in completions", mode)
		}
	}
}

func TestSanitizeCommandFlags(t *testing.T) {
	// Verify the sanitize command has expected flags
	flags := sanitizeCmd.Flags()

	// Mode flag
	modeFlag := flags.Lookup("mode")
	if modeFlag == nil {
		t.Error("expected --mode flag to exist")
	} else {
		if modeFlag.Shorthand != "m" {
			t.Errorf("mode flag shorthand = %q, want %q", modeFlag.Shorthand, "m")
		}
		if modeFlag.DefValue != SanitizeModeModerate {
			t.Errorf("mode flag default = %q, want %q", modeFlag.DefValue, SanitizeModeModerate)
		}
	}

	// Output flag
	outputFlag := flags.Lookup("output")
	if outputFlag == nil {
		t.Error("expected --output flag to exist")
	} else if outputFlag.Shorthand != "o" {
		t.Errorf("output flag shorthand = %q, want %q", outputFlag.Shorthand, "o")
	}

	// Mapping flag
	mappingFlag := flags.Lookup("mapping")
	if mappingFlag == nil {
		t.Error("expected --mapping flag to exist")
	}

	// Force flag
	forceFlag := flags.Lookup("force")
	if forceFlag == nil {
		t.Error("expected --force flag to exist")
	}
}

func TestSanitizeCommandGroupID(t *testing.T) {
	if sanitizeCmd.GroupID != "utility" {
		t.Errorf("sanitizeCmd.GroupID = %q, want %q", sanitizeCmd.GroupID, "utility")
	}
}

func TestSanitizeModeConstants(t *testing.T) {
	// Verify our constants match the sanitizer package
	if !sanitizer.IsValidMode(SanitizeModeAggressive) {
		t.Errorf("SanitizeModeAggressive %q is not valid in sanitizer package", SanitizeModeAggressive)
	}
	if !sanitizer.IsValidMode(SanitizeModeModerate) {
		t.Errorf("SanitizeModeModerate %q is not valid in sanitizer package", SanitizeModeModerate)
	}
	if !sanitizer.IsValidMode(SanitizeModeMinimal) {
		t.Errorf("SanitizeModeMinimal %q is not valid in sanitizer package", SanitizeModeMinimal)
	}
}

func TestDetermineSanitizeOutputPath_NewFile(t *testing.T) {
	// Test with a file that doesn't exist
	tmpDir := t.TempDir()
	outputPath := filepath.Join(tmpDir, "new-file.xml")

	result, err := determineSanitizeOutputPath(outputPath, false)
	if err != nil {
		t.Fatalf("determineSanitizeOutputPath() error = %v", err)
	}

	if result != outputPath {
		t.Errorf("result = %q, want %q", result, outputPath)
	}
}

func TestDetermineSanitizeOutputPath_ExistingFile_Force(t *testing.T) {
	// Create a temporary file
	tmpDir := t.TempDir()
	outputPath := filepath.Join(tmpDir, "existing-file.xml")

	if err := os.WriteFile(outputPath, []byte("<test/>"), 0o600); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	// With force=true, should succeed without prompt
	result, err := determineSanitizeOutputPath(outputPath, true)
	if err != nil {
		t.Fatalf("determineSanitizeOutputPath() with force error = %v", err)
	}

	if result != outputPath {
		t.Errorf("result = %q, want %q", result, outputPath)
	}
}

func TestSanitizeCommandIntegration(t *testing.T) {
	// Create a test XML file
	tmpDir := t.TempDir()
	inputFile := filepath.Join(tmpDir, "config.xml")
	outputFile := filepath.Join(tmpDir, "sanitized.xml")

	testXML := `<?xml version="1.0"?>
<opnsense>
  <system>
    <user>
      <password>supersecret123</password>
      <name>admin</name>
    </user>
    <hostname>firewall.company.com</hostname>
  </system>
  <interfaces>
    <wan>
      <ipaddr>203.0.113.50</ipaddr>
    </wan>
    <lan>
      <ipaddr>192.168.1.1</ipaddr>
    </lan>
  </interfaces>
</opnsense>`

	if err := os.WriteFile(inputFile, []byte(testXML), 0o600); err != nil {
		t.Fatalf("failed to create test input file: %v", err)
	}

	// Test sanitization using the sanitizer package directly
	// This avoids test isolation issues with the full command chain
	s := sanitizer.NewSanitizer(sanitizer.ModeAggressive)

	inFile, err := os.Open(inputFile)
	if err != nil {
		t.Fatalf("failed to open input file: %v", err)
	}
	defer inFile.Close()

	outFile, err := os.Create(outputFile)
	if err != nil {
		t.Fatalf("failed to create output file: %v", err)
	}
	defer outFile.Close()

	if err := s.SanitizeXML(inFile, outFile); err != nil {
		t.Fatalf("sanitize failed: %v", err)
	}

	// Verify output file was created
	outputContent, err := os.ReadFile(outputFile)
	if err != nil {
		t.Fatalf("failed to read output file: %v", err)
	}

	// Verify sensitive data was redacted
	outputStr := string(outputContent)

	if bytes.Contains(outputContent, []byte("supersecret123")) {
		t.Error("password was not redacted")
	}

	if bytes.Contains(outputContent, []byte("203.0.113.50")) {
		t.Error("public IP was not redacted")
	}

	// In aggressive mode, private IPs should also be redacted
	if bytes.Contains(outputContent, []byte("192.168.1.1")) {
		t.Error("private IP was not redacted in aggressive mode")
	}

	// Verify XML structure is preserved
	if !bytes.Contains(outputContent, []byte("<opnsense>")) {
		t.Error("XML structure not preserved - missing <opnsense> tag")
	}

	// Verify we have some redacted content
	if !bytes.Contains(outputContent, []byte("REDACTED")) && !bytes.Contains(outputContent, []byte("10.0.0.")) {
		t.Errorf("expected redacted content in output: %s", outputStr)
	}
}
