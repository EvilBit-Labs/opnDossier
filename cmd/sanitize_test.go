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

// TestSanitizeCmdLongAndExample guards against silent collapse of the Long
// description or the dedicated Cobra Example field. Both must remain populated
// so --help, auto-generated man pages, and generated markdown docs stay useful.
func TestSanitizeCmdLongAndExample(t *testing.T) {
	if sanitizeCmd.Long == "" {
		t.Error("sanitizeCmd.Long should not be empty")
	}
	if sanitizeCmd.Example == "" {
		t.Error("sanitizeCmd.Example should not be empty")
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
    <authserver>
      <type>ldap</type>
      <name>corp-ldap</name>
      <host>ldap.example.com</host>
      <ldap_port>636</ldap_port>
      <ldap_basedn>dc=corp,dc=example,dc=com</ldap_basedn>
      <ldap_authcn>cn=users,dc=corp,dc=example,dc=com</ldap_authcn>
      <ldap_attr_user>uid</ldap_attr_user>
      <ldap_binddn>cn=svc_bind,ou=svc,dc=corp,dc=example,dc=com</ldap_binddn>
      <ldap_bindpw>bindpwsecret</ldap_bindpw>
      <ldap_extended_query>(|(memberOf=cn=admins,ou=groups,dc=corp,dc=example,dc=com))</ldap_extended_query>
      <ldap_sync_memberof_groups>cn=sync-members,ou=groups,dc=corp,dc=example,dc=com</ldap_sync_memberof_groups>
      <ldap_sync_default_groups>cn=defaults,ou=groups,dc=corp,dc=example,dc=com</ldap_sync_default_groups>
    </authserver>
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

	if bytes.Contains(outputContent, []byte("bindpwsecret")) {
		t.Error("ldap bind password was not redacted")
	}

	if bytes.Contains(outputContent, []byte("203.0.113.50")) {
		t.Error("public IP was not redacted")
	}

	// In aggressive mode, private IPs should also be redacted
	if bytes.Contains(outputContent, []byte("192.168.1.1")) {
		t.Error("private IP was not redacted in aggressive mode")
	}

	if bytes.Contains(outputContent, []byte("dc=corp,dc=example,dc=com")) {
		t.Error("ldap basedn was not redacted in aggressive mode")
	}

	if bytes.Contains(outputContent, []byte("cn=users,dc=corp,dc=example,dc=com")) {
		t.Error("ldap authcn was not redacted in aggressive mode")
	}

	if bytes.Contains(outputContent, []byte("cn=svc_bind,ou=svc,dc=corp,dc=example,dc=com")) {
		t.Error("ldap binddn was not redacted in aggressive mode")
	}

	if bytes.Contains(outputContent, []byte("memberOf=cn=admins,ou=groups,dc=corp,dc=example,dc=com")) {
		t.Error("ldap extended query was not redacted in aggressive mode")
	}

	if bytes.Contains(outputContent, []byte("cn=sync-members,ou=groups,dc=corp,dc=example,dc=com")) {
		t.Error("ldap sync memberof groups was not redacted in aggressive mode")
	}

	if bytes.Contains(outputContent, []byte("cn=defaults,ou=groups,dc=corp,dc=example,dc=com")) {
		t.Error("ldap sync default groups was not redacted in aggressive mode")
	}

	expectedAuthServerFragments := [][]byte{
		[]byte("<name>authserver-001</name>"),
		[]byte("<host>ldap-001.example.invalid</host>"),
		[]byte("<ldap_port>55001</ldap_port>"),
		[]byte("<ldap_basedn>dc=auth001,dc=example,dc=invalid</ldap_basedn>"),
		[]byte("<ldap_authcn>cn=auth-search-001,ou=ldap,dc=example,dc=invalid</ldap_authcn>"),
		[]byte("<ldap_attr_user>opndossierUserAttr001</ldap_attr_user>"),
		[]byte("<ldap_binddn>cn=bind-user-001,ou=svc,dc=example,dc=invalid</ldap_binddn>"),
		[]byte("<ldap_bindpw>BindPw-001-NotReal!</ldap_bindpw>"),
		[]byte("<ldap_extended_query>(&amp;(objectClass=person)(uid=redacted-001))</ldap_extended_query>"),
		[]byte(
			"<ldap_sync_memberof_groups>cn=memberof-sync-001,ou=groups,dc=example,dc=invalid</ldap_sync_memberof_groups>",
		),
		[]byte(
			"<ldap_sync_default_groups>cn=default-sync-001,ou=groups,dc=example,dc=invalid</ldap_sync_default_groups>",
		),
	}
	for _, expectedFragment := range expectedAuthServerFragments {
		if !bytes.Contains(outputContent, expectedFragment) {
			t.Errorf("expected authserver pseudonymized fragment %q in output", expectedFragment)
		}
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
