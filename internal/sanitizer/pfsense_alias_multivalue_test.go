// Package sanitizer test file. This file intentionally mirrors
// alias_multivalue_test.go structurally (GOTCHAS §9.1: dupl fires
// bidirectionally on both sides of a duplicate pair) — each vendor fixture
// needs its own independent, readable assertions rather than a shared
// table-driven helper.
//
//nolint:dupl // see file header above
package sanitizer

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// pfSenseAliasFixturePath is the pfSense-specific alias fixture (see U3 of
// the firewall-shadowing plan): a minimal valid pfSense config.xml with a
// populated top-level <aliases> block whose members are SPACE-separated
// multi-value <address> elements — pfSense's member convention, as opposed
// to OPNsense's newline-separated <content> (see alias_multivalue_test.go).
// It lives under testdata/pfsense/ (not the flat testdata/ root) alongside
// the other pfSense-only fixtures, since TestOpnSenseDocument_XMLCoverage
// (pkg/schema/opnsense) unmarshals every flat *.xml file under testdata/ as
// an OpnSenseDocument and would fail on a pfSense-rooted document.
const pfSenseAliasFixturePath = "../../testdata/pfsense/pfsense-aliases.xml"

// TestSanitizeXML_PfSenseAliasMultiValue_Aggressive proves that `sanitize
// --mode aggressive` (SanitizeXML) redacts every IP address embedded in the
// pfSense alias fixture's SPACE-separated multi-value <address> elements,
// reusing the same whitespace-token-based redaction wired for OPNsense's
// newline-separated <content> in U2 (internal/sanitizer/patterns.go's
// hasTokenMatch/redactTokenMatches) — no new sanitizer code is required.
func TestSanitizeXML_PfSenseAliasMultiValue_Aggressive(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile(filepath.Clean(pfSenseAliasFixturePath))
	if err != nil {
		t.Fatalf("reading pfSense alias fixture: %v", err)
	}

	s := NewSanitizer(ModeAggressive)
	var output bytes.Buffer
	if err := s.SanitizeXML(bytes.NewReader(data), &output); err != nil {
		t.Fatalf("SanitizeXML() error = %v", err)
	}
	result := output.String()

	// WEB_SERVERS (private, host alias, space-separated address).
	leakedPrivateHosts := []string{"10.20.30.40", "10.20.30.41"}
	for _, addr := range leakedPrivateHosts {
		if strings.Contains(result, addr) {
			t.Errorf("private host alias member %q leaked in aggressive sanitize output", addr)
		}
	}

	// INTERNAL_NET (private network/CIDR alias, single-value address).
	if strings.Contains(result, "10.20.0.0/16") || strings.Contains(result, "10.20.0.0") {
		t.Error("private network alias CIDR leaked in aggressive sanitize output")
	}

	// ALL_SERVERS (nested alias: alias-name member + literal host, space-separated).
	if strings.Contains(result, "10.20.30.50") {
		t.Error("nested alias's literal host member leaked in aggressive sanitize output")
	}

	// EXTERNAL_HOSTS (public, host alias, space-separated address) —
	// exercises the public_ip rule's multi-value fallback specifically.
	leakedPublicHosts := []string{"203.0.113.10", "198.51.100.20"}
	for _, addr := range leakedPublicHosts {
		if strings.Contains(result, addr) {
			t.Errorf("public host alias member %q leaked in aggressive sanitize output", addr)
		}
	}

	// The alias name itself is not sensitive and should survive (proves the
	// sanitizer didn't just nuke the whole element/file).
	if !strings.Contains(result, "WEB_SERVERS") {
		t.Error("expected alias name WEB_SERVERS to survive sanitization (not a secret)")
	}
}
