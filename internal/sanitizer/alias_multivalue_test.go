// Package sanitizer test file. This file intentionally mirrors
// pfsense_alias_multivalue_test.go structurally (GOTCHAS §9.1: dupl fires
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

// aliasFixturePath is the repo-root OPNsense alias fixture (see U2 of the
// firewall-shadowing plan): a minimal valid config.xml with a populated MVC
// <Firewall><Alias><aliases> block whose members are newline-separated
// multi-value <content> elements — the shape net.ParseIP/net.ParseCIDR-based
// whole-value checks cannot redact (they require the WHOLE field to be one
// address). See internal/sanitizer/patterns.go's hasTokenMatch/
// redactTokenMatches and the updated public_ip/private_ip_aggressive/
// subnet_field rules in rules.go.
const aliasFixturePath = "../../testdata/opnsense-aliases.xml"

// TestSanitizeXML_AliasMultiValue_Aggressive proves that `sanitize --mode
// aggressive` (SanitizeXML — the path cmd/sanitize.go actually uses, not
// SanitizeStruct, which has no production callers per GOTCHAS §14.4) redacts
// every IP address embedded in the alias fixture's newline-separated
// multi-value <content> elements, not just single-value fields.
//
// TestSanitizeXML_AliasMultiValue_MixedTypes_Aggressive (below) is the
// mixed-type regression: a single alias mixing a private IP, a public IP, a
// CIDR subnet, and a hostname in one newline-separated <content> value. Prior
// to the per-token dispatch fix in sanitizer.go's sanitizeCharData, rule
// dispatch returned only the FIRST matching rule for the whole value, so a
// mixed-type value only got the first-matched type's tokens redacted —
// leaking every other type in cleartext.
func TestSanitizeXML_AliasMultiValue_Aggressive(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile(filepath.Clean(aliasFixturePath))
	if err != nil {
		t.Fatalf("reading alias fixture: %v", err)
	}

	s := NewSanitizer(ModeAggressive)
	var output bytes.Buffer
	if err := s.SanitizeXML(bytes.NewReader(data), &output); err != nil {
		t.Fatalf("SanitizeXML() error = %v", err)
	}
	result := output.String()

	// WEB_SERVERS (private, host alias, newline-separated content).
	leakedPrivateHosts := []string{"10.20.30.40", "10.20.30.41"}
	for _, addr := range leakedPrivateHosts {
		if strings.Contains(result, addr) {
			t.Errorf("private host alias member %q leaked in aggressive sanitize output", addr)
		}
	}

	// INTERNAL_NET (private network/CIDR alias, single-value content but
	// still exercises the same private_ip_aggressive path as multi-value).
	if strings.Contains(result, "10.20.0.0/16") || strings.Contains(result, "10.20.0.0") {
		t.Error("private network alias CIDR leaked in aggressive sanitize output")
	}

	// ALL_SERVERS (nested alias: alias-name member + literal host, newline-separated).
	if strings.Contains(result, "10.20.30.50") {
		t.Error("nested alias's literal host member leaked in aggressive sanitize output")
	}

	// EXTERNAL_HOSTS (public, host alias, newline-separated content) —
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

// TestSanitizeXML_AliasMultiValue_MixedTypes_Aggressive is the P0 regression
// for the mixed-type alias leak: MIXED_TYPES combines a private IP, a public
// IP, a CIDR subnet, and a hostname in one newline-separated <content>
// value. Before sanitizeCharData's per-token dispatch fix, ShouldRedactValue
// returned only the FIRST matching rule for the whole multi-value string
// (e.g. public_ip, whose token-aware Redactor only redacted public-IP-typed
// tokens), leaving the private IP, CIDR, and hostname members in cleartext.
func TestSanitizeXML_AliasMultiValue_MixedTypes_Aggressive(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile(filepath.Clean(aliasFixturePath))
	if err != nil {
		t.Fatalf("reading alias fixture: %v", err)
	}

	s := NewSanitizer(ModeAggressive)
	var output bytes.Buffer
	if err := s.SanitizeXML(bytes.NewReader(data), &output); err != nil {
		t.Fatalf("SanitizeXML() error = %v", err)
	}
	result := output.String()

	leaks := map[string]string{
		"10.20.30.60":      "private IP member",
		"203.0.113.20":     "public IP member",
		"198.51.100.0/24":  "CIDR subnet member",
		"mail.example.org": "hostname member",
	}
	for value, label := range leaks {
		if strings.Contains(result, value) {
			t.Errorf("MIXED_TYPES alias %s %q leaked in aggressive sanitize output", label, value)
		}
	}

	if !strings.Contains(result, "MIXED_TYPES") {
		t.Error("expected alias name MIXED_TYPES to survive sanitization (not a secret)")
	}
}
