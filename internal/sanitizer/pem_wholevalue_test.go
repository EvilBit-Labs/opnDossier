// Package sanitizer test file covering the whole-value-first fix for
// redactValueTokens: a PEM-armored secret or OpenVPN static-key envelope in
// a field whose name matches no FieldPattern previously leaked in cleartext,
// because replaceTokens splits the value on whitespace before any value
// detector runs, and no single token carries both the BEGIN and END markers
// (e.g. "-----BEGIN RSA PRIVATE KEY-----" splits into "-----BEGIN", "RSA",
// "PRIVATE", "KEY-----"). See sanitizer.go's looksLikeArmoredSecret and
// GOTCHAS.md §11.3/§14.2.
package sanitizer

import (
	"bytes"
	"strings"
	"testing"
)

// somefieldPEMXML wraps body in an element name ("somefield") that matches
// no rule's FieldPatterns, so the only way body can be redacted is via the
// value-detector path.
func somefieldPEMXML(body string) string {
	return "<opnsense><widgets><somefield>" + body + "</somefield></widgets></opnsense>"
}

// TestSanitizeXML_PEMWholeValue_NoMatchingFieldName_StillRedacted is the
// direct regression for the reported bug: a PEM private key in a field with
// no matching FieldPattern must still be redacted, in every mode where the
// private_key rule is active (all of them).
func TestSanitizeXML_PEMWholeValue_NoMatchingFieldName_StillRedacted(t *testing.T) {
	t.Parallel()

	const pemBody = "-----BEGIN RSA PRIVATE KEY-----\n" +
		"MIIEowIBAAKCAQEAx7Zt5vQ9kLmNpQrStUvWxYz0123456789abcdefghijklmnop\n" +
		"-----END RSA PRIVATE KEY-----"

	for _, mode := range ValidModes() {
		t.Run(string(mode), func(t *testing.T) {
			t.Parallel()

			s := NewSanitizer(mode)
			var output bytes.Buffer
			if err := s.SanitizeXML(strings.NewReader(somefieldPEMXML(pemBody)), &output); err != nil {
				t.Fatalf("SanitizeXML() error = %v", err)
			}
			result := output.String()

			if strings.Contains(result, "PRIVATE KEY-----\n") {
				t.Errorf("mode=%q leaked PEM armor: %s", mode, result)
			}
			if strings.Contains(result, "MIIEowIBAAKCAQEA") {
				t.Errorf("mode=%q leaked key body: %s", mode, result)
			}
			if !strings.Contains(result, "[REDACTED-PRIVATE-KEY]") {
				t.Errorf("mode=%q missing redaction marker: %s", mode, result)
			}
		})
	}
}

// TestSanitizeXML_OpenVPNStaticKeyWholeValue_NoMatchingFieldName_StillRedacted
// is the OpenVPN static-key variant of the same gap: its envelope label
// ("OpenVPN Static key V1") is mixed-case, so it never matches the PEM
// regex's uppercase-only label class, but it is exactly as vulnerable to
// token-splitting and must go through the same whole-value fix.
func TestSanitizeXML_OpenVPNStaticKeyWholeValue_NoMatchingFieldName_StillRedacted(t *testing.T) {
	t.Parallel()

	const staticKeyBody = "-----BEGIN OpenVPN Static key V1-----\n" +
		"abc123def456789001234567890abcdef\n" +
		"-----END OpenVPN Static key V1-----"

	for _, mode := range ValidModes() {
		t.Run(string(mode), func(t *testing.T) {
			t.Parallel()

			s := NewSanitizer(mode)
			var output bytes.Buffer
			if err := s.SanitizeXML(strings.NewReader(somefieldPEMXML(staticKeyBody)), &output); err != nil {
				t.Fatalf("SanitizeXML() error = %v", err)
			}
			result := output.String()

			if strings.Contains(result, "BEGIN OpenVPN Static key") {
				t.Errorf("mode=%q leaked OpenVPN envelope: %s", mode, result)
			}
			if strings.Contains(result, "abc123def456") {
				t.Errorf("mode=%q leaked key body: %s", mode, result)
			}
			if !strings.Contains(result, "[REDACTED-PRIVATE-KEY]") {
				t.Errorf("mode=%q missing redaction marker: %s", mode, result)
			}
		})
	}
}

// TestRedactValueTokens_OverRedactionGuard_MixedBenignMultiValue proves the
// whole-value-first attempt does not swallow a legitimate multi-value field
// that merely contains whitespace: a value mixing a private IP (the
// "secret") with a benign hostname must still redact only the IP, leaving
// the hostname to survive untouched (aggressive mode does not redact
// hostnames unless it independently matches the hostname rule, so a plain
// non-FQDN label like "router" is the clean control for "survives
// untouched"). looksLikeArmoredSecret must reject this value (no PEM/
// OpenVPN envelope present) so it falls straight to the existing per-token
// pass, unaffected by this change.
func TestRedactValueTokens_OverRedactionGuard_MixedBenignMultiValue(t *testing.T) {
	t.Parallel()

	s := NewSanitizer(ModeAggressive)
	const mixed = "10.20.30.40 router"

	if looksLikeArmoredSecret(mixed) {
		t.Fatalf("looksLikeArmoredSecret(%q) = true, want false: not PEM/OpenVPN-shaped", mixed)
	}

	result := s.redactValueTokens("widgets.somefield", mixed)

	if strings.Contains(result, "10.20.30.40") {
		t.Errorf("private IP member leaked: %q", result)
	}
	if !strings.Contains(result, "router") {
		t.Errorf("benign token %q did not survive: %q", "router", result)
	}
}

// TestLooksLikeArmoredSecret_RejectsNonEnvelopeMultiValue pins the gate
// itself: any of these realistic multi-value alias shapes must NOT be
// treated as an armored secret, or the whole-value attempt would run every
// value detector (including the unanchored hostname/MAC/email regexes)
// against the full concatenation and risk claiming the entire value on a
// single member's shape.
func TestLooksLikeArmoredSecret_RejectsNonEnvelopeMultiValue(t *testing.T) {
	t.Parallel()

	cases := []string{
		"10.20.30.40\n10.20.30.41",                                  // newline-separated OPNsense alias content
		"10.20.30.40 10.20.30.41",                                   // space-separated pfSense alias address
		"10.20.30.60 203.0.113.20 mail.example.org 198.51.100.0/24", // mixed types
		"aa:bb:cc:dd:ee:ff host.example.com",                        // MAC + hostname mix
	}

	for _, c := range cases {
		if looksLikeArmoredSecret(c) {
			t.Errorf("looksLikeArmoredSecret(%q) = true, want false", c)
		}
	}
}

// TestSanitizeXML_PEMEmbeddedAmongBenignLines_KnownTradeoff pins a known,
// deliberate trade-off rather than a requirement: if a CharData value were
// to combine benign alias-style members with an actual PEM block on other
// lines (no known vendor config shape does this — a PEM-carrying field such
// as openvpn.tls or openvpn.statickeys holds only the PEM/envelope value),
// looksLikeArmoredSecret's substring search (IsPEM has no ^/$ anchors) fires
// on the whole value and the whole-value redaction below swallows the
// benign lines along with the secret rather than surgically extracting just
// the PEM block. That is over-redaction, the safe direction per this
// package's threat model (under-redaction is the dangerous failure mode) —
// so this is accepted rather than fixed with block-extraction logic for a
// shape that does not occur in real configs. If a real vendor field is ever
// found to mix the two, revisit with a regex-extraction approach instead of
// the whole-value swallow.
func TestSanitizeXML_PEMEmbeddedAmongBenignLines_KnownTradeoff(t *testing.T) {
	t.Parallel()

	const mixed = "host1.example.com\n" +
		"-----BEGIN RSA PRIVATE KEY-----\n" +
		"MIIEowIBAAKCAQEAx7Zt5vQ9kLmNpQrStUvWxYz0123456789abcdefghijklmnop\n" +
		"-----END RSA PRIVATE KEY-----\n" +
		"host2.example.com"

	s := NewSanitizer(ModeAggressive)
	result := s.redactValueTokens("widgets.somefield", mixed)

	// The secret must never leak -- this is the load-bearing assertion.
	if strings.Contains(result, "MIIEowIBAAKCAQEA") {
		t.Errorf("key body leaked: %q", result)
	}
	if !strings.Contains(result, "[REDACTED-PRIVATE-KEY]") {
		t.Errorf("missing redaction marker: %q", result)
	}
	// Documents today's accepted behavior: the benign lines do not survive
	// this synthetic shape. Safe-direction over-redaction, not a bug.
	if strings.Contains(result, "host1.example.com") || strings.Contains(result, "host2.example.com") {
		t.Error(
			"expected benign lines to be swallowed with the PEM block in this synthetic mixed shape (see comment above) -- if this now fails, block-extraction has been implemented and this assertion should be updated",
		)
	}
}
