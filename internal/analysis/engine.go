package analysis

import (
	"fmt"
	"strings"

	"github.com/EvilBit-Labs/opnDossier/internal/constants"
	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
)

// weakCipherTokens lists cipher/protocol substrings that indicate a legacy,
// broken, or otherwise weak TLS cipher configuration. Matching is
// case-insensitive substring search against the configured OpenSSL cipher
// string.
var weakCipherTokens = []string{"RC4", "DES", "3DES", "MD5", "NULL", "EXPORT"}

// weakTLSProtocols lists TLS/DTLS protocol-version floors considered
// insecure by current guidance (TLS 1.0/1.1 and all SSL versions).
var weakTLSProtocols = []string{"SSLv3", "SSLv2", "TLSv1", "TLSv1.1"}

// ScanObservations runs the shared detection engine over cfg and returns a
// flat, neutral list of Observations: the existing DetectSecurityIssues
// detections wrapped with reachability and confidence, plus additive
// framework-free hygiene detectors for categories no compliance plugin owns
// at per-instance granularity (insecure management protocols, weak crypto
// defaults, any-to-any rules, disabled logging).
//
// ScanObservations does not modify DetectSecurityIssues or ComputeAnalysis;
// both remain unchanged for their existing callers in internal/converter and
// internal/processor (KTD3, R4). Returns nil for a nil cfg.
func ScanObservations(cfg *common.CommonDevice) []Observation {
	if cfg == nil {
		return nil
	}

	observations := adaptSecurityFindings(DetectSecurityIssues(cfg))
	observations = append(observations, detectInsecureManagementProtocols(cfg)...)
	observations = append(observations, detectWeakCryptoDefaults(cfg)...)
	observations = append(observations, detectAnyToAnyRules(cfg)...)
	observations = append(observations, detectDisabledLogging(cfg)...)

	return observations
}

// adaptSecurityFindings wraps the existing DetectSecurityIssues output into
// Observations without altering DetectSecurityIssues itself (KTD3). Every
// existing detection is deterministic pattern matching against config
// fields, so confidence is High.
func adaptSecurityFindings(findings []common.SecurityFinding) []Observation {
	observations := make([]Observation, 0, len(findings))

	for _, f := range findings {
		observations = append(observations, Observation{
			Severity:       Severity(f.Severity),
			Confidence:     ConfidenceHigh,
			Reachability:   securityFindingReachability(f),
			Component:      f.Component,
			Evidence:       f.Description,
			Title:          f.Issue,
			Description:    f.Description,
			Recommendation: f.Recommendation,
		})
	}

	return observations
}

// securityFindingReachability derives a reachability tag for a
// DetectSecurityIssues finding.
//
// The only per-instance-rule finding DetectSecurityIssues currently emits is
// the permissive WAN pass rule (Component "filter.rule[N]"), and that
// detector already requires the rule to be bound to a WAN interface (via
// RuleReachability as of the U1 consolidation), so it is deterministically
// WAN-reachable. System-wide findings (insecure WebGUI protocol, default
// SNMP community) are not bound to a specific interface, and correlating
// them against exposing firewall/NAT rules is red mode's WAN-exposed-service
// enumeration (R17), out of scope for this slice — so they are tagged Local
// here rather than guessed.
func securityFindingReachability(f common.SecurityFinding) Reachability {
	if strings.HasPrefix(f.Component, "filter.rule[") {
		return WANReachable
	}

	return Local
}

// detectInsecureManagementProtocols flags SNMP v1/v2c community-based
// authentication as an insecure management protocol family, independent of
// whether the configured community string happens to be the well-known
// default ("public", already covered by DetectSecurityIssues). SNMP v1/v2c
// transmits its community string in cleartext regardless of the string's
// value, so any configured RO community is a distinct, additive hygiene
// concern.
func detectInsecureManagementProtocols(cfg *common.CommonDevice) []Observation {
	if cfg.SNMP.ROCommunity == "" {
		return nil
	}

	return []Observation{
		{
			Severity:       SeverityMedium,
			Confidence:     ConfidenceHigh,
			Reachability:   Local,
			Component:      "snmpd.protocol",
			Evidence:       "snmp community-based authentication (v1/v2c) configured",
			Title:          "Insecure Management Protocol: SNMP v1/v2c",
			Description:    "SNMP is configured with community-string authentication (v1/v2c), which transmits credentials in cleartext regardless of the community string value.",
			Recommendation: "Migrate to SNMPv3 with authentication and privacy (authPriv), or disable SNMP if not required.",
		},
	}
}

// detectWeakCryptoDefaults flags legacy/weak TLS cipher strings or minimum
// protocol versions configured in the device's system-wide trust settings.
func detectWeakCryptoDefaults(cfg *common.CommonDevice) []Observation {
	if cfg.Trust == nil {
		return nil
	}

	var observations []Observation

	// containsWeakCipherToken splits the OpenSSL cipher string on its
	// list separators and honors the "!"/"-" exclusion prefixes, so a
	// string that *excludes* a weak class (the standard
	// "!aNULL:!MD5:!RC4:!3DES" hardening suffix) no longer
	// false-positives. Confidence stays Medium rather than High because
	// macro selectors like HIGH/ALL/DEFAULT can still implicitly pull in
	// a weak cipher without any literal weak token for us to match; the
	// observation is still always surfaced per R6 (confidence never
	// gates a match).
	if token, ok := containsWeakCipherToken(cfg.Trust.CipherString); ok {
		observations = append(observations, Observation{
			Severity:     SeverityMedium,
			Confidence:   ConfidenceMedium,
			Reachability: Local,
			Component:    "trust.cipherstring",
			Evidence:     fmt.Sprintf("cipherString contains weak token %q", token),
			Title:        "Weak Crypto Default: Legacy TLS Cipher",
			Description: fmt.Sprintf(
				"The system-wide TLS cipher string includes the legacy/weak cipher token %q.",
				token,
			),
			Recommendation: "Remove legacy cipher tokens (RC4, DES, 3DES, MD5, NULL, EXPORT) from the OpenSSL cipher string.",
		})
	}

	if slicesContainsFold(weakTLSProtocols, cfg.Trust.MinProtocol) {
		observations = append(observations, Observation{
			Severity:     SeverityMedium,
			Confidence:   ConfidenceHigh,
			Reachability: Local,
			Component:    "trust.minprotocol",
			Evidence:     "minProtocol=" + cfg.Trust.MinProtocol,
			Title:        "Weak Crypto Default: Legacy TLS Protocol Floor",
			Description: fmt.Sprintf(
				"The minimum TLS protocol version is set to %s, a deprecated/insecure protocol version.",
				cfg.Trust.MinProtocol,
			),
			Recommendation: "Set the minimum TLS protocol version to TLSv1.2 or higher.",
		})
	}

	return observations
}

// cipherListSeparators are the delimiters OpenSSL recognizes between
// selectors in a cipher string (colon, comma, and whitespace).
const cipherListSeparators = ": ,\t"

// containsWeakCipherToken reports whether any actively-enabled selector in the
// OpenSSL cipherString contains a known weak-cipher token, returning the
// matched token for use in the finding description.
//
// The cipher string is split into individual selectors and each is checked
// against its OpenSSL prefix operator: "!" and "-" exclude a cipher class (it
// is not enabled and must not raise a finding), while "+" only reorders and
// leaves the cipher enabled. A weak token is reported only when it appears in
// a selector that is actually enabled.
func containsWeakCipherToken(cipherString string) (string, bool) {
	if cipherString == "" {
		return "", false
	}

	selectors := strings.FieldsFunc(cipherString, func(r rune) bool {
		return strings.ContainsRune(cipherListSeparators, r)
	})

	for _, selector := range selectors {
		switch selector[0] {
		case '!', '-':
			continue
		case '+':
			selector = selector[1:]
		}

		upper := strings.ToUpper(selector)
		for _, token := range weakCipherTokens {
			if strings.Contains(upper, token) {
				return token, true
			}
		}
	}

	return "", false
}

// slicesContainsFold reports whether value case-insensitively matches any
// entry in candidates.
func slicesContainsFold(candidates []string, value string) bool {
	if value == "" {
		return false
	}

	for _, c := range candidates {
		if strings.EqualFold(c, value) {
			return true
		}
	}

	return false
}

// detectAnyToAnyRules flags enabled pass rules with source, destination,
// port, and protocol all set to "any" — one Observation per matching rule.
// This mirrors the firewall compliance plugin's FIREWALL-022 control at
// per-rule granularity: the plugin control reports a single pass/fail for
// the whole device, while this hygiene detector identifies which specific
// rule(s) are the smell so blue can point at the exact config element.
func detectAnyToAnyRules(cfg *common.CommonDevice) []Observation {
	var observations []Observation

	for i, rule := range cfg.FirewallRules {
		if rule.Disabled || rule.Type != common.RuleTypePass {
			continue
		}

		srcAny := rule.Source.Address == constants.NetworkAny
		dstAny := rule.Destination.Address == constants.NetworkAny
		portAny := rule.Destination.Port == "" || rule.Destination.Port == constants.NetworkAny
		protoAny := rule.Protocol == "" || strings.EqualFold(rule.Protocol, constants.NetworkAny)

		if !srcAny || !dstAny || !portAny || !protoAny {
			continue
		}

		component := fmt.Sprintf("filter.rule[%d]", i)
		observations = append(observations, Observation{
			Severity:     SeverityHigh,
			Confidence:   ConfidenceHigh,
			Reachability: RuleReachability(rule, cfg.Interfaces),
			Component:    component,
			Evidence:     fmt.Sprintf("rule %d: source=any destination=any port=any protocol=any", i+1),
			Title:        "Any-to-Any Pass Rule",
			Description: fmt.Sprintf(
				"Rule %d passes traffic with source, destination, port, and protocol all set to any.",
				i+1,
			),
			Recommendation: "Replace any-any rules with specific source/destination/port/protocol restrictions.",
		})
	}

	return observations
}

// detectDisabledLogging flags remote syslog forwarding that is enabled but
// does not include firewall filter log messages, meaning allowed/denied
// traffic decisions are not captured in the forwarded log stream.
func detectDisabledLogging(cfg *common.CommonDevice) []Observation {
	if !cfg.Syslog.Enabled || cfg.Syslog.FilterLogging {
		return nil
	}

	return []Observation{
		{
			Severity:       SeverityMedium,
			Confidence:     ConfidenceHigh,
			Reachability:   Local,
			Component:      "syslog.filterlogging",
			Evidence:       "syslog.enabled=true syslog.filterLogging=false",
			Title:          "Disabled Logging: Firewall Filter Events Not Forwarded",
			Description:    "Remote syslog forwarding is enabled, but firewall filter log messages are not included, so allow/deny decisions are not captured off-box.",
			Recommendation: "Enable filter logging under the remote syslog configuration so firewall decisions are forwarded.",
		},
	}
}
