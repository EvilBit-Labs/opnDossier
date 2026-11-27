package formatters

import (
	"strings"

	"github.com/EvilBit-Labs/opnDossier/internal/analysis"
	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
)

// Scoring constants and penalty values used by CalculateSecurityScore to compute a security posture score.
const (
	maxSecurityScore       = 100
	initialSecurityScore   = 100
	firewallMissingPenalty = 20
	managementOnWANPenalty = 30
	insecureTunablePenalty = 5
	defaultUserPenalty     = 15
)

// AssessRiskLevel returns a consistent emoji + text representation.
func AssessRiskLevel(severity string) string {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "critical":
		return "🔴 Critical Risk"
	case "high":
		return "🟠 High Risk"
	case "medium":
		return "🟡 Medium Risk"
	case "low":
		return "🟢 Low Risk"
	case "info", "informational":
		return "ℹ️ Informational"
	default:
		return "⚪ Unknown Risk"
	}
}

// CalculateSecurityScore computes an overall score (0-100).
func CalculateSecurityScore(data *common.CommonDevice) int {
	if data == nil {
		return 0
	}

	score := initialSecurityScore

	if len(data.FirewallRules) == 0 {
		score -= firewallMissingPenalty
	}

	if hasManagementOnWAN(data) {
		score -= managementOnWANPenalty
	}

	// With packet filtering disabled no rule is loaded and every management
	// service is reachable from the WAN, so both penalties above apply in full,
	// counted once whatever the rules say.
	if data.System.PacketFilterDisabled {
		score = min(score, initialSecurityScore-firewallMissingPenalty-managementOnWANPenalty)
	}

	securityTunables := map[string]string{
		"net.inet.ip.forwarding":   "0",
		"net.inet6.ip6.forwarding": "0",
		"net.inet.tcp.blackhole":   "2",
		"net.inet.udp.blackhole":   "1",
	}
	for tunable, expected := range securityTunables {
		if !checkTunable(data, tunable, expected) {
			score -= insecureTunablePenalty
		}
	}

	for _, user := range data.Users {
		if isDefaultUser(user) {
			score -= defaultUserPenalty
		}
	}

	if score < 0 {
		score = 0
	}
	if score > maxSecurityScore {
		score = maxSecurityScore
	}
	return score
}

// AssessServiceRisk maps common services to risk levels.
func AssessServiceRisk(serviceName string) string {
	riskServices := map[string]string{
		"telnet": "critical",
		"ftp":    "high",
		"vnc":    "high",
		"rdp":    "medium",
		"ssh":    "low",
		"https":  "info",
	}

	name := strings.ToLower(serviceName)
	for pattern, risk := range riskServices {
		if strings.Contains(name, pattern) {
			return AssessRiskLevel(risk)
		}
	}
	return AssessRiskLevel("info")
}

// hasManagementOnWAN checks whether any enabled pass rule allows inbound traffic to common management ports on a WAN interface.
func hasManagementOnWAN(data *common.CommonDevice) bool {
	mgmtPorts := []int{443, 80, 22, 8080}

	for _, rule := range data.FirewallRules {
		// The shared classifier, so a rule on a second uplink, on an interface
		// group with a WAN member, or floating on every interface counts too.
		if analysis.RuleReachability(rule, data) != analysis.WANReachable {
			continue
		}
		// A rule the firewall skips, or one that does not pass traffic, exposes
		// nothing. A rule with no type is the pass rule both firewalls load it as.
		if rule.Disabled || (rule.Type != "" && rule.Type != common.RuleTypePass) {
			continue
		}
		// Only an outbound rule is left out. A rule with direction any matches
		// inbound traffic too, and an unrecognized direction counts as inbound,
		// so that the score over-reports rather than misses a rule.
		if rule.Direction == common.DirectionOut {
			continue
		}
		// A list or range is matched by containment, and a rule with no port or
		// a port alias counts, so the score over-reports (GOTCHAS 8.4).
		for _, port := range mgmtPorts {
			if analysis.RulePortPermits(rule.Destination.Port, port) {
				return true
			}
		}
	}
	return false
}

// checkTunable returns true if a sysctl tunable is known to hold the expected
// value. A tunable left at its default reads as the value in effect on the
// firewall (analysis.EffectiveSysctl), and one whose value cannot be told
// counts as not holding it.
//
// When a padded row names the tunable (analysis.SysctlNamePadded), the value
// in effect depends on the release, so the tunable is read as it was at
// a5e66959: the first row naming it exactly must hold the expected value as
// written.
func checkTunable(data *common.CommonDevice, name, expected string) bool {
	if analysis.SysctlNamePadded(data, name) {
		for _, item := range data.Sysctl {
			if item.Tunable == name {
				return item.Value == expected
			}
		}

		return false
	}

	value, known := analysis.EffectiveSysctl(data, name)
	return known && value == expected
}

// isDefaultUser returns true if the user has a well-known default username such as admin, root, or user.
func isDefaultUser(u common.User) bool {
	switch strings.ToLower(u.Name) {
	case "admin", "root", "user":
		return true
	default:
		return false
	}
}
