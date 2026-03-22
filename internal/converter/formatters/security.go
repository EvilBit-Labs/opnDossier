package formatters

import (
	"slices"
	"strings"

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

	securityTunables := map[string]string{
		"net.inet.ip.forwarding":   "0",
		"net.inet6.ip6.forwarding": "0",
		"net.inet.tcp.blackhole":   "2",
		"net.inet.udp.blackhole":   "1",
	}
	for tunable, expected := range securityTunables {
		if !checkTunable(data.Sysctl, tunable, expected) {
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

// hasManagementOnWAN checks whether any firewall rule allows inbound traffic to common management ports on the WAN interface.
func hasManagementOnWAN(data *common.CommonDevice) bool {
	mgmtPorts := []string{"443", "80", "22", "8080"}

	for _, rule := range data.FirewallRules {
		if !slices.ContainsFunc(rule.Interfaces, func(s string) bool {
			return strings.EqualFold(s, "wan")
		}) {
			continue
		}
		if rule.Direction != "" && rule.Direction != common.DirectionIn {
			continue
		}
		for _, port := range mgmtPorts {
			if strings.Contains(rule.Destination.Port, port) {
				return true
			}
		}
	}
	return false
}

// checkTunable returns true if a sysctl tunable with the given name exists and has the expected value.
func checkTunable(tunables []common.SysctlItem, name, expected string) bool {
	for _, tunable := range tunables {
		if tunable.Tunable == name {
			return tunable.Value == expected
		}
	}
	return false
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
