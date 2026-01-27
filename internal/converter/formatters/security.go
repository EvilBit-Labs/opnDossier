package formatters

import (
	"strings"

	"github.com/EvilBit-Labs/opnDossier/internal/model"
)

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
func CalculateSecurityScore(data *model.OpnSenseDocument) int {
	if data == nil {
		return 0
	}

	score := initialSecurityScore

	if len(data.Filter.Rule) == 0 {
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

	for _, user := range data.System.User {
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
func AssessServiceRisk(service model.Service) string {
	riskServices := map[string]string{
		"telnet": "critical",
		"ftp":    "high",
		"vnc":    "high",
		"rdp":    "medium",
		"ssh":    "low",
		"https":  "info",
	}

	name := strings.ToLower(service.Name)
	for pattern, risk := range riskServices {
		if strings.Contains(name, pattern) {
			return AssessRiskLevel(risk)
		}
	}
	return AssessRiskLevel("info")
}

func hasManagementOnWAN(data *model.OpnSenseDocument) bool {
	mgmtPorts := []string{"443", "80", "22", "8080"}

	for _, rule := range data.Filter.Rule {
		if !rule.Interface.Contains("wan") {
			continue
		}
		if rule.Direction != "" && !strings.EqualFold(rule.Direction, "in") {
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

func checkTunable(tunables []model.SysctlItem, name, expected string) bool {
	for _, tunable := range tunables {
		if tunable.Tunable == name {
			return tunable.Value == expected
		}
	}
	return false
}

func isDefaultUser(u model.User) bool {
	switch strings.ToLower(u.Name) {
	case "admin", "root", "user":
		return true
	default:
		return false
	}
}
