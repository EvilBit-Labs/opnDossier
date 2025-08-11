package converter

import (
	"strings"

	"github.com/EvilBit-Labs/opnDossier/internal/model"
)

const (
	// Security scoring constants.
	maxSecurityScore       = 100
	initialSecurityScore   = 100
	firewallMissingPenalty = 20
	managementOnWANPenalty = 30
	insecureTunablePenalty = 5
	defaultUserPenalty     = 15
)

// AssessRiskLevel returns a consistent emoji + text representation.
func (b *MarkdownBuilder) AssessRiskLevel(severity string) string {
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
// Implementation notes:
//   - Prefer reusing a single source of truth for scoring. Until model exports a public function,
//     provide a small, transparent wrapper here with conservative checks and clamps.
//   - This wrapper is intentionally minimal and documented below; follow-up will centralize logic.
func (b *MarkdownBuilder) CalculateSecurityScore(data *model.OpnSenseDocument) int {
	if data == nil {
		return 0
	}

	score := initialSecurityScore

	// Heuristic checks consistent with our reporting goals

	// 1) Basic firewall presence
	if len(data.Filter.Rule) == 0 {
		score -= firewallMissingPenalty
	}

	// 2) Management exposure on WAN
	if b.hasManagementOnWAN(data) {
		score -= managementOnWANPenalty
	}

	// 3) Security-relevant sysctl tunables
	securityTunables := map[string]string{
		"net.inet.ip.forwarding":   "0",
		"net.inet6.ip6.forwarding": "0",
		"net.inet.tcp.blackhole":   "2",
		"net.inet.udp.blackhole":   "1",
	}
	for tunable, expected := range securityTunables {
		if !b.checkTunable(data.Sysctl, tunable, expected) {
			score -= insecureTunablePenalty
		}
	}

	// 4) Default users
	for _, user := range data.System.User {
		if b.isDefaultUser(user) {
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
func (b *MarkdownBuilder) AssessServiceRisk(service model.Service) string {
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
			return b.AssessRiskLevel(risk)
		}
	}
	return b.AssessRiskLevel("info")
}

// hasManagementOnWAN flags if WAN rules expose common management ports.
// Notes:
// - InterfaceList captures logical names; we check for "wan" in rule.Interface.
// - Direction is considered if set ("in"); many configs omit it, so we don't require it.
// - Destination.Port may be ranges/aliases; simple substring match as a safe heuristic.
func (b *MarkdownBuilder) hasManagementOnWAN(data *model.OpnSenseDocument) bool {
	mgmtPorts := []string{"443", "80", "22", "8080"}

	for _, rule := range data.Filter.Rule {
		if !rule.Interface.Contains("wan") {
			continue
		}
		// Optional direction check
		if rule.Direction != "" && !strings.EqualFold(rule.Direction, "in") {
			continue
		}
		for _, p := range mgmtPorts {
			if strings.Contains(rule.Destination.Port, p) {
				return true
			}
		}
	}
	return false
}

func (b *MarkdownBuilder) checkTunable(tunables []model.SysctlItem, name, expected string) bool {
	for _, t := range tunables {
		if t.Tunable == name {
			return t.Value == expected
		}
	}
	return false
}

func (b *MarkdownBuilder) isDefaultUser(u model.User) bool {
	switch strings.ToLower(u.Name) {
	case "admin", "root", "user":
		return true
	default:
		return false
	}
}
