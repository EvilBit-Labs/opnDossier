package audit

import (
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/EvilBit-Labs/opnDossier/internal/analysis"
	"github.com/EvilBit-Labs/opnDossier/internal/constants"
	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
)

// Default listening ports for the in-scope management services. WebGUI has no
// explicit port field, so it is inferred from the configured protocol.
const (
	portHTTPS   = 443
	portHTTP    = 80
	portSSH     = 22
	portSNMP    = 161
	unknownPort = 0
)

// maxManagementServices is the number of in-scope management services
// (WebGUI, SSH, SNMP) — the upper bound for the serviceExposures slice.
const maxManagementServices = 3

// findingTypeExposure is the Finding.Type for every red-mode exposure finding.
const findingTypeExposure = "exposure"

// exposedService describes an in-scope management/system service and where it
// is reachable from. Reachability is computed by correlating the service's
// listening port against the device's WAN-reachable firewall and inbound-NAT
// rules (R17) — a service is WAN-reachable only when an actual rule permits its
// port, never on the service being enabled alone.
type exposedService struct {
	kind            exploitNoteKind
	name            string
	displayName     string
	severity        analysis.Severity
	component       string
	port            int
	reachability    analysis.Reachability
	description     string
	recommendation  string
	vulnerabilities []string
}

// serviceExposures enumerates the in-scope management services present on the
// device (WebGUI is always present; SSH when enabled; SNMP when a read-only
// community is configured) and classifies each as WAN-reachable or LAN-only by
// correlating its port against WAN-reachable rules. Local-only services are not
// possible here — a configured management service is at least LAN-reachable.
func serviceExposures(device *common.CommonDevice) []exposedService {
	if device == nil {
		return nil
	}

	services := make([]exposedService, 0, maxManagementServices)

	// WebGUI is always listening; the only question is its reachability. Use the
	// configured custom port when the unified model carries one (pfSense sets it;
	// OPNsense leaves it empty), otherwise the protocol default.
	webGUIPort := portHTTPS
	if device.System.WebGUI.Protocol != "" && device.System.WebGUI.Protocol != constants.ProtocolHTTPS {
		webGUIPort = portHTTP
	}
	webGUIPort = parsePort(device.System.WebGUI.Port, webGUIPort)
	services = append(services, exposedService{
		kind:            exploitKindWebGUI,
		name:            "webgui",
		displayName:     "Web Administration Interface",
		severity:        analysis.SeverityCritical,
		component:       "system.webgui.protocol",
		port:            webGUIPort,
		reachability:    serviceReachability(device, webGUIPort),
		description:     "The web administration interface is reachable from a WAN interface, exposing the device management plane to untrusted networks.",
		recommendation:  "Restrict web GUI access to management networks via firewall rules, and never expose it directly to the WAN.",
		vulnerabilities: []string{"exposed-management-interface"},
	})

	if device.System.SSH.Enabled {
		sshPort := parsePort(device.System.SSH.Port, portSSH)
		services = append(services, exposedService{
			kind:            exploitKindSSH,
			name:            "ssh",
			displayName:     "SSH Remote Administration",
			severity:        analysis.SeverityHigh,
			component:       "system.ssh",
			port:            sshPort,
			reachability:    serviceReachability(device, sshPort),
			description:     "The SSH administration service is reachable from a WAN interface, exposing remote shell access to untrusted networks.",
			recommendation:  "Restrict SSH to management networks via firewall rules, or disable it if remote shell access is not required.",
			vulnerabilities: []string{"exposed-remote-admin"},
		})
	}

	if device.SNMP.ROCommunity != "" {
		services = append(services, exposedService{
			kind:            exploitKindSNMP,
			name:            "snmp",
			displayName:     "SNMP Management Service",
			severity:        analysis.SeverityHigh,
			component:       "snmpd",
			port:            portSNMP,
			reachability:    serviceReachability(device, portSNMP),
			description:     "The SNMP management service is reachable from a WAN interface, exposing device and topology information to untrusted networks.",
			recommendation:  "Restrict SNMP to management networks, migrate to SNMPv3 with authPriv, or disable SNMP if unused.",
			vulnerabilities: []string{"exposed-snmp"},
		})
	}

	return services
}

// serviceReachability classifies a service by port: WAN-reachable when a
// WAN-reachable firewall pass rule or inbound NAT rule permits that port,
// otherwise LAN-only. A configured management service is never Local.
func serviceReachability(device *common.CommonDevice, port int) analysis.Reachability {
	if wanRulePermitsPort(device, port) {
		return analysis.WANReachable
	}

	return analysis.LANOnly
}

// wanRulePermitsPort reports whether any WAN-reachable enabled firewall pass
// rule or WAN-reachable inbound NAT rule permits the given port. Port matching
// biases toward over-reporting exposure (the safe direction for a security
// tool): an empty or "any" rule port permits every port, a numeric range or
// comma-list is matched by containment, and an unresolvable port alias is
// treated as permitting the port rather than silently classifying the service
// as safely LAN-only. Only a concrete numeric port that does not contain the
// service port is treated as non-permitting. See rulePortPermits.
func wanRulePermitsPort(device *common.CommonDevice, port int) bool {
	for _, rule := range device.FirewallRules {
		if rule.Disabled || rule.Type != common.RuleTypePass {
			continue
		}

		if analysis.RuleReachability(rule, device.Interfaces) != analysis.WANReachable {
			continue
		}

		if rulePortPermits(rule.Destination.Port, port) {
			return true
		}
	}

	for _, nat := range device.NAT.InboundRules {
		if analysis.InboundNATRuleReachability(nat, device.Interfaces, device.FirewallRules) != analysis.WANReachable {
			continue
		}

		if rulePortPermits(nat.ExternalPort, port) {
			return true
		}
	}

	return false
}

// rulePortPermits reports whether a rule's destination/external port permits
// traffic to the given numeric service port.
//
// An empty or "any" rule port permits every port. Otherwise the rule port is
// parsed as a comma-separated list whose entries are each either a concrete
// numeric port or a numeric "N-M" range; a match is exact-numeric or
// range-containment. A token that is neither numeric nor a numeric range is an
// OPNsense/pfSense port alias we cannot resolve without the alias table, so it
// is treated as permitting the port — the over-report (safe) direction,
// consistent with the empty/"any" handling. This deliberately never
// under-reports: a possibly-exposed service is never classified as safely
// LAN-only on unresolvable input, because a false negative in a security audit
// is worse than a false positive.
func rulePortPermits(rulePort string, servicePort int) bool {
	if rulePort == "" || rulePort == constants.NetworkAny {
		return true
	}

	for token := range strings.SplitSeq(rulePort, ",") {
		token = strings.TrimSpace(token)
		if token == "" {
			continue
		}

		if lo, hi, ok := parsePortRange(token); ok {
			if servicePort >= lo && servicePort <= hi {
				return true
			}

			continue
		}

		if p, err := strconv.Atoi(token); err == nil {
			if p == servicePort {
				return true
			}

			continue
		}

		// Non-numeric, non-range token (a port alias): unresolvable here, so
		// over-report rather than emit a false negative.
		return true
	}

	return false
}

// portRangeParts is the expected number of parts in a "start-end" port range.
const portRangeParts = 2

// parsePortRange parses a "N-M" numeric port range into inclusive low/high
// bounds, normalizing reversed bounds. The third result is false when token is
// not a numeric range.
//
//nolint:gocritic // nonamedreturns enforced project-wide
func parsePortRange(token string) (int, int, bool) {
	parts := strings.SplitN(token, "-", portRangeParts)
	if len(parts) != portRangeParts {
		return 0, 0, false
	}

	lo, errLo := strconv.Atoi(strings.TrimSpace(parts[0]))
	hi, errHi := strconv.Atoi(strings.TrimSpace(parts[1]))
	if errLo != nil || errHi != nil {
		return 0, 0, false
	}

	if lo > hi {
		lo, hi = hi, lo
	}

	return lo, hi, true
}

// maxPort is the highest valid TCP/UDP port number.
const maxPort = 65535

// parsePort parses a port string, returning fallback when the string is empty,
// non-numeric, or outside the valid 1..65535 range. The range check matters
// because strconv.Atoi accepts negative and out-of-range values: without it, a
// malformed config.xml port (e.g. "-22") would parse to a nonsensical number
// that never matches a real WAN rule port, silently classifying a genuinely
// WAN-exposed service as LAN-only — the under-report direction this analysis is
// designed to avoid.
func parsePort(s string, fallback int) int {
	if s == "" {
		return fallback
	}

	p, err := strconv.Atoi(s)
	if err != nil || p < 1 || p > maxPort {
		return fallback
	}

	return p
}

// newExposureFinding builds a red-mode exposure Finding: an analysis.Finding of
// type findingTypeExposure wrapped with AttackSurface detail and an
// impact/context ExploitNote for the given exposure kind. Shared by the three
// red Finding producers so the wrapper shape lives in exactly one place while
// each producer keeps its own distinct filtering logic.
func newExposureFinding(
	severity analysis.Severity,
	title, description, recommendation, component string,
	surface *AttackSurface,
	kind exploitNoteKind,
	blackhat bool,
) Finding {
	return Finding{
		Finding: analysis.Finding{
			Type:           findingTypeExposure,
			Severity:       string(severity),
			Title:          title,
			Description:    description,
			Recommendation: recommendation,
			Component:      component,
		},
		AttackSurface: surface,
		ExploitNotes:  exploitNoteFor(kind, blackhat),
	}
}

// addWANExposedServices renders each WAN-reachable management service as a
// red-mode Finding carrying AttackSurface detail and an impact/context
// ExploitNote (R15, R17, R19). This is the primary red Findings producer: SSH,
// SNMP, and the WebGUI management plane each land in report.Findings when a WAN
// rule permits their port. LAN-only services are excluded from Findings and
// recorded in the admin-portal inventory instead (R16). The service list is
// computed once by generateRedReport and shared with addAdminPortals. blackhat
// only selects the sharper ExploitNote tone.
func (r *Report) addWANExposedServices(services []exposedService, blackhat bool) {
	count := 0
	for _, svc := range services {
		if svc.reachability != analysis.WANReachable {
			continue
		}

		count++
		r.Findings = append(r.Findings, newExposureFinding(
			svc.severity,
			"WAN-Exposed Service: "+svc.displayName,
			svc.description,
			svc.recommendation,
			svc.component,
			&AttackSurface{
				Type:            "wan-exposed-service",
				Ports:           portsOf(svc.port),
				Services:        []string{svc.name},
				Vulnerabilities: svc.vulnerabilities,
			},
			svc.kind,
			blackhat,
		))
	}

	r.Metadata["wan_exposed_services_count"] = count
	r.Metadata["wan_exposure_scan_completed"] = true
}

// addWeakNATRules renders each WAN-reachable inbound NAT port-forward as a
// red-mode Finding (R15). A NAT rule is included only when it correlates with
// an enabled WAN pass rule (via InboundNATRuleReachability, R3) — a port
// forward with no matching pass rule is inert and is not reported. blackhat only
// selects the sharper ExploitNote tone.
func (r *Report) addWeakNATRules(blackhat bool) {
	device := r.Configuration
	if device == nil {
		r.Metadata["weak_nat_rules_count"] = 0

		return
	}

	count := 0
	for i, nat := range device.NAT.InboundRules {
		if analysis.InboundNATRuleReachability(nat, device.Interfaces, device.FirewallRules) != analysis.WANReachable {
			continue
		}

		count++
		r.Findings = append(r.Findings, newExposureFinding(
			analysis.SeverityHigh,
			"WAN-Reachable Port Forward",
			fmt.Sprintf(
				"Inbound NAT rule %d forwards WAN traffic to an internal host and correlates with an enabled WAN pass rule, exposing the internal service to untrusted networks.",
				i+1,
			),
			"Restrict the source scope of the port forward and its associated pass rule, or remove the rule if the exposure is unnecessary.",
			fmt.Sprintf("nat.inbound[%d]", i),
			&AttackSurface{
				Type:            "port-forward",
				Ports:           portsOf(parsePort(nat.ExternalPort, unknownPort)),
				Services:        natServices(nat),
				Vulnerabilities: []string{"exposed-internal-host"},
			},
			exploitKindPortForward,
			blackhat,
		))
	}

	r.Metadata["weak_nat_rules_count"] = count
}

// addAdminPortals records a structured inventory of the device's management
// portals (WebGUI, SSH) tagged with reachability. This is metadata, not
// Findings: a WAN-reachable portal is already surfaced as a Finding by
// addWANExposedServices, so re-emitting it here would double-count the same
// exposure. The inventory retains LAN-only portals (tagged "lan") so a reader
// sees every management plane, satisfying the AE3 both-halves invariant — the
// LAN-only portal is present here and absent from the WAN-exposed Findings. The
// service list is computed once by generateRedReport and shared with
// addWANExposedServices.
func (r *Report) addAdminPortals(services []exposedService) {
	// No capacity hint: the loop filters out non-portal services (SNMP), so the
	// final length is not known ahead of time (AGENTS.md item 7).
	var portals []adminPortal

	for _, svc := range services {
		if svc.kind != exploitKindWebGUI && svc.kind != exploitKindSSH {
			continue
		}

		portals = append(portals, adminPortal{
			Name:         svc.name,
			Port:         svc.port,
			Reachability: svc.reachability,
		})
	}

	slices.SortFunc(portals, func(a, b adminPortal) int {
		return strings.Compare(a.Name, b.Name)
	})

	r.Metadata["admin_portals"] = portals
	r.Metadata["admin_portals_count"] = len(portals)
}

// adminPortal is one management-plane entry in the red-mode admin-portal
// inventory metadata.
type adminPortal struct {
	// Name is the portal service name (e.g. "webgui", "ssh").
	Name string `json:"name"`
	// Port is the portal's listening port.
	Port int `json:"port"`
	// Reachability is where the portal is reachable from (wan, lan, or local).
	Reachability analysis.Reachability `json:"reachability"`
}

// addAttackSurfaces renders the shared engine's WAN-reachable hygiene
// observations as red-mode exposure Findings (R16): a config weakness that is
// internet-reachable is adversarially relevant and reframed as exposure.
// Observations already surfaced as service/NAT Findings (matched by Component)
// are skipped so an exposure is not double-counted. Only WAN-reachable
// observations are included; LAN-only and local hygiene items are excluded from
// the red exposure sections. blackhat only selects the sharper ExploitNote tone.
func (r *Report) addAttackSurfaces(observations []analysis.Observation, blackhat bool) {
	existing := make(map[string]struct{}, len(r.Findings))
	for _, f := range r.Findings {
		if f.Component != "" {
			existing[f.Component] = struct{}{}
		}
	}

	count := 0
	for _, obs := range observations {
		if obs.Reachability != analysis.WANReachable {
			continue
		}

		if _, seen := existing[obs.Component]; seen {
			continue
		}

		count++
		existing[obs.Component] = struct{}{}
		r.Findings = append(r.Findings, newExposureFinding(
			obs.Severity,
			"Exposed Weakness: "+obs.Title,
			obs.Description,
			obs.Recommendation,
			obs.Component,
			&AttackSurface{
				Type: "config-weakness",
				// Ports/Services have no omitempty, so emit empty slices (not
				// nil) to keep the JSON shape consistent with the service and
				// port-forward producers, which serialize [] rather than null.
				Ports:           []int{},
				Services:        []string{},
				Vulnerabilities: []string{obs.Title},
			},
			exploitKindConfigWeakness,
			blackhat,
		))
	}

	r.Metadata["attack_surfaces_count"] = count

	// R16: WAN-reachable exposures lead. All red Findings are WAN-reachable by
	// construction, so order them by severity (most urgent first).
	r.sortRedFindingsBySeverity()
}

// sortRedFindingsBySeverity orders report.Findings by severity, most urgent
// first, using the shared severityOrder ranking. Stable so equal-severity
// findings keep their producer order (services, then NAT, then attack
// surfaces).
func (r *Report) sortRedFindingsBySeverity() {
	slices.SortStableFunc(r.Findings, func(a, b Finding) int {
		return severityRank(analysis.Severity(a.Severity)) - severityRank(analysis.Severity(b.Severity))
	})
}

// addEnumerationData records a structured reconnaissance summary of the device
// (element counts an attacker would enumerate). Metadata, not Findings — these
// are inventory facts, not exposures.
func (r *Report) addEnumerationData() {
	var data enumerationData

	if cfg := r.Configuration; cfg != nil {
		data.Interfaces = len(cfg.Interfaces)
		for _, iface := range cfg.Interfaces {
			if analysis.InterfaceReachability(iface) == analysis.WANReachable {
				data.WANInterfaces++
			}
		}

		data.FirewallRules = len(cfg.FirewallRules)
		data.InboundNATRules = len(cfg.NAT.InboundRules)
		data.Users = len(cfg.Users)
		data.Groups = len(cfg.Groups)
	}

	r.Metadata["enumeration_data"] = data
	// Report completion honestly: with no configuration there was nothing to
	// enumerate, so the step did not "complete" over real data. Mirrors the
	// compliance_check_completed honesty fix in generateBlueReport.
	r.Metadata["enumeration_completed"] = r.Configuration != nil
}

// enumerationData is the red-mode reconnaissance summary metadata.
type enumerationData struct {
	// Interfaces is the number of configured interfaces.
	Interfaces int `json:"interfaces"`
	// WANInterfaces is the number of WAN-reachable interfaces.
	WANInterfaces int `json:"wanInterfaces"`
	// FirewallRules is the number of configured firewall rules.
	FirewallRules int `json:"firewallRules"`
	// InboundNATRules is the number of inbound NAT (port-forward) rules.
	InboundNATRules int `json:"inboundNatRules"`
	// Users is the number of configured user accounts.
	Users int `json:"users"`
	// Groups is the number of configured groups.
	Groups int `json:"groups"`
}

// portsOf returns a single-element port slice, or an empty slice when the port
// is unknown, so AttackSurface.Ports never carries a meaningless zero.
func portsOf(port int) []int {
	if port == unknownPort {
		return []int{}
	}

	return []int{port}
}

// natServices returns a best-effort service label slice for an inbound NAT
// rule, using its layer-4 protocol when present.
func natServices(nat common.InboundNATRule) []string {
	if nat.Protocol != "" {
		return []string{nat.Protocol}
	}

	return []string{}
}
