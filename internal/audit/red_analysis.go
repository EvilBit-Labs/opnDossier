package audit

import (
	"cmp"
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/EvilBit-Labs/opnDossier/internal/analysis"
	"github.com/EvilBit-Labs/opnDossier/internal/constants"
	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
)

// Default listening ports for the in-scope management services. WebGUI uses
// its configured custom port (device.System.WebGUI.Port) when the unified
// model carries one; otherwise the port is inferred from the configured
// protocol.
const (
	portHTTPS   = 443
	portHTTP    = 80
	portSSH     = 22
	portSNMP    = 161
	unknownPort = 0

	// protocolHTTP is the WebGUI protocol value that selects the HTTP default
	// port. Matched case-insensitively (constants.ProtocolHTTPS is the only
	// other recognized value, and any other/unset protocol keeps the HTTPS
	// default — the safer direction per R17: over-report exposure rather than
	// mis-infer a lower-risk port from an unrecognized protocol string).
	protocolHTTP = "http"
)

// maxManagementServices is the number of in-scope management services
// (WebGUI, SSH, SNMP) — the upper bound for the serviceExposures slice.
const maxManagementServices = 3

// findingTypeExposure is the Finding.Type for every red-mode exposure finding.
const findingTypeExposure = "exposure"

// aliasTypeNetworkGroup is the vendor type of an OPNsense alias whose members are
// all alias names. The model has no constant for it (GOTCHAS 23.1).
const aliasTypeNetworkGroup common.NamedObjectType = "networkgroup"

// aliasNamePattern matches the characters both vendors allow in an alias name.
// No address, URL or hostname with a domain is made of these alone.
var aliasNamePattern = regexp.MustCompile(`^\w+$`)

// exposedService describes an in-scope management/system service and where it
// is reachable from. Reachability is computed by correlating the service's
// listening port against the device's WAN-reachable firewall and inbound-NAT
// rules (R17) — a service is WAN-reachable only when an actual rule permits its
// port, never on the service being enabled alone.
type exposedService struct {
	kind         exploitNoteKind
	name         string
	displayName  string
	severity     analysis.Severity
	component    string
	port         int
	reachability analysis.Reachability
	// description asserts WAN reachability unconditionally ("...is reachable
	// from a WAN interface...") regardless of the actual reachability value
	// above. It is only accurate when reachability == analysis.WANReachable
	// and must only be surfaced for a WAN-reachable instance — its sole
	// consumer, addWANExposedServices, filters to WAN-reachable services
	// before rendering this text.
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

	// WebGUI is always listening; the only question is its reachability. Both
	// OPNsense and pfSense parsers populate device.System.WebGUI.Port with the
	// configured custom port when the config.xml sets one; the protocol default
	// below applies only when the port is absent.
	webGUIPort := portHTTPS
	if strings.EqualFold(device.System.WebGUI.Protocol, protocolHTTP) {
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

// serviceReachability classifies a firewall-local management service (WebGUI,
// SSH, SNMP) by port: WAN-reachable when wanRulePermitsPort finds a pass rule
// that admits that port on the firewall, otherwise LAN-only. A configured
// management service is never Local.
//
// Deliberately never counts device.NAT.InboundRules as exposure: an inbound NAT
// rule forwards WAN traffic to InboundNATRule.InternalIP, normally a different
// host than the firewall itself, so a NAT rule sharing the same external port as
// a management service is never evidence that the firewall's OWN service is
// WAN-reachable. A forward can target the firewall, but the evidence is then the
// filter rule that passes it, never the forward, so a forward that stores no
// filter rule (the Pass association, which pf gets as rdr pass) reports nothing
// here. Correlating NAT rules against firewall-local ports produced a false
// positive: a NAT rule forwarding WAN port 22 to an unrelated internal host's SSH
// would flag the firewall's own SSH daemon (also on port 22) as exposed even with
// no pass rule ever targeting the firewall directly. NAT rules are correlated
// separately, on their own terms, by addWeakNATRules/InboundNATRuleReachability.
func serviceReachability(device *common.CommonDevice, port int) analysis.Reachability {
	if wanRulePermitsPort(device, port) {
		return analysis.WANReachable
	}

	return analysis.LANOnly
}

// wanRulePermitsPort reports whether any WAN-reachable enabled firewall pass
// rule permits the given port on the firewall itself. A rule that passes a port
// forward's traffic to another host does not count (forwardsToAnotherHost).
// Port matching biases toward over-reporting exposure (the safe direction for a
// security tool): an empty or "any" rule port permits every port, a numeric
// range or comma-list is matched by containment, and an unresolvable port alias
// is treated as permitting the port rather than silently classifying the service
// as safely LAN-only. As far as ports go, only a concrete numeric port that does
// not contain the service port is treated as non-permitting. See rulePortPermits.
func wanRulePermitsPort(device *common.CommonDevice, port int) bool {
	for _, rule := range device.FirewallRules {
		if rule.Disabled || rule.Type != common.RuleTypePass {
			continue
		}

		if analysis.RuleReachability(rule, device.Interfaces) != analysis.WANReachable ||
			forwardsToAnotherHost(rule, device) {
			continue
		}

		if rulePortPermits(rule.Destination.Port, port) {
			return true
		}
	}

	return false
}

// forwardsToAnotherHost reports whether rule passes a port forward's traffic to
// a host other than the firewall. pf matches a filter rule after rdr has
// rewritten the destination to the forward's target, so such a rule never
// admits traffic to the firewall's own services. The rule's destination is what
// ties it to a forward: both vendors copy the target onto the rule a forward
// stores for itself, and the "unassociated" option of the OPNsense port forward
// page, up to 25.7, writes the same rule with no link. The link is not read,
// because from 26.1 deleting a forward leaves its rule behind with the link, so
// a link alone says nothing about where traffic goes.
//
// Another host is a literal address or network a forward targets that holds no
// address of the firewall (firewallAddresses), or an alias a forward targets
// (forwardsToAlias). A network that holds one keeps the rule, since traffic to
// that address passes it as well, and so does a macro or a name the config does
// not define: the over-report direction. So does a rule of its own to an address
// or network no forward targets, which may hold an address the firewall has and
// the config does not record, such as a DHCP lease.
func forwardsToAnotherHost(rule common.FirewallRule, device *common.CommonDevice) bool {
	if rule.Destination.Negated {
		return false
	}

	own := firewallAddresses(device)

	if ref := rule.Destination.AddressRef; ref != nil {
		return forwardsToAlias(ref.Name, device, own)
	}

	target, ok := literalNetwork(rule.Destination.Address)
	if !ok || holdsFirewallAddress(rule.Destination.Address, own) {
		return false
	}

	return slices.ContainsFunc(device.NAT.InboundRules, func(nat common.InboundNATRule) bool {
		forwardTarget, ok := literalNetwork(nat.InternalIP)
		return ok && forwardTarget == target
	})
}

// literalNetwork reads a literal address as the network of that one host and a
// CIDR as its network with the host bits cleared, so that two spellings of one
// target compare equal.
func literalNetwork(entry string) (netip.Prefix, bool) {
	if addr, err := netip.ParseAddr(entry); err == nil {
		return netip.PrefixFrom(addr, addr.BitLen()), true
	}

	prefix, err := netip.ParsePrefix(entry)

	return prefix.Masked(), err == nil
}

// forwardsToAlias reports whether the alias name is a port forward's target and
// holds no address of the firewall. Both vendors copy an alias target onto the
// forward's rule as it stands, so the name is what ties the two together. The
// members the config holds are the only evidence, so an alias whose members the
// firewall fetches at runtime, such as a URL table, counts as the forward's rule.
func forwardsToAlias(name string, device *common.CommonDevice, own []netip.Addr) bool {
	isTarget := slices.ContainsFunc(device.NAT.InboundRules, func(nat common.InboundNATRule) bool {
		return nat.InternalIP == name
	})

	return isTarget && !aliasHoldsFirewallAddress(device.NamedObjects, name, own)
}

// aliasHoldsFirewallAddress walks the members of the alias name, and of every
// alias they name, for an address of the firewall. It reads Members directly:
// NamedObjects.Resolve stops on any type but host, network and port, and a
// network group is such a type although its members are alias names (GOTCHAS
// 23.1). A member no alias defines counts when it can name a table the config
// does not store (namesUnstoredTable). A URL, a country code or a hostname with a
// domain names no alias and tells nothing, so a table fetched at runtime reads as
// holding no address. seen is shared by the whole walk, so a nesting loop ends
// and an alias named many times is read once.
func aliasHoldsFirewallAddress(objects common.NamedObjects, name string, own []netip.Addr) bool {
	seen := map[string]bool{name: true}
	pending := []string{name}

	for len(pending) > 0 {
		last := len(pending) - 1
		object := objects[pending[last]]
		pending = pending[:last]

		for _, member := range object.Members {
			_, defined := objects[member]

			switch {
			case holdsFirewallAddress(member, own), !defined && namesUnstoredTable(object.Type, member):
				return true
			case defined && !seen[member]:
				seen[member] = true
				pending = append(pending, member)
			}
		}
	}

	return false
}

// namesUnstoredTable reports whether member of an alias of aliasType, which no
// alias in the config defines, reads as the name of a table the config does not
// store. OPNsense generates such tables and accepts them as members of a host,
// network or network group alias: __<interface>_network, the network of an
// interface, which holds the firewall's own address there, and static tables such
// as bogons. Their contents are not in the config, so a bare name keeps the rule,
// the over-report direction, and that covers a name a deleted alias left behind.
// A hostname with a domain does not match and tells nothing. One with no domain
// has the shape of an alias name, cannot be told from one, and keeps the rule.
func namesUnstoredTable(aliasType common.NamedObjectType, member string) bool {
	nests := aliasType == common.NamedObjectTypeHost || aliasType == common.NamedObjectTypeNetwork ||
		aliasType == aliasTypeNetworkGroup

	return nests && aliasNamePattern.MatchString(member)
}

// firewallAddresses returns the loopback addresses and the addresses the config
// records for the firewall on an interface: its IPv4 and IPv6 address, the alias
// address of its DHCP client, and its virtual IPs. An interface configured by
// DHCP records no address of its own, and an address recorded anywhere else, such
// as a tunnel's inner address, is not read. The loopback addresses are what makes
// a network as wide as 0.0.0.0/0 hold one on a firewall that records no other.
func firewallAddresses(device *common.CommonDevice) []netip.Addr {
	entries := make([]string, 0, 2+3*len(device.Interfaces)+len(device.VirtualIPs))
	entries = append(entries, "127.0.0.1", "::1")

	for _, iface := range device.Interfaces {
		entries = append(entries, iface.IPAddress, iface.IPv6Address)
		if iface.DHCPAdvancedV4 != nil {
			entries = append(entries, iface.DHCPAdvancedV4.AliasAddress)
		}
	}

	for _, vip := range device.VirtualIPs {
		entries = append(entries, vip.Subnet)
	}

	var own []netip.Addr

	for _, entry := range entries {
		if addr, err := netip.ParseAddr(entry); err == nil {
			own = append(own, addr)
		}
	}

	return own
}

// holdsFirewallAddress reports whether entry is, or spans, a loopback address or
// an address in own. It reads a literal address, a CIDR, the wildcard network an
// OPNsense network alias can hold, and the first-last range an OPNsense host
// alias can hold. Any other form, such as a hostname or an entry excluded with
// "!", tells nothing and does not count.
func holdsFirewallAddress(entry string, own []netip.Addr) bool {
	if addr, err := netip.ParseAddr(entry); err == nil {
		return addr.IsLoopback() || slices.Contains(own, addr)
	}

	if prefix, err := netip.ParsePrefix(entry); err == nil {
		return prefix.Addr().IsLoopback() || slices.ContainsFunc(own, prefix.Contains)
	}

	if wildcardHoldsFirewallAddress(entry, own) {
		return true
	}

	from, to, _ := strings.Cut(entry, "-")
	first, errFirst := netip.ParseAddr(from)
	last, errLast := netip.ParseAddr(to)
	if errFirst != nil || errLast != nil {
		return false
	}

	return first.IsLoopback() || slices.ContainsFunc(own, func(addr netip.Addr) bool {
		return !addr.Less(first) && !last.Less(addr)
	})
}

// wildcardHoldsFirewallAddress reports whether entry is a wildcard network that
// matches a loopback address or an address in own. Such a network is an address
// and a mask of one family, and a bit set in the mask matches either value, so
// 192.168.0.1/0.0.255.0 is 192.168.x.1 (net_wildcard_iterator in OPNsense's
// alias/base.py).
func wildcardHoldsFirewallAddress(entry string, own []netip.Addr) bool {
	from, to, _ := strings.Cut(entry, "/")
	base, errBase := netip.ParseAddr(from)
	mask, errMask := netip.ParseAddr(to)
	if errBase != nil || errMask != nil || base.BitLen() != mask.BitLen() {
		return false
	}

	return base.IsLoopback() || slices.ContainsFunc(own, func(addr netip.Addr) bool {
		return addr.BitLen() == base.BitLen() && differOnlyInMask(addr, base, mask)
	})
}

// differOnlyInMask reports whether two addresses of one family differ only in
// bits set in mask.
func differOnlyInMask(first, second, mask netip.Addr) bool {
	firstBytes, secondBytes, maskBytes := first.AsSlice(), second.AsSlice(), mask.AsSlice()

	for i := range maskBytes {
		if (firstBytes[i]^secondBytes[i])&^maskBytes[i] != 0 {
			return false
		}
	}

	return true
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
	s = strings.TrimSpace(s)
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
				Type:            constants.FindingTypeWANExposedService,
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
// forward with no matching pass rule is inert and is not reported, and neither
// is a no-RDR rule, which exempts traffic from redirection and forwards
// nothing. blackhat only selects the sharper ExploitNote tone.
func (r *Report) addWeakNATRules(blackhat bool) {
	device := r.Configuration
	if device == nil {
		r.Metadata["weak_nat_rules_count"] = 0

		return
	}

	count := 0
	for i, nat := range device.NAT.InboundRules {
		if nat.NoRDR ||
			analysis.InboundNATRuleReachability(nat, device.Interfaces, device.FirewallRules) != analysis.WANReachable {
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
				Type: constants.FindingTypePortForward,
				// Neither vendor writes <externalport>; the matched port is the
				// destination port.
				Ports:           portsOf(parsePort(cmp.Or(nat.ExternalPort, nat.Destination.Port), unknownPort)),
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
	Name string `json:"name" yaml:"name"`
	// Port is the portal's listening port.
	Port int `json:"port" yaml:"port"`
	// Reachability is where the portal is reachable from (wan, lan, or local).
	Reachability analysis.Reachability `json:"reachability" yaml:"reachability"`
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
				Type: constants.FindingTypeConfigWeakness,
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
	Interfaces int `json:"interfaces" yaml:"interfaces"`
	// WANInterfaces is the number of WAN-reachable interfaces.
	WANInterfaces int `json:"wanInterfaces" yaml:"wanInterfaces"`
	// FirewallRules is the number of configured firewall rules.
	FirewallRules int `json:"firewallRules" yaml:"firewallRules"`
	// InboundNATRules is the number of inbound NAT (port-forward) rules.
	InboundNATRules int `json:"inboundNatRules" yaml:"inboundNatRules"`
	// Users is the number of configured user accounts.
	Users int `json:"users" yaml:"users"`
	// Groups is the number of configured groups.
	Groups int `json:"groups" yaml:"groups"`
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
