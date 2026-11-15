package analysis

import (
	"strconv"
	"strings"

	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
)

// maxPort is the highest TCP/UDP port number.
const maxPort = 65535

// maxPortAliasDepth bounds how deeply nested port aliases are followed, as
// NamedObjects.Resolve bounds every alias.
const maxPortAliasDepth = 16

// maxPortAliasVisits bounds how many alias expansions one endpoint may take, in
// the port walk and in the literal address walk of the complement proof, so a
// graph of aliases that name each other many times cannot drive either walk
// into exponential work. The port walk caches an alias it has expanded, and
// expands it again only when a cycle or the depth cap was involved, so there
// the budget stops a graph of cycles or a tree of more than 4096 aliases. Far
// above any real configuration.
const maxPortAliasVisits = 4096

// maxPortAliasWork bounds how many port ranges one port alias walk gathers,
// counting an alias's ranges each time a parent takes them, so that many
// aliases which each take a large set cannot keep the walk busy. A walk that
// reaches it leaves the set incomplete. It is far above any real
// configuration and far above maxResolvedMembers, so aliases whose sets
// overlap are merged before the member cap is applied. Reaching it takes
// something like hundreds of aliases that each name one alias of thousands of
// ports, which NamedObjects.Resolve would expand in full.
const maxPortAliasWork = 1 << 20

// wellKnownServicePorts maps the service names OPNsense's PortField accepts as
// a rule port to their numbers (PortField.php $wellknownservices). It is the
// same list as wellKnownPorts in pkg/parser/opnsense, kept as a copy because
// pkg/ must not import internal/ and sharing the converter's list would mean
// exporting it as public API; both are pinned against PortField.php, so
// change them together.
//
//nolint:gochecknoglobals // immutable lookup table copied from the vendor source
var wellKnownServicePorts = map[string]string{
	"afs3-fileserver": "7000", "aol": "5190", "auth": "113", "avt-profile-1": "5004", "cvsup": "5999",
	"domain": "53", "domain-s": "853", "ftp": "21", "hbci": "3000", "http": "80", "https": "443",
	"igmpv3lite": "465", "imap": "143", "imaps": "993", "ipsec-msft": "10000", "ipsec-nat-t": "4500",
	"isakmp": "500", "l2f": "1701", "ldap": "389", "ldaps": "636", "microsoft-ds": "445",
	"ms-streaming": "1755", "ms-wbt-server": "3389", "msnp": "1863", "nat-stun-port": "3478",
	"netbios-dgm": "138", "netbios-ns": "137", "netbios-ssn": "139", "nntp": "119", "ntp": "123",
	"openvpn": "1194", "pop3": "110", "pop3s": "995", "pptp": "1723", "radius": "1812",
	"radius-acct": "1813", "rfb": "5900", "sip": "5060", "sip-tls": "5061", "smtp": "25", "snmp": "161",
	"snmptrap": "162", "ssh": "22", "submission": "587", "submissions": "465", "telnet": "23",
	"teredo": "3544", "tftp": "69", "urd": "465", "wins": "1512",
}

// notInServices lists the PortField names FreeBSD's /etc/services does not
// carry. A rule port may use them, since the ruleset maps them through
// PortField::getWellKnown, but an alias member may not: the alias model and
// the loader read members with getservbyname, which looks only at
// /etc/services, so the firewall drops such a member.
//
//nolint:gochecknoglobals // immutable set derived from the vendor source
var notInServices = map[string]struct{}{
	"aol": {}, "avt-profile-1": {}, "hbci": {}, "ipsec-msft": {}, "ms-streaming": {}, "msnp": {},
	"nat-stun-port": {}, "radius-acct": {}, "rfb": {}, "teredo": {}, "wins": {},
}

// portVocab says which service names a port value may use.
type portVocab int

const (
	// ruleVocab is a rule's own port: every PortField name.
	ruleVocab portVocab = iota
	// aliasVocab is a port alias member: the PortField names /etc/services
	// also carries.
	aliasVocab
)

// servicePort returns the port number of a service name and whether vocab
// accepts the name. The match is exact, as getservbyname's lookup is, so
// TELNET is not telnet.
func servicePort(name string, vocab portVocab) (string, bool) {
	number, ok := wellKnownServicePorts[name]
	if !ok {
		return "", false
	}

	if _, missing := notInServices[name]; missing && vocab == aliasVocab {
		return "", false
	}

	return number, true
}

// parsePortNumber parses one port: a number, or a service name vocab accepts.
func parsePortNumber(s string, vocab portVocab) (int, bool) {
	s = strings.TrimSpace(s)
	if number, ok := servicePort(s, vocab); ok {
		s = number
	}

	return parsePortDigits(s)
}

// parsePortDigits parses decimal digits up to 65535. A sign, a space inside
// the value or an empty string is not a port, as in Util::isPort, which
// requires ctype_digit.
func parsePortDigits(s string) (int, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, false
	}

	for _, r := range s {
		if r < '0' || r > '9' {
			return 0, false
		}
	}

	n, err := strconv.Atoi(s)
	if err != nil || n > maxPort {
		return 0, false
	}

	return n, true
}

// blockCause records why a set of ports is known only in part. A zero value
// means it is known in full.
type blockCause uint8

const (
	// causeAlias: an alias could not be expanded (unknown, dynamic, cyclic,
	// nested too deeply or too large).
	causeAlias blockCause = 1 << iota
	// causeValue: a value is not a port, a range or a service name the
	// analysis knows.
	causeValue
)

// portValues is the set of ports an endpoint matches, as far as it can be
// read: the merged intervals that could be read, whether a wildcard member
// makes it match every port, and why any part could not be read.
type portValues struct {
	ranges []portRange
	every  bool
	cause  blockCause
}

// complete reports whether every part of the set could be read.
func (v portValues) complete() bool {
	return v.cause == 0
}

// matchesNothing reports whether the set was read in full and holds no port,
// as a disabled or empty port alias does.
func (v portValues) matchesNothing() bool {
	return v.complete() && !v.every && len(v.ranges) == 0
}

// resolvePorts reads the ports an endpoint matches. A literal port is parsed
// as a rule port. A port alias is expanded as the ruleset loader expands it
// (filter.lib.inc filter_core_get_port_alias): a disabled alias, at any depth,
// contributes no port, and a member that names another alias is expanded in
// turn. Unlike the loader, which drops what it cannot read, a part this code
// cannot read leaves the set incomplete, since the analysis knows fewer
// service names than /etc/services holds. The parts it could read are kept,
// so a caller can still act on a port they certainly contain.
func resolvePorts(ep common.RuleEndpoint, no common.NamedObjects) portValues {
	if ep.PortRef == nil {
		ranges, every, complete := parsePortSpec(ep.Port)
		if !complete {
			return portValues{cause: causeValue}
		}

		return portValues{ranges: ranges, every: every}
	}

	w := portAliasWalker{
		no:       no,
		visiting: make(map[string]struct{}),
		memo:     make(map[string]portSubtree),
	}
	sub, _ := w.walk(ep.PortRef.Name, 0)

	// The cap counts the merged set, so a port listed twice, or reached
	// through two aliases, counts once, as both loaders keep it once.
	if len(sub.ranges) > maxResolvedMembers {
		return portValues{cause: sub.cause | causeAlias}
	}

	return portValues{ranges: sub.ranges, cause: sub.cause}
}

// portSubtree is what one port alias contributes to a set: its merged ranges,
// why any part could not be read, and how many levels of nested aliases lie
// below it.
type portSubtree struct {
	ranges []portRange
	cause  blockCause
	height int
}

// portAliasWalker expands one port alias tree for resolvePorts.
type portAliasWalker struct {
	no       common.NamedObjects
	visiting map[string]struct{}
	// memo holds each alias whose reading does not depend on the path that
	// reached it, so an alias named many times is expanded once, as
	// NamedObjects.Resolve caches a clean subtree.
	memo   map[string]portSubtree
	visits int
	work   int
}

// walk returns the ports of the alias name, reached at depth, and whether the
// answer is the same on every path to it, so that it may be cached. A cycle,
// the depth cap and the two work caps depend on the path or on what was walked
// before, so an answer that met one is not cached. The loader keeps the rest
// of an alias when one member is cyclic, so a cycle only marks the set
// incomplete.
func (w *portAliasWalker) walk(name string, depth int) (portSubtree, bool) {
	if depth > maxPortAliasDepth {
		return portSubtree{cause: causeAlias}, false
	}

	// An alias cached on a shorter path may reach past the depth cap on this
	// one. It is then marked incomplete, as an uncached walk would mark it,
	// but keeps every range, as OPNsense's loader, which has no depth cap,
	// does. The set comes out the same in whichever order the two paths are
	// walked.
	if sub, cached := w.memo[name]; cached {
		if depth+sub.height > maxPortAliasDepth {
			sub.cause |= causeAlias

			return sub, false
		}

		return sub, true
	}

	if _, cyclic := w.visiting[name]; cyclic {
		return portSubtree{cause: causeAlias}, false
	}

	w.visits++
	if w.visits > maxPortAliasVisits || w.work > maxPortAliasWork {
		return portSubtree{cause: causeAlias}, false
	}

	obj, exists := w.no[name]

	// The loader reads only aliases of type port. Anything else, such as a
	// URL table of ports, is fetched at runtime or loaded differently by each
	// vendor, so its ports are not known.
	if !exists || obj.Type != common.NamedObjectTypePort {
		return portSubtree{cause: causeAlias}, true
	}

	// A disabled alias loads with no members (filter.lib.inc L153, and
	// filter.inc L607-L611 turns an empty alias into a port that matches
	// nothing). Only OPNsense's model can disable an alias.
	if obj.Disabled {
		return portSubtree{}, true
	}

	w.visiting[name] = struct{}{}
	defer delete(w.visiting, name)

	sub, cacheable := w.members(obj.Members, depth)
	if cacheable {
		w.memo[name] = sub
	}

	return sub, cacheable
}

// members reads the members of one alias reached at depth, and reports
// whether the answer may be cached. A member listed twice adds nothing the
// first did not: the loader expands a nested alias the same way each time and
// keeps a port it already holds once (filter.lib.inc in_array).
func (w *portAliasWalker) members(members []string, depth int) (portSubtree, bool) {
	var (
		sub    portSubtree
		ranges []portRange
	)

	cacheable := true
	seen := make(map[string]struct{}, len(members))

	for _, member := range members {
		if _, repeated := seen[member]; repeated {
			continue
		}

		seen[member] = struct{}{}

		if w.work > maxPortAliasWork {
			sub.cause |= causeAlias
			cacheable = false

			break
		}

		if _, nested := w.no[member]; nested {
			child, ok := w.walk(member, depth+1)
			cacheable = cacheable && ok
			sub.cause |= child.cause
			sub.height = max(sub.height, child.height+1)
			ranges = append(ranges, child.ranges...)
			w.work += len(child.ranges)

			continue
		}

		// A member is read as one port or one colon range. OPNsense's loader
		// reads it with is_port or is_portrange and drops anything else, a
		// comma list, a dash range and "any" included, keeping the other
		// members. pfSense's (filter_generate_nested_alias_recurse) takes a
		// dash range or "any" for a hostname, hands it to filterdns and then
		// empties the whole alias, and keeps a comma list such as "20,23"
		// verbatim, which pf loads as two ports. A member this code cannot
		// read is therefore left unknown rather than dropped, which is also
		// right for a service name the analysis does not know.
		r, ok := parsePortPart(member, aliasVocab)
		if !ok {
			sub.cause |= causeValue

			continue
		}

		ranges = append(ranges, r)
		w.work++
	}

	sub.ranges = mergeIntervals(ranges)

	return sub, cacheable
}

// PortSet is the set of ports a rule endpoint matches once its port alias,
// nested aliases included, is expanded. It may be known only in part.
type PortSet struct {
	values portValues
}

// EndpointPorts reads the ports an endpoint matches, resolving a port alias
// through NamedObjects the way the shadow analysis does. Check Complete before
// reading a set that names none of the ports asked about as matching none.
func EndpointPorts(ep common.RuleEndpoint, no common.NamedObjects) PortSet {
	return PortSet{values: resolvePorts(ep, no)}
}

// Complete reports whether every part of the set could be read. When it is
// false the set may hold ports ContainsAny cannot see.
func (s PortSet) Complete() bool {
	return s.values.complete()
}

// MatchesNothing reports whether the set was read in full and holds no port,
// as a disabled port alias or one with no members does. A rule with such an
// endpoint matches no traffic.
func (s PortSet) MatchesNothing() bool {
	return s.values.matchesNothing()
}

// CoversEveryPort reports whether the set matches every port: the any-port
// wildcard, or ranges that span 1 to 65535. pfSense writes no port statement
// at all for a rule to 1-65535.
func (s PortSet) CoversEveryPort() bool {
	if s.values.every {
		return true
	}

	for _, r := range s.values.ranges {
		if r.lo <= 1 && r.hi >= maxPort {
			return true
		}
	}

	return false
}

// ContainsAny reports whether the part of the set that could be read names any
// of ports. The any-port wildcard does not count: a caller looking for a rule
// aimed at a service reads a rule open to every port separately, if at all.
func (s PortSet) ContainsAny(ports ...int) bool {
	for _, r := range s.values.ranges {
		for _, port := range ports {
			if r.lo <= port && port <= r.hi {
				return true
			}
		}
	}

	return false
}
