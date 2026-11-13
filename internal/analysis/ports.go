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

// maxPortAliasVisits bounds how many alias expansions one endpoint may take, so
// a graph of aliases that name each other many times cannot drive the walk
// into exponential work. Far above any real configuration.
const maxPortAliasVisits = 4096

// wellKnownServicePorts maps the service names OPNsense's PortField accepts as
// a rule port to their numbers (PortField.php $wellknownservices). It is the
// same list as wellKnownPorts in pkg/parser/opnsense, which pkg/ cannot share
// with internal/; both are pinned against PortField.php, so change them
// together.
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
		ranges, every, ok := parsePortSpec(ep.Port, ruleVocab)
		if !ok {
			return portValues{cause: causeValue}
		}

		return portValues{ranges: ranges, every: every}
	}

	w := portAliasWalker{no: no, visiting: make(map[string]struct{})}
	w.walk(ep.PortRef.Name, 0)

	if len(w.ranges) > maxResolvedMembers {
		return portValues{cause: w.cause | causeAlias}
	}

	return portValues{ranges: mergeIntervals(w.ranges), every: w.every, cause: w.cause}
}

// portAliasWalker expands one port alias tree for resolvePorts.
type portAliasWalker struct {
	no       common.NamedObjects
	visiting map[string]struct{}
	visits   int
	ranges   []portRange
	every    bool
	cause    blockCause
}

// walk adds the ports of the alias name to w. The loader keeps the rest of an
// alias when one member is cyclic, so a cycle only marks the set incomplete.
func (w *portAliasWalker) walk(name string, depth int) {
	w.visits++

	obj, exists := w.no[name]
	if !exists || depth > maxPortAliasDepth || w.visits > maxPortAliasVisits ||
		len(w.ranges) > maxResolvedMembers {
		w.cause |= causeAlias

		return
	}

	if _, cyclic := w.visiting[name]; cyclic {
		w.cause |= causeAlias

		return
	}

	// The loader reads only aliases of type port. Anything else, such as a
	// URL table of ports, is fetched at runtime or loaded differently by each
	// vendor, so its ports are not known.
	if obj.Type != common.NamedObjectTypePort {
		w.cause |= causeAlias

		return
	}

	// A disabled alias loads with no members (filter.lib.inc L153, and
	// filter.inc L607-L611 turns an empty alias into a port that matches
	// nothing). Only OPNsense's model can disable an alias.
	if obj.Disabled {
		return
	}

	w.visiting[name] = struct{}{}
	defer delete(w.visiting, name)

	for _, member := range obj.Members {
		if _, nested := w.no[member]; nested {
			w.walk(member, depth+1)

			continue
		}

		ranges, every, ok := parsePortSpec(member, aliasVocab)
		if !ok {
			w.cause |= causeValue

			continue
		}

		w.every = w.every || every
		w.ranges = append(w.ranges, ranges...)
	}
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
