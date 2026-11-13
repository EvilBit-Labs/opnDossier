package analysis

import (
	"strconv"
	"strings"

	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
)

// maxPort is the highest TCP/UDP port number.
const maxPort = 65535

// wellKnownServicePorts maps the service names OPNsense's PortField accepts as
// a port to their numbers (PortField.php $wellknownservices). The filter
// model's converter rewrites a rule port through it, and the port parser reads
// alias members with it, since an alias member may be any name in
// /etc/services (Util::isPort calls getservbyname). A name outside this table
// stays unparseable, and every caller treats that as unknown rather than as no
// match.
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

// ServicePort returns the port number of a well-known service name, matched
// without regard to case, and whether the name is known.
func ServicePort(name string) (string, bool) {
	number, ok := wellKnownServicePorts[strings.ToLower(name)]

	return number, ok
}

// parsePortNumber parses one port: a number, or a known service name.
func parsePortNumber(s string) (int, bool) {
	s = strings.TrimSpace(s)
	if number, ok := ServicePort(s); ok {
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

// PortSet is the set of ports a rule endpoint matches once its port alias,
// nested aliases included, is expanded.
type PortSet struct {
	ranges []portRange
}

// EndpointPorts resolves an endpoint's port through NamedObjects and parses
// the result. The second return is false when the set cannot be known: the
// port names an alias that does not resolve (unknown, dynamic, cyclic or too
// large), or a value is not a port, a range or a known service name. Callers
// must not read an unknown set as matching nothing.
func EndpointPorts(ep common.RuleEndpoint, no common.NamedObjects) (PortSet, bool) {
	vals, blocked := resolvePortValues(ep, no)
	if blocked {
		return PortSet{}, false
	}

	// parsePortMembers leaves the intervals empty for the any-port wildcard,
	// so ContainsAny reads it as naming no port in particular.
	ranges, _, ok := parsePortMembers(vals)
	if !ok {
		return PortSet{}, false
	}

	return PortSet{ranges: ranges}, true
}

// ContainsAny reports whether the set names any of ports explicitly. The
// any-port wildcard does not count: callers looking for a rule aimed at a
// service read a rule open to every port separately, if at all.
func (s PortSet) ContainsAny(ports ...int) bool {
	for _, r := range s.ranges {
		for _, port := range ports {
			if r.lo <= port && port <= r.hi {
				return true
			}
		}
	}

	return false
}
