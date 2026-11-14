package analysis

import (
	"strings"
	"testing"

	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
	"github.com/stretchr/testify/assert"
)

// TestServicePortTable pins the table against the service names of
// PortField.php in OPNsense 26.7.5, the same list pkg/parser/opnsense pins for
// its own copy, and pins the names FreeBSD's /etc/services lacks.
func TestServicePortTable(t *testing.T) {
	t.Parallel()

	const services = `afs3-fileserver 7000 aol 5190 auth 113 avt-profile-1 5004 cvsup 5999 domain 53
		domain-s 853 ftp 21 hbci 3000 http 80 https 443 igmpv3lite 465 imap 143 imaps 993
		ipsec-msft 10000 ipsec-nat-t 4500 isakmp 500 l2f 1701 ldap 389 ldaps 636 microsoft-ds 445
		ms-streaming 1755 ms-wbt-server 3389 msnp 1863 nat-stun-port 3478 netbios-dgm 138
		netbios-ns 137 netbios-ssn 139 nntp 119 ntp 123 openvpn 1194 pop3 110 pop3s 995 pptp 1723
		radius 1812 radius-acct 1813 rfb 5900 sip 5060 sip-tls 5061 smtp 25 snmp 161 snmptrap 162
		ssh 22 submission 587 submissions 465 telnet 23 teredo 3544 tftp 69 urd 465 wins 1512`

	const missingFromServices = `aol avt-profile-1 hbci ipsec-msft ms-streaming msnp nat-stun-port
		radius-acct rfb teredo wins`

	fields := strings.Fields(services)
	table := make(map[string]string, len(fields)/2)

	for i := 0; i < len(fields); i += 2 {
		table[fields[i]] = fields[i+1]
	}

	missing := make(map[string]struct{})
	for name := range strings.FieldsSeq(missingFromServices) {
		missing[name] = struct{}{}
	}

	assert.Equal(t, table, wellKnownServicePorts)
	assert.Equal(t, missing, notInServices)
}

// TestParsePortPart_VendorForms covers the forms a rule port and a port alias
// member take: the colon range only an alias can hold, the dash range of a
// rule port, service names and ranges of two.
func TestParsePortPart_VendorForms(t *testing.T) {
	t.Parallel()

	tests := []struct {
		part   string
		vocab  portVocab
		want   portRange
		wantOK bool
	}{
		{part: "8050", want: portRange{lo: 8050, hi: 8050}, wantOK: true},
		{part: "8000:8100", want: portRange{lo: 8000, hi: 8100}, wantOK: true},
		{part: "8000-8100", want: portRange{lo: 8000, hi: 8100}, wantOK: true},
		{part: " 8000 : 8100 ", want: portRange{lo: 8000, hi: 8100}, wantOK: true},
		{part: "https", want: portRange{lo: 443, hi: 443}, wantOK: true},
		{part: "netbios-ns", want: portRange{lo: 137, hi: 137}, wantOK: true},
		{part: "ms-wbt-server", want: portRange{lo: 3389, hi: 3389}, wantOK: true},
		{part: "http:https", want: portRange{lo: 80, hi: 443}, wantOK: true},
		{part: "http-https", want: portRange{lo: 80, hi: 443}, wantOK: true},
		{part: "netbios-ns-netbios-ssn", want: portRange{lo: 137, hi: 139}, wantOK: true},
		{part: "netbios-ns:netbios-ssn", want: portRange{lo: 137, hi: 139}, wantOK: true},
		{part: "ssh-25", want: portRange{lo: 22, hi: 25}, wantOK: true},
		{part: "rfb", want: portRange{lo: 5900, hi: 5900}, wantOK: true},
		{part: "rfb", vocab: aliasVocab, wantOK: false},
		{part: "telnet", vocab: aliasVocab, want: portRange{lo: 23, hi: 23}, wantOK: true},
		{part: "netbios-ns", vocab: aliasVocab, want: portRange{lo: 137, hi: 137}, wantOK: true},
		{part: "netbios-ns:netbios-ssn", vocab: aliasVocab, want: portRange{lo: 137, hi: 139}, wantOK: true},
		{part: "8000-8100", vocab: aliasVocab, wantOK: false},
		{part: "http-https", vocab: aliasVocab, wantOK: false},
		{part: "HTTPS", wantOK: false},
		{part: "TELNET", vocab: aliasVocab, wantOK: false},
		{part: "100:http", wantOK: false},
		{part: "8100:8000", wantOK: false},
		{part: "1:2:3", wantOK: false},
		{part: "65536", wantOK: false},
		{part: "+80", wantOK: false},
		{part: "-80", wantOK: false},
		{part: "no-such-service", wantOK: false},
		{part: "MgmtPorts", wantOK: false},
		{part: "", wantOK: false},
	}

	for _, tt := range tests {
		name := tt.part
		if tt.vocab == aliasVocab {
			name += " as alias member"
		}

		t.Run(name, func(t *testing.T) {
			t.Parallel()

			got, ok := parsePortPart(tt.part, tt.vocab)

			assert.Equal(t, tt.wantOK, ok)

			if tt.wantOK {
				assert.Equal(t, tt.want, got)
			}
		})
	}
}

// TestEndpointPorts_PartialSets pins how an alias tree reads: a disabled alias
// at any depth adds no port and leaves the set complete, as the loader skips
// it; a cycle, a non-port alias, a missing alias or a member the analysis
// cannot read leaves the set incomplete but keeps what could be read.
func TestEndpointPorts_PartialSets(t *testing.T) {
	t.Parallel()

	port := func(name string, members ...string) common.NamedObject {
		return common.NamedObject{Name: name, Type: common.NamedObjectTypePort, Members: members}
	}
	disabled := func(obj common.NamedObject) common.NamedObject {
		obj.Disabled = true
		return obj
	}

	objects := common.NamedObjects{
		"Off":       disabled(port("Off", "23")),
		"OuterOff":  port("OuterOff", "443", "Off"),
		"CycleA":    port("CycleA", "23", "CycleB"),
		"CycleB":    port("CycleB", "CycleA"),
		"WithHost":  port("WithHost", "23", "Servers"),
		"Servers":   {Name: "Servers", Type: common.NamedObjectTypeHost, Members: []string{"10.0.0.1"}},
		"Feed":      {Name: "Feed", Type: "urltable_ports", Members: []string{"https://example.org/ports"}},
		"WithFeed":  port("WithFeed", "23", "Feed"),
		"Syslog":    port("Syslog", "23", "syslog"),
		"Empty":     port("Empty"),
		"Upper":     port("Upper", "TELNET"),
		"Telnet":    port("Telnet", "telnet"),
		"FullRange": port("FullRange", "1:65535"),
		"Dashed":    port("Dashed", "20-25"),
		"Listed":    port("Listed", "20,23"),
		"AnyMember": port("AnyMember", "any"),
	}

	ref := func(name string) common.RuleEndpoint {
		return common.RuleEndpoint{Port: name, PortRef: &common.ObjectRef{Name: name}}
	}

	tests := []struct {
		name         string
		ep           common.RuleEndpoint
		wantTelnet   bool
		wantComplete bool
		wantEvery    bool
	}{
		{name: "disabled alias", ep: ref("Off"), wantComplete: true},
		{name: "disabled alias nested", ep: ref("OuterOff"), wantComplete: true},
		{name: "cycle keeps the rest", ep: ref("CycleA"), wantTelnet: true},
		{name: "host alias member keeps the rest", ep: ref("WithHost"), wantTelnet: true},
		{name: "dynamic alias member keeps the rest", ep: ref("WithFeed"), wantTelnet: true},
		{name: "dynamic alias", ep: ref("Feed")},
		{name: "unknown service name keeps the rest", ep: ref("Syslog"), wantTelnet: true},
		{name: "empty alias matches no port", ep: ref("Empty"), wantComplete: true},
		{name: "names are case sensitive", ep: ref("Upper")},
		{name: "service name", ep: ref("Telnet"), wantTelnet: true, wantComplete: true},
		{name: "full range", ep: ref("FullRange"), wantTelnet: true, wantComplete: true, wantEvery: true},
		{name: "missing alias", ep: ref("Nowhere")},
		{name: "literal with no alias", ep: common.RuleEndpoint{Port: "syslog"}},
		{name: "literal range", ep: common.RuleEndpoint{Port: "20-25"}, wantTelnet: true, wantComplete: true},
		{name: "literal list with an unreadable part is not read", ep: common.RuleEndpoint{Port: "23,syslog"}},
		{name: "literal list is not read", ep: common.RuleEndpoint{Port: "23,25"}},
		{name: "dash range member is not loaded", ep: ref("Dashed")},
		{name: "comma list member is not loaded", ep: ref("Listed")},
		{name: "any member is not the wildcard", ep: ref("AnyMember")},
		{name: "any port", ep: common.RuleEndpoint{}, wantComplete: true, wantEvery: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			set := EndpointPorts(tt.ep, objects)

			assert.Equal(t, tt.wantTelnet, set.ContainsAny(23), "names telnet")
			assert.Equal(t, tt.wantComplete, set.Complete(), "complete")
			assert.Equal(t, tt.wantEvery, set.CoversEveryPort(), "covers every port")
		})
	}
}

// TestPortCoverage_PartialSets pins the safe direction: a port set known only
// in part is unknown rather than disjoint, so a Security pair still surfaces as
// the R8 advisory, and what could be read still proves an overlap.
func TestPortCoverage_PartialSets(t *testing.T) {
	t.Parallel()

	objects := common.NamedObjects{
		"Odd":  {Name: "Odd", Type: common.NamedObjectTypePort, Members: []string{"8000:8100", "no-such-service"}},
		"Feed": {Name: "Feed", Type: "urltable_ports", Members: []string{"https://example.org/ports"}},
		"Off": {
			Name: "Off", Type: common.NamedObjectTypePort, Members: []string{"23"}, Disabled: true,
		},
		"Empty": {Name: "Empty", Type: common.NamedObjectTypePort},
	}
	odd := common.RuleEndpoint{Port: "Odd", PortRef: &common.ObjectRef{Name: "Odd"}}
	feed := common.RuleEndpoint{Port: "Feed", PortRef: &common.ObjectRef{Name: "Feed"}}
	off := common.RuleEndpoint{Port: "Off", PortRef: &common.ObjectRef{Name: "Off"}}
	empty := common.RuleEndpoint{Port: "Empty", PortRef: &common.ObjectRef{Name: "Empty"}}

	tests := []struct {
		name      string
		earlier   common.RuleEndpoint
		later     common.RuleEndpoint
		want      Coverage
		wantCause blockCause
	}{
		{
			name:      "readable part covers the later port",
			earlier:   odd,
			later:     common.RuleEndpoint{Port: "8050"},
			want:      CoverFull,
			wantCause: causeValue,
		},
		{
			name:      "readable part misses the later port",
			earlier:   odd,
			later:     common.RuleEndpoint{Port: "9000"},
			want:      CoverNone,
			wantCause: causeValue,
		},
		{
			name:      "a later set known in part is never covered in full",
			earlier:   common.RuleEndpoint{Port: "8000-8100"},
			later:     odd,
			want:      CoverPartial,
			wantCause: causeValue,
		},
		{
			name:      "unresolvable alias",
			earlier:   feed,
			later:     common.RuleEndpoint{Port: "443"},
			want:      CoverNone,
			wantCause: causeAlias,
		},
		{
			name:      "the same unresolvable alias matches itself",
			earlier:   feed,
			later:     feed,
			want:      CoverFull,
			wantCause: causeAlias,
		},
		{
			name:    "identical unreadable literals match",
			earlier: common.RuleEndpoint{Port: "x"},
			later:   common.RuleEndpoint{Port: "x"},
			want:    CoverFull,
		},
		{name: "any port covers a set known in part", earlier: common.RuleEndpoint{}, later: odd, want: CoverFull},
		{
			name:    "a disabled alias is covered by nothing",
			earlier: common.RuleEndpoint{Port: "23"},
			later:   off,
			want:    CoverNone,
		},
		{
			name:    "a disabled alias is not covered by any port",
			earlier: common.RuleEndpoint{},
			later:   off,
			want:    CoverNone,
		},
		{
			name:    "a disabled alias covers nothing",
			earlier: off,
			later:   common.RuleEndpoint{Port: "23"},
			want:    CoverNone,
		},
		{name: "a disabled alias does not cover any port", earlier: off, later: common.RuleEndpoint{}, want: CoverNone},
		{name: "an empty alias is covered by nothing", earlier: common.RuleEndpoint{}, later: empty, want: CoverNone},
		{name: "an empty alias covers nothing", earlier: empty, later: feed, want: CoverNone},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, cause := portCoverage(tt.earlier, tt.later, objects)

			assert.Equal(t, tt.want, got)
			assert.Equal(t, tt.wantCause, cause)
		})
	}
}

// TestCoverage_DisjointDimensionWins pins that only a dimension proven
// disjoint outweighs a blocked one: a pass to an unreadable port over a block
// on another single protocol or another literal host raises no advisory, but
// an address the analysis cannot compare, such as an interface network, a
// negated network, (self) or a hostname, or a combined protocol, proves
// nothing and leaves the advisory standing.
func TestCoverage_DisjointDimensionWins(t *testing.T) {
	t.Parallel()

	objects := common.NamedObjects{
		"Feed":    {Name: "Feed", Type: "urltable_ports", Members: []string{"https://example.org/ports"}},
		"Fetched": {Name: "Fetched", Type: "urltable", Members: []string{"https://example.org/hosts"}},
		"LoopA":   {Name: "LoopA", Type: common.NamedObjectTypePort, Members: []string{"LoopB"}},
		"LoopB":   {Name: "LoopB", Type: common.NamedObjectTypePort, Members: []string{"LoopA"}},
	}
	alias := func(name string) common.RuleEndpoint {
		return common.RuleEndpoint{Port: name, PortRef: &common.ObjectRef{Name: name}}
	}
	withAddress := func(ep common.RuleEndpoint, address string) common.RuleEndpoint {
		ep.Address = address
		return ep
	}
	pass := func(proto string, src, dst common.RuleEndpoint) common.FirewallRule {
		return common.FirewallRule{Type: common.RuleTypePass, Protocol: proto, Source: src, Destination: dst}
	}
	block := func(proto string, src, dst common.RuleEndpoint) common.FirewallRule {
		return common.FirewallRule{Type: common.RuleTypeBlock, Protocol: proto, Source: src, Destination: dst}
	}
	unreadable := common.RuleEndpoint{Address: "10.0.0.1", Port: "no-such-service"}
	host := common.RuleEndpoint{Address: "10.0.0.1", Port: "8050"}
	client := common.RuleEndpoint{Address: "192.168.1.50"}

	tests := []struct {
		name      string
		earlier   common.FirewallRule
		later     common.FirewallRule
		wantCause blockCause
	}{
		{
			name:    "other protocol",
			earlier: pass("tcp", common.RuleEndpoint{}, unreadable),
			later:   block("udp", common.RuleEndpoint{}, host),
		},
		{
			name:    "other literal host",
			earlier: pass("tcp", common.RuleEndpoint{}, unreadable),
			later:   block("tcp", common.RuleEndpoint{}, withAddress(host, "10.0.0.2")),
		},
		{
			name:    "other literal network",
			earlier: pass("tcp", common.RuleEndpoint{Address: "10.0.0.0/8"}, unreadable),
			later:   block("tcp", client, host),
		},
		{
			name: "ports read in full outweigh an unresolvable address",
			earlier: pass("tcp", common.RuleEndpoint{}, common.RuleEndpoint{
				Address: "Fetched", AddressRef: &common.ObjectRef{Name: "Fetched"}, Port: "22",
			}),
			later: block("tcp", common.RuleEndpoint{}, host),
		},
		{
			name:      "same protocol and host",
			earlier:   pass("tcp", common.RuleEndpoint{}, unreadable),
			later:     block("tcp", common.RuleEndpoint{}, host),
			wantCause: causeValue,
		},
		{
			name:      "interface network as the source",
			earlier:   pass("tcp", common.RuleEndpoint{Address: "lan"}, withAddress(alias("Feed"), "10.0.0.1")),
			later:     block("tcp", client, withAddress(host, "10.0.0.1")),
			wantCause: causeAlias,
		},
		{
			name:      "interface network beside a cyclic alias",
			earlier:   pass("tcp", common.RuleEndpoint{Address: "lan"}, withAddress(alias("LoopA"), "10.0.0.1")),
			later:     block("tcp", client, host),
			wantCause: causeAlias,
		},
		{
			name:      "negated network as the source",
			earlier:   pass("tcp", common.RuleEndpoint{Address: "10.0.0.0/8", Negated: true}, unreadable),
			later:     block("tcp", client, host),
			wantCause: causeValue,
		},
		{
			name:      "the firewall itself as the destination",
			earlier:   pass("tcp", common.RuleEndpoint{}, withAddress(unreadable, "(self)")),
			later:     block("tcp", common.RuleEndpoint{}, host),
			wantCause: causeValue,
		},
		{
			name:      "hostname as the destination",
			earlier:   pass("tcp", common.RuleEndpoint{}, withAddress(unreadable, "fw.example.org")),
			later:     block("tcp", common.RuleEndpoint{}, host),
			wantCause: causeValue,
		},
		{
			name:      "combined protocol",
			earlier:   pass("tcp/udp", common.RuleEndpoint{}, unreadable),
			later:     block("tcp", common.RuleEndpoint{}, host),
			wantCause: causeValue,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, cause := coverage(tt.earlier, tt.later, objects)

			assert.Equal(t, CoverNone, got)
			assert.Equal(t, tt.wantCause, cause)
		})
	}
}

// TestDetectShadowedRules_R10ComplementWithUnreadablePart pins that a pass
// from !X never meets a block from X, or from a set inside X, whatever else in
// the pair cannot be read. The unreadable part reaches the advisory scan as
// CoverNone (a port list) or as CoverIndeterminate (an alias with one
// unreadable member), and the complement silences both, with the negation on
// either rule. When the plain side reaches outside X the rules can overlap,
// and the advisory stands.
func TestDetectShadowedRules_R10ComplementWithUnreadablePart(t *testing.T) {
	t.Parallel()

	objects := common.NamedObjects{
		"Ports": {Name: "Ports", Type: common.NamedObjectTypePort, Members: []string{"8000:8100", "no-such-service"}},
		"Geo":   {Name: "Geo", Type: "geoip", Members: []string{"CN"}},
	}
	alias := func(name string) *common.ObjectRef { return &common.ObjectRef{Name: name} }

	tests := []struct {
		name          string
		earlierSource common.RuleEndpoint
		laterSource   common.RuleEndpoint
		earlierPort   common.RuleEndpoint
		want          bool
	}{
		{
			name:          "unreadable port list, pass negated",
			earlierSource: common.RuleEndpoint{Address: "10.0.0.0/8", Negated: true},
			laterSource:   common.RuleEndpoint{Address: "10.0.0.0/8"},
			earlierPort:   common.RuleEndpoint{Port: "8000-8100,syslog"},
		},
		{
			name:          "unreadable port list, block negated",
			earlierSource: common.RuleEndpoint{Address: "10.0.0.0/8"},
			laterSource:   common.RuleEndpoint{Address: "10.0.0.0/8", Negated: true},
			earlierPort:   common.RuleEndpoint{Port: "8000-8100,syslog"},
		},
		{
			name:          "unreadable alias member, pass negated",
			earlierSource: common.RuleEndpoint{Address: "10.0.0.0/8", Negated: true},
			laterSource:   common.RuleEndpoint{Address: "10.0.0.0/8"},
			earlierPort:   common.RuleEndpoint{Port: "Ports", PortRef: alias("Ports")},
		},
		{
			name:          "block from a network inside the negated one",
			earlierSource: common.RuleEndpoint{Address: "10.0.0.0/8", Negated: true},
			laterSource:   common.RuleEndpoint{Address: "10.1.0.0/16"},
			earlierPort:   common.RuleEndpoint{Port: "Ports", PortRef: alias("Ports")},
		},
		{
			name:          "geoip alias and its complement",
			earlierSource: common.RuleEndpoint{Address: "Geo", AddressRef: alias("Geo"), Negated: true},
			laterSource:   common.RuleEndpoint{Address: "Geo", AddressRef: alias("Geo")},
			earlierPort:   common.RuleEndpoint{Port: "8050"},
		},
		{
			name:          "geoip alias and its complement, block negated",
			earlierSource: common.RuleEndpoint{Address: "Geo", AddressRef: alias("Geo")},
			laterSource:   common.RuleEndpoint{Address: "Geo", AddressRef: alias("Geo"), Negated: true},
			earlierPort:   common.RuleEndpoint{Port: "8050"},
		},
		{
			name:          "block from any reaches outside the negated network",
			earlierSource: common.RuleEndpoint{Address: "10.0.0.0/8", Negated: true},
			laterSource:   common.RuleEndpoint{Address: "any"},
			earlierPort:   common.RuleEndpoint{Port: "Ports", PortRef: alias("Ports")},
			want:          true,
		},
		{
			name:          "a negated any proves nothing",
			earlierSource: common.RuleEndpoint{Address: "any", Negated: true},
			laterSource:   common.RuleEndpoint{Address: "10.0.0.0/8"},
			earlierPort:   common.RuleEndpoint{Port: "Ports", PortRef: alias("Ports")},
			want:          true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			earlier := baseShadowRule("wan", common.DirectionIn, common.RuleTypePass)
			earlier.Source = tt.earlierSource
			earlier.Destination = common.RuleEndpoint{
				Address: "192.168.1.10", Port: tt.earlierPort.Port, PortRef: tt.earlierPort.PortRef,
			}

			later := baseShadowRule("wan", common.DirectionIn, common.RuleTypeBlock)
			later.Source = tt.laterSource
			later.Destination = common.RuleEndpoint{Address: "192.168.1.10", Port: "8050"}

			cfg := &common.CommonDevice{
				FirewallRules: []common.FirewallRule{earlier, later},
				NamedObjects:  objects,
			}

			findings := DetectShadowedRules(cfg)
			if !tt.want {
				assert.Empty(t, findings)

				return
			}

			if assert.Len(t, findings, 1) {
				assert.Equal(t, common.ConfidenceLow, findings[0].Confidence)
			}
		})
	}
}

// TestComplementDisjoint pins the two shapes that prove a negated endpoint and
// a plain one share no address, and the vendor shapes that must not: a
// disabled alias loads with no members, an exclusion member takes addresses
// out of an alias, and an interface network, (self), a geoip alias or an alias
// whose content is managed at runtime is not a fixed literal set.
func TestComplementDisjoint(t *testing.T) {
	t.Parallel()

	network := func(name string, members ...string) common.NamedObject {
		return common.NamedObject{Name: name, Type: common.NamedObjectTypeNetwork, Members: members}
	}
	off := network("NetOff", "10.0.0.0/8")
	off.Disabled = true

	objects := common.NamedObjects{
		"NetX":    network("NetX", "10.0.0.0/8"),
		"NetOff":  off,
		"NetExcl": network("NetExcl", "10.0.0.0/8", "!10.1.0.0/16"),
		"Nested":  network("Nested", "NetX"),
		"Empty":   network("Empty"),
		"Hosts":   {Name: "Hosts", Type: common.NamedObjectTypeHost, Members: []string{"10.0.0.1"}},
		"Geo":     {Name: "Geo", Type: common.NamedObjectTypeGeoIP, Members: []string{"CN"}},
		"Ext":     {Name: "Ext", Type: common.NamedObjectTypeExternal, Members: []string{"10.0.0.0/8"}},
	}
	lit := func(address string) common.RuleEndpoint { return common.RuleEndpoint{Address: address} }
	ref := func(name string) common.RuleEndpoint {
		return common.RuleEndpoint{Address: name, AddressRef: &common.ObjectRef{Name: name}}
	}
	not := func(ep common.RuleEndpoint) common.RuleEndpoint {
		ep.Negated = true
		return ep
	}

	tests := []struct {
		name           string
		negated, plain common.RuleEndpoint
		want           bool
	}{
		{name: "same literal network", negated: not(lit("10.0.0.0/8")), plain: lit("10.0.0.0/8"), want: true},
		{name: "plain network inside", negated: not(lit("10.0.0.0/8")), plain: lit("10.1.0.0/16"), want: true},
		{name: "plain host inside", negated: not(lit("10.0.0.0/8")), plain: lit("10.0.0.1"), want: true},
		{name: "plain network reaches outside", negated: not(lit("10.0.0.0/8")), plain: lit("10.0.0.0/7")},
		{name: "plain network holds the negated one", negated: not(lit("10.1.0.0/16")), plain: lit("10.0.0.0/8")},
		{name: "other address family", negated: not(lit("10.0.0.0/8")), plain: lit("fd00::/8")},
		{name: "same alias", negated: not(ref("NetX")), plain: ref("NetX"), want: true},
		{name: "same disabled alias", negated: not(ref("NetOff")), plain: ref("NetOff"), want: true},
		{name: "same alias with an exclusion member", negated: not(ref("NetExcl")), plain: ref("NetExcl"), want: true},
		{name: "same geoip alias", negated: not(ref("Geo")), plain: ref("Geo"), want: true},
		{name: "enabled aliases with literal members", negated: not(ref("Nested")), plain: ref("Hosts"), want: true},
		{name: "disabled negated alias", negated: not(ref("NetOff")), plain: lit("10.0.0.0/8")},
		{name: "exclusion member", negated: not(ref("NetExcl")), plain: lit("10.1.0.0/16")},
		{name: "empty negated alias", negated: not(ref("Empty")), plain: lit("10.0.0.0/8")},
		{name: "negated geoip against a network", negated: not(ref("Geo")), plain: lit("10.0.0.0/8")},
		{name: "network against a negated geoip", negated: not(lit("10.0.0.0/8")), plain: ref("Geo")},
		{name: "runtime alias", negated: not(ref("Ext")), plain: lit("10.0.0.0/8")},
		{name: "interface network", negated: not(lit("lan")), plain: lit("lan")},
		{name: "self", negated: not(lit("(self)")), plain: lit("(self)")},
		{name: "negated any", negated: not(lit("any")), plain: lit("10.0.0.0/8")},
		{name: "both negated", negated: not(lit("10.0.0.0/8")), plain: not(lit("10.0.0.0/8"))},
		{
			name: "a list that also names the alias",
			negated: not(common.RuleEndpoint{
				Address: "NetX,10.1.0.0/16", AddressRef: &common.ObjectRef{Name: "NetX"},
			}),
			plain: ref("NetX"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, tt.want, complementDisjoint(tt.negated, tt.plain, objects), "negated first")
			assert.Equal(t, tt.want, complementDisjoint(tt.plain, tt.negated, objects), "plain first")
		})
	}
}

// TestDetectShadowedRules_DestinationComplementWithUnreadablePort is the
// destination-side twin of the source complement: a pass to !192.168.1.0/24
// never meets a block to a host inside it, whatever its port alias holds, and
// it does meet a block to a host outside it.
func TestDetectShadowedRules_DestinationComplementWithUnreadablePort(t *testing.T) {
	t.Parallel()

	objects := common.NamedObjects{
		"Ports": {Name: "Ports", Type: common.NamedObjectTypePort, Members: []string{"8000:8100", "no-such-service"}},
	}

	for _, tt := range []struct {
		name, blocked string
		want          bool
	}{
		{name: "host inside the negated network", blocked: "192.168.1.10"},
		{name: "host outside the negated network", blocked: "192.168.2.10", want: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			earlier := baseShadowRule("wan", common.DirectionIn, common.RuleTypePass)
			earlier.Destination = common.RuleEndpoint{
				Address: "192.168.1.0/24", Negated: true,
				Port: "Ports", PortRef: &common.ObjectRef{Name: "Ports"},
			}

			later := baseShadowRule("wan", common.DirectionIn, common.RuleTypeBlock)
			later.Destination = common.RuleEndpoint{Address: tt.blocked, Port: "8050"}

			findings := DetectShadowedRules(&common.CommonDevice{
				FirewallRules: []common.FirewallRule{earlier, later},
				NamedObjects:  objects,
			})

			if !tt.want {
				assert.Empty(t, findings)

				return
			}

			if assert.Len(t, findings, 1) {
				assert.Equal(t, common.ConfidenceLow, findings[0].Confidence)
			}
		})
	}
}
