package analysis

import (
	"strings"
	"testing"

	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
	"github.com/stretchr/testify/assert"
)

// TestServicePortTable pins the table against the service names of
// PortField.php in OPNsense 26.7.5.
func TestServicePortTable(t *testing.T) {
	t.Parallel()

	const services = `afs3-fileserver 7000 aol 5190 auth 113 avt-profile-1 5004 cvsup 5999 domain 53
		domain-s 853 ftp 21 hbci 3000 http 80 https 443 igmpv3lite 465 imap 143 imaps 993
		ipsec-msft 10000 ipsec-nat-t 4500 isakmp 500 l2f 1701 ldap 389 ldaps 636 microsoft-ds 445
		ms-streaming 1755 ms-wbt-server 3389 msnp 1863 nat-stun-port 3478 netbios-dgm 138
		netbios-ns 137 netbios-ssn 139 nntp 119 ntp 123 openvpn 1194 pop3 110 pop3s 995 pptp 1723
		radius 1812 radius-acct 1813 rfb 5900 sip 5060 sip-tls 5061 smtp 25 snmp 161 snmptrap 162
		ssh 22 submission 587 submissions 465 telnet 23 teredo 3544 tftp 69 urd 465 wins 1512`

	fields := strings.Fields(services)
	table := make(map[string]string, len(fields)/2)

	for i := 0; i < len(fields); i += 2 {
		table[fields[i]] = fields[i+1]
	}

	assert.Equal(t, table, wellKnownServicePorts)
}

// TestParsePortPart_VendorForms covers the forms a port alias member and a rule
// port take: the colon range only an alias can hold, service names, and the
// dash range of a rule port.
func TestParsePortPart_VendorForms(t *testing.T) {
	t.Parallel()

	tests := []struct {
		part   string
		want   portRange
		wantOK bool
	}{
		{part: "8050", want: portRange{lo: 8050, hi: 8050}, wantOK: true},
		{part: "8000:8100", want: portRange{lo: 8000, hi: 8100}, wantOK: true},
		{part: "8000-8100", want: portRange{lo: 8000, hi: 8100}, wantOK: true},
		{part: " 8000 : 8100 ", want: portRange{lo: 8000, hi: 8100}, wantOK: true},
		{part: "https", want: portRange{lo: 443, hi: 443}, wantOK: true},
		{part: "HTTPS", want: portRange{lo: 443, hi: 443}, wantOK: true},
		{part: "netbios-ns", want: portRange{lo: 137, hi: 137}, wantOK: true},
		{part: "ms-wbt-server", want: portRange{lo: 3389, hi: 3389}, wantOK: true},
		{part: "http:https", want: portRange{lo: 80, hi: 443}, wantOK: true},
		{part: "netbios-ns:netbios-ssn", want: portRange{lo: 137, hi: 139}, wantOK: true},
		{part: "100:http", wantOK: false},
		{part: "8100:8000", wantOK: false},
		{part: "ssh-25", wantOK: false},
		{part: "1:2:3", wantOK: false},
		{part: "65536", wantOK: false},
		{part: "+80", wantOK: false},
		{part: "-80", wantOK: false},
		{part: "no-such-service", wantOK: false},
		{part: "MgmtPorts", wantOK: false},
		{part: "", wantOK: false},
	}

	for _, tt := range tests {
		t.Run(tt.part, func(t *testing.T) {
			t.Parallel()

			got, ok := parsePortPart(tt.part)

			assert.Equal(t, tt.wantOK, ok)

			if tt.wantOK {
				assert.Equal(t, tt.want, got)
			}
		})
	}
}

// TestPortCoverage_UnknownMemberIsBlocked pins the safe direction: a port
// value that cannot be parsed makes the dimension unknown, not disjoint, so a
// Security pair still surfaces as the R8 advisory. Identical strings stay a
// confident match, and an any-port covering endpoint covers whatever it meets.
func TestPortCoverage_UnknownMemberIsBlocked(t *testing.T) {
	t.Parallel()

	objects := common.NamedObjects{
		"Odd": {Name: "Odd", Type: common.NamedObjectTypePort, Members: []string{"443", "no-such-service"}},
	}
	alias := common.RuleEndpoint{Port: "Odd", PortRef: &common.ObjectRef{Name: "Odd"}}

	tests := []struct {
		name        string
		earlier     common.RuleEndpoint
		later       common.RuleEndpoint
		want        Coverage
		wantBlocked bool
	}{
		{
			name:        "alias with an unknown member over a port",
			earlier:     alias,
			later:       common.RuleEndpoint{Port: "8050"},
			want:        CoverNone,
			wantBlocked: true,
		},
		{
			name:        "port over an alias with an unknown member",
			earlier:     common.RuleEndpoint{Port: "443"},
			later:       alias,
			want:        CoverNone,
			wantBlocked: true,
		},
		{
			name:    "identical unparseable strings still match",
			earlier: common.RuleEndpoint{Port: "Undefined"},
			later:   common.RuleEndpoint{Port: "Undefined"},
			want:    CoverFull,
		},
		{
			name:    "any port covers an alias with an unknown member",
			earlier: common.RuleEndpoint{},
			later:   alias,
			want:    CoverFull,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, blocked := portCoverage(tt.earlier, tt.later, objects)

			assert.Equal(t, tt.want, got)
			assert.Equal(t, tt.wantBlocked, blocked)
		})
	}
}
