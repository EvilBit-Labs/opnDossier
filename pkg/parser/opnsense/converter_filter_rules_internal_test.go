package opnsense

import (
	"strings"
	"testing"

	schema "github.com/EvilBit-Labs/opnDossier/pkg/schema/opnsense"
	"github.com/stretchr/testify/assert"
)

// TestVendorTables pins the two tables against the values OPNsense 26.7.5
// holds: the service names of PortField.php, and the ICMPv6 types of the filter
// model with the names list_legacy_rules.php gives them.
func TestVendorTables(t *testing.T) {
	t.Parallel()

	const services = `afs3-fileserver 7000 aol 5190 auth 113 avt-profile-1 5004 cvsup 5999 domain 53
		domain-s 853 ftp 21 hbci 3000 http 80 https 443 igmpv3lite 465 imap 143 imaps 993
		ipsec-msft 10000 ipsec-nat-t 4500 isakmp 500 l2f 1701 ldap 389 ldaps 636 microsoft-ds 445
		ms-streaming 1755 ms-wbt-server 3389 msnp 1863 nat-stun-port 3478 netbios-dgm 138
		netbios-ns 137 netbios-ssn 139 nntp 119 ntp 123 openvpn 1194 pop3 110 pop3s 995 pptp 1723
		radius 1812 radius-acct 1813 rfb 5900 sip 5060 sip-tls 5061 smtp 25 snmp 161 snmptrap 162
		ssh 22 submission 587 submissions 465 telnet 23 teredo 3544 tftp 69 urd 465 wins 1512`

	const icmp6Types = `1 unreach 2 toobig 3 timex 4 paramprob 128 echoreq 129 echorep 130 listqry
		131 listenrep 132 listendone 133 routersol 134 routeradv 135 neighbrsol 136 neighbradv
		137 redir 138 routrrenum 139 niqry 140 nirep 200 mtraceresp 201 mtrace`

	pairs := func(list string) map[string]string {
		fields := strings.Fields(list)
		table := make(map[string]string, len(fields)/2)

		for i := 0; i < len(fields); i += 2 {
			table[fields[i]] = fields[i+1]
		}

		return table
	}

	assert.Equal(t, pairs(services), wellKnownPorts)
	assert.Equal(t, pairs(icmp6Types), icmp6TypeNames)
}

// TestModelRuleSortKey pins the shape of the key: a number is padded on the
// left and anything else on the right, so numbers line up and compare by value.
// The sequence is kept as stored.
func TestModelRuleSortKey(t *testing.T) {
	t.Parallel()

	key := func(sequence, uuid string) string {
		return modelRuleSortKey(schema.FirewallFilterRule{Sequence: sequence, UUID: uuid})
	}

	assert.Equal(t, "                           100,u", key("100", "u"))
	assert.Equal(t, "                             1,u", key("", "u"), "no sequence is sequence 1")
	assert.Equal(t, "10a                           ,u", key("10a", "u"))
	assert.Equal(t, strings.Repeat(" ", 26)+"100 ,u", key("100 ", "u"), "PHP reads it as a number")
	assert.Equal(t, strings.Repeat(" ", 26)+"+100,u", key("+100", "u"))

	assert.Negative(t, naturalCompareFold(key("9", "z"), key("10", "a")))
	assert.Negative(t, naturalCompareFold(key("10", "z"), key("10a", "a")))
	assert.Negative(t, naturalCompareFold(key("10a", "z"), key("11", "a")))
	assert.Negative(t, naturalCompareFold(key("7", ""), key("7", "a")), "a rule without a uuid sorts first")
}

// TestIsNumericString pins the port of PHP 8's is_numeric against what PHP
// accepts and refuses.
func TestIsNumericString(t *testing.T) {
	t.Parallel()

	for _, s := range []string{
		"0", "100", " 100", "100 ", "\t100\n", "+100", "-5", "1.5", "1.", ".5", "1e3", "1E3", "1e+3", "-1.5e-3",
	} {
		assert.True(t, isNumericString(s), "%q", s)
	}

	for _, s := range []string{
		"", " ", "+", "-", ".", "1e", "e3", "1e3.5", "1.2.3", "10a", "a10", "0x1A", "+ 5", "1 0", "--5", "1e++3",
	} {
		assert.False(t, isNumericString(s), "%q", s)
	}
}
