package opnsense

import (
	"strings"
	"testing"

	schema "github.com/EvilBit-Labs/opnDossier/pkg/schema/opnsense"
	"github.com/stretchr/testify/assert"
)

// TestVendorTables pins the ICMPv6 types of the filter model against the names
// OPNsense 26.7.5's list_legacy_rules.php gives them. The service name table
// moved to internal/analysis and is pinned there.
func TestVendorTables(t *testing.T) {
	t.Parallel()

	const icmp6Types = `1 unreach 2 toobig 3 timex 4 paramprob 128 echoreq 129 echorep 130 listqry
		131 listenrep 132 listendone 133 routersol 134 routeradv 135 neighbrsol 136 neighbradv
		137 redir 138 routrrenum 139 niqry 140 nirep 200 mtraceresp 201 mtrace`

	fields := strings.Fields(icmp6Types)
	table := make(map[string]string, len(fields)/2)

	for i := 0; i < len(fields); i += 2 {
		table[fields[i]] = fields[i+1]
	}

	assert.Equal(t, table, icmp6TypeNames)
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
