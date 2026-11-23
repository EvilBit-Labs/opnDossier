package firewall_test

import (
	"context"
	"strings"
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/cfgparser"
	"github.com/EvilBit-Labs/opnDossier/internal/plugins/firewall"
	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
	"github.com/EvilBit-Labs/opnDossier/pkg/parser/opnsense"
	"github.com/EvilBit-Labs/opnDossier/pkg/parser/pfsense"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const dnsRebindControl = "FIREWALL-007"

// rebindPrivateAddress is part of the default list Unbound.xml ships, so the
// list is populated in every OPNsense case below: the bug is that it stops
// mattering once rebind checks are disabled.
const rebindPrivateAddress = `<advanced><privateaddress>10.0.0.0/8,192.168.0.0/16</privateaddress></advanced>`

// rebindCheckOff is what System > Settings > Administration writes when
// "Disable DNS Rebinding Checks" is ticked.
const rebindCheckOff = `<nodnsrebindcheck>1</nodnsrebindcheck>`

func opnsenseRebindConfig(webgui, rest string) string {
	return `<?xml version="1.0"?><opnsense><system><webgui><protocol>https</protocol>` + webgui +
		`</webgui></system>` + rest + `</opnsense>`
}

// rebindOutcome is what the firewall plugin did with FIREWALL-007.
type rebindOutcome struct {
	evaluated bool
	finding   bool
}

// rebindStatus parses config with the given parser and reports whether
// FIREWALL-007 was evaluated and whether it produced a finding.
func rebindStatus(
	t *testing.T,
	parse func(context.Context, *strings.Reader) (*common.CommonDevice, []common.ConversionWarning, error),
	config string,
) rebindOutcome {
	t.Helper()

	var got rebindOutcome

	device, _, err := parse(context.Background(), strings.NewReader(config))
	require.NoError(t, err)

	findings, controls, err := firewall.NewPlugin().RunChecks(device)
	require.NoError(t, err)

	for _, f := range findings {
		if f.Reference == dnsRebindControl {
			got.finding = true
		}
	}

	for _, id := range controls {
		if id == dnsRebindControl {
			got.evaluated = true
		}
	}

	return got
}

// TestFirewallPlugin_DNSRebindCheckDisabled_OPNsense drives configs through the
// parser. OPNsense writes no private-address lines for Unbound, and drops
// dnsmasq's stop-dns-rebind, while <system><webgui><nodnsrebindcheck> is set
// (unbound.inc, dnsmasq.conf template), whatever the list holds.
func TestFirewallPlugin_DNSRebindCheckDisabled_OPNsense(t *testing.T) {
	parse := func(ctx context.Context, r *strings.Reader) (*common.CommonDevice, []common.ConversionWarning, error) {
		return opnsense.NewParser(cfgparser.NewXMLParser()).Parse(ctx, r)
	}

	unbound267 := `<OPNsense><unboundplus version="1.0.15"><general><enabled>1</enabled></general>` +
		rebindPrivateAddress + `</unboundplus></OPNsense>`
	unbound231 := `<unbound><enable>1</enable></unbound><OPNsense><unboundplus version="1.0.4">` +
		rebindPrivateAddress + `</unboundplus></OPNsense>`
	dnsmasqOnly := `<dnsmasq><enable>1</enable></dnsmasq>`

	cases := []struct {
		name          string
		config        string
		wantEvaluated bool
		wantFinding   bool
	}{
		{"26.7 Unbound, checks on", opnsenseRebindConfig(``, unbound267), true, false},
		{"26.7 Unbound, checks off", opnsenseRebindConfig(rebindCheckOff, unbound267), true, true},
		{"23.1 Unbound, checks off", opnsenseRebindConfig(rebindCheckOff, unbound231), true, true},
		{"empty element still disables", opnsenseRebindConfig(`<nodnsrebindcheck/>`, unbound267), true, true},
		{"dnsmasq only, checks off", opnsenseRebindConfig(rebindCheckOff, dnsmasqOnly), true, true},
		{"no resolver, checks off", opnsenseRebindConfig(rebindCheckOff, ``), false, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := rebindStatus(t, parse, tc.config)
			assert.Equal(t, rebindOutcome{evaluated: tc.wantEvaluated, finding: tc.wantFinding}, got)
		})
	}
}

// TestFirewallPlugin_DNSRebindCheckDisabled_PfSense covers pfSense, which gates
// Unbound's built-in private-address list and dnsmasq's --stop-dns-rebind on
// the same element with config_path_enabled(), and writes it empty.
func TestFirewallPlugin_DNSRebindCheckDisabled_PfSense(t *testing.T) {
	parse := func(ctx context.Context, r *strings.Reader) (*common.CommonDevice, []common.ConversionWarning, error) {
		return pfsense.NewParser(nil).Parse(ctx, r)
	}
	config := func(webgui string) string {
		return `<?xml version="1.0"?><pfsense><system><webgui><protocol>https</protocol>` + webgui +
			`</webgui></system><unbound><enable></enable></unbound></pfsense>`
	}

	assert.Equal(t, rebindOutcome{evaluated: true, finding: true},
		rebindStatus(t, parse, config(`<nodnsrebindcheck></nodnsrebindcheck>`)))

	// With the checks on, the converter carries no private-address list for
	// pfSense, so the control stays unknown as before.
	assert.Equal(t, rebindOutcome{}, rebindStatus(t, parse, config(``)))
}
