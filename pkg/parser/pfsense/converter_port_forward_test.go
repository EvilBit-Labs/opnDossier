package pfsense_test

import (
	"context"
	"strings"
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/cfgparser"
	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
	"github.com/EvilBit-Labs/opnDossier/pkg/parser/opnsense"
	"github.com/EvilBit-Labs/opnDossier/pkg/parser/pfsense"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestParser_ConfigPfSense_CompanionRulesKeepTheirLink covers the pass rules
// the fixture's two port forwards store under <filter>. Each carries the same
// <associated-rule-id> as its forward. The schema bound the element and the
// converter did not carry it over.
func TestParser_ConfigPfSense_CompanionRulesKeepTheirLink(t *testing.T) {
	t.Parallel()

	device, _ := parseConfigPfSenseFixture(t)
	require.Len(t, device.NAT.InboundRules, 2)

	linked := make(map[string]string)
	for _, rule := range device.FirewallRules {
		if rule.AssociatedRuleID != "" {
			linked[rule.AssociatedRuleID] = rule.Description
		}
	}

	assert.Equal(t, map[string]string{
		"nat_5e7bb3b731ebf3.20248323": "NAT HTTP to webserver",
		"nat_5e7bb3f7a503d5.68828728": "NAT HTTPS to webserver",
	}, linked)

	for _, forward := range device.NAT.InboundRules {
		assert.Contains(t, linked, forward.AssociatedRuleID, forward.Description)
	}
}

// parsePfSensePortForward parses a config whose <nat> holds one port forward
// with the given body and returns it with the warnings raised about it.
func parsePfSensePortForward(t *testing.T, ruleBody string) (common.InboundNATRule, []common.ConversionWarning) {
	t.Helper()

	const configTemplate = `<?xml version="1.0"?>
<pfsense>
  <system>
    <hostname>fw</hostname>
    <domain>example.com</domain>
  </system>
  <nat><rule><interface>wan</interface><protocol>tcp</protocol>%s</rule></nat>
</pfsense>`

	device, warnings, err := pfsense.NewParser(nil).Parse(
		context.Background(),
		strings.NewReader(strings.Replace(configTemplate, "%s", ruleBody, 1)),
	)
	require.NoError(t, err)
	require.NotNil(t, device)
	require.Len(t, device.NAT.InboundRules, 1)

	var natWarnings []common.ConversionWarning
	for _, w := range warnings {
		if strings.HasPrefix(w.Field, "NAT.InboundRules") {
			natWarnings = append(natWarnings, w)
		}
	}

	return device.NAT.InboundRules[0], natWarnings
}

// TestConverter_PortForwards_NoRDRHasNoTarget covers the rule that exempts
// traffic from redirection. pfSense writes no target for it, so a missing one
// is not a defect.
func TestConverter_PortForwards_NoRDRHasNoTarget(t *testing.T) {
	t.Parallel()

	const match = `<source><any></any></source><destination><network>wanip</network><port>443</port></destination>`

	rule, warnings := parsePfSensePortForward(t, match+`<nordr></nordr>`)
	assert.True(t, rule.NoRDR)
	assert.Empty(t, warnings)

	rule, warnings = parsePfSensePortForward(t, match)
	assert.False(t, rule.NoRDR)
	require.Len(t, warnings, 1)
	assert.Equal(t, "NAT.InboundRules[0].InternalIP", warnings[0].Field)
	assert.Equal(t, common.SeverityHigh, warnings[0].Severity)
}

// TestConverter_PortForwards_RedirectAddress covers which element supplies the
// redirect address. pfSense writes <target>; <internalip> is read for XML this
// tool marshalled before the schema bound <target>.
func TestConverter_PortForwards_RedirectAddress(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		body string
		want string
	}{
		{name: "target", body: `<target>192.168.1.50</target>`, want: "192.168.1.50"},
		{name: "internalip alone", body: `<internalip>192.168.1.60</internalip>`, want: "192.168.1.60"},
		{
			name: "target wins over internalip",
			body: `<target>192.168.1.50</target><internalip>192.168.1.60</internalip>`,
			want: "192.168.1.50",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			rule, warnings := parsePfSensePortForward(t, tt.body)
			assert.Equal(t, tt.want, rule.InternalIP)
			assert.Empty(t, warnings)
		})
	}
}

// TestConverter_PortForwards_KeepNegation covers <not> on a port forward's
// source and destination, which firewall rules kept and port forwards dropped.
func TestConverter_PortForwards_KeepNegation(t *testing.T) {
	t.Parallel()

	const target = `<target>192.168.1.50</target><local-port>8443</local-port>`

	rule, _ := parsePfSensePortForward(t, target+
		`<source><network>lan</network><not></not></source><destination><network>wanip</network><port>443</port></destination>`)
	assert.True(t, rule.Source.Negated)
	assert.False(t, rule.Destination.Negated)

	rule, _ = parsePfSensePortForward(t, target+
		`<source><any></any></source><destination><network>wanip</network><port>443</port><not></not></destination>`)
	assert.False(t, rule.Source.Negated)
	assert.True(t, rule.Destination.Negated)
}

// TestConverter_PortForwards_EmptyEndpointIsAny covers an endpoint with no
// address. A port forward with no source matches every source, and the OPNsense
// converter already reports that as "any"; the pfSense converter left it empty,
// so the same rule exported differently per vendor and the diff rendered the
// pfSense side as "unknown".
func TestConverter_PortForwards_EmptyEndpointIsAny(t *testing.T) {
	t.Parallel()

	const target = `<target>192.168.1.50</target>`
	const anySource = `<source><any></any></source>`
	const wanDest = `<destination><network>wanip</network><port>443</port></destination>`

	tests := []struct {
		name        string
		body        string
		wantSrc     string
		wantDst     string
		wantSrcPort string
		wantDstPort string
		wantNegated bool
	}{
		{name: "omitted source", body: target + wanDest, wantSrc: "any", wantDst: "wanip", wantDstPort: "443"},
		{
			name:        "empty source",
			body:        target + `<source></source>` + wanDest,
			wantSrc:     "any",
			wantDst:     "wanip",
			wantDstPort: "443",
		},
		{
			name:        "explicit any source",
			body:        target + anySource + wanDest,
			wantSrc:     "any",
			wantDst:     "wanip",
			wantDstPort: "443",
		},
		{
			name:    "literal source network is kept",
			body:    target + `<source><network>192.0.2.0/24</network></source>` + wanDest,
			wantSrc: "192.0.2.0/24", wantDst: "wanip", wantDstPort: "443",
		},
		{name: "omitted destination", body: target + anySource, wantSrc: "any", wantDst: "any"},
		{
			name:    "empty destination",
			body:    target + anySource + `<destination></destination>`,
			wantSrc: "any",
			wantDst: "any",
		},
		{
			name:        "empty destination keeps its port",
			body:        target + anySource + `<destination><port>8080</port></destination>`,
			wantSrc:     "any",
			wantDst:     "any",
			wantDstPort: "8080",
		},
		{
			name:        "negated empty source",
			body:        target + `<source><not></not></source>` + wanDest,
			wantSrc:     "any",
			wantDst:     "wanip",
			wantDstPort: "443",
			wantNegated: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			rule, warnings := parsePfSensePortForward(t, tt.body)
			assert.Empty(t, warnings)
			assert.Equal(t, tt.wantSrc, rule.Source.Address)
			assert.Equal(t, tt.wantSrcPort, rule.Source.Port)
			assert.Equal(t, tt.wantNegated, rule.Source.Negated)
			assert.Nil(t, rule.Source.AddressRef, "an empty or literal endpoint names no alias")
			assert.Equal(t, tt.wantDst, rule.Destination.Address)
			assert.Equal(t, tt.wantDstPort, rule.Destination.Port)
			assert.Nil(t, rule.Destination.AddressRef)
		})
	}
}

// TestConverter_PortForwards_CrossVendorEndpointsMatch parses one rule body
// under both vendor roots and asserts the endpoints agree. Only Address, Port
// and Negated are compared: AddressRef is a pointer and compares by identity.
func TestConverter_PortForwards_CrossVendorEndpointsMatch(t *testing.T) {
	t.Parallel()

	const target = `<target>192.168.1.50</target>`
	const wanDest = `<destination><network>wanip</network><port>443</port></destination>`

	bodies := map[string]string{
		"omitted source":     target + wanDest,
		"empty source":       target + `<source></source>` + wanDest,
		"any source":         target + `<source><any></any></source>` + wanDest,
		"literal source":     target + `<source><network>192.0.2.0/24</network></source>` + wanDest,
		"empty destination":  target + `<source><any></any></source><destination></destination>`,
		"negated any source": target + `<source><any></any><not></not></source>` + wanDest,
	}

	for name, body := range bodies {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			pf, _ := parsePfSensePortForward(t, body)
			opn := parseOPNsensePortForward(t, body)

			assertEndpointsAgree(t, "source", opn.Source, pf.Source)
			assertEndpointsAgree(t, "destination", opn.Destination, pf.Destination)
		})
	}
}

// parseOPNsensePortForward parses the same rule body parsePfSensePortForward
// uses, under an <opnsense> root, through the OPNsense parser's exported entry
// point.
func parseOPNsensePortForward(t *testing.T, ruleBody string) common.InboundNATRule {
	t.Helper()

	const configTemplate = `<?xml version="1.0"?>
<opnsense>
  <system>
    <hostname>fw</hostname>
    <domain>example.com</domain>
  </system>
  <nat><rule><interface>wan</interface><protocol>tcp</protocol>%s</rule></nat>
</opnsense>`

	device, _, err := opnsense.NewParser(cfgparser.NewXMLParser()).Parse(
		context.Background(),
		strings.NewReader(strings.Replace(configTemplate, "%s", ruleBody, 1)),
	)
	require.NoError(t, err)
	require.NotNil(t, device)
	require.Len(t, device.NAT.InboundRules, 1)

	return device.NAT.InboundRules[0]
}

// assertEndpointsAgree compares the vendor-independent fields of two endpoints.
func assertEndpointsAgree(t *testing.T, side string, want, got common.RuleEndpoint) {
	t.Helper()

	assert.Equal(t, want.Address, got.Address, "%s address", side)
	assert.Equal(t, want.Port, got.Port, "%s port", side)
	assert.Equal(t, want.Negated, got.Negated, "%s negation", side)
}
