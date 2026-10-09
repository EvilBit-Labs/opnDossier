package pfsense_test

import (
	"context"
	"strings"
	"testing"

	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
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
