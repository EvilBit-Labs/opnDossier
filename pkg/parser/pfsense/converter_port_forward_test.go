package pfsense_test

import (
	"testing"

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
