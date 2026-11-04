package audit

import (
	"slices"
	"strings"
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/compliance"
	"github.com/EvilBit-Labs/opnDossier/internal/plugins/sans"
)

// TestSANS_TCPPortForwardRuleKeepsState covers the state tracking controls on a
// TCP port forward's rule. The pfSense page writes that rule with no <type> and
// no <statetype>, and filter.inc compiles it as pass with keep state, so both
// controls have to pass. The shipped config has only tcp/udp forwards, which the
// controls do not read, so the rewrite is what puts the rule in front of them.
func TestSANS_TCPPortForwardRuleKeepsState(t *testing.T) {
	t.Parallel()

	const protocol = "<protocol>tcp/udp</protocol>"

	raw := readFixture(t, "pfsense/config-pfSense.xml")

	requireFixtureHolds(t, raw, map[string]int{protocol: 7})

	device := parseConfig(t, strings.ReplaceAll(raw, protocol, "<protocol>tcp</protocol>"))

	findings, evaluated, err := sans.NewPlugin().RunChecks(device)
	if err != nil {
		t.Fatal(err)
	}

	for _, control := range []string{"SANS-FW-007", "SANS-FW-024"} {
		if !slices.Contains(evaluated, control) {
			t.Errorf("%s was not evaluated, so the config puts no TCP pass rule in front of it", control)
		}

		if slices.ContainsFunc(findings, func(finding compliance.Finding) bool {
			return finding.Reference == control
		}) {
			t.Errorf("%s fails on a rule filter.inc compiles with keep state", control)
		}
	}
}
