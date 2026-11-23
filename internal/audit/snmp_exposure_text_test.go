package audit

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSNMPAgent_ExposureTextFollowsTheCommunity checks the text red mode gives
// a WAN-exposed SNMP agent, in both tones. An agent with a community is told to
// migrate to SNMPv3, and its note names community authentication. An agent
// with none, such as an os-net-snmp agent that answers only SNMPv3 users, gets
// neither, and neither does a legacy agent with <enable> and no community.
func TestSNMPAgent_ExposureTextFollowsTheCommunity(t *testing.T) {
	t.Parallel()

	const legacyEnabledNoCommunity = `
  <snmpd>
    <syslocation>closet</syslocation>
    <syscontact>ops</syscontact>
    <enable/>
  </snmpd>`

	tests := []struct {
		name      string
		topLevel  string
		model     string
		community bool
	}{
		{name: "net-snmp enabled with public", model: snmpNetsnmpPublic, community: true},
		{name: "net-snmp enabled with SNMPv3 users only", model: snmpNetsnmpV3Only},
		{name: "legacy block with enable and no community", topLevel: legacyEnabledNoCommunity},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			device := parseConfig(t, snmpAgentConfig(tc.topLevel, tc.model))
			require.True(t, device.SNMP.IsEnabled())
			assert.Equal(t, tc.community, device.SNMP.ROCommunity != "")

			for _, blackhat := range []bool{false, true} {
				report := newRedReport(device)
				report.addWANExposedServices(serviceExposures(device), blackhat)

				finding, ok := findingByTitlePrefix(report.Findings, "WAN-Exposed Service: SNMP")
				require.True(t, ok, "blackhat=%v: no SNMP exposure", blackhat)
				require.NotEmpty(t, finding.ExploitNotes, "blackhat=%v", blackhat)

				assert.Equal(t, tc.community, strings.Contains(finding.Recommendation, "SNMPv3"),
					"blackhat=%v recommendation: %q", blackhat, finding.Recommendation)
				assert.Equal(t, tc.community, strings.Contains(strings.ToLower(finding.ExploitNotes), "community"),
					"blackhat=%v note: %q", blackhat, finding.ExploitNotes)
			}
		})
	}
}
