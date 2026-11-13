package analysis_test

import (
	"strings"
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/analysis"
	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
	"github.com/stretchr/testify/assert"
)

// uplinkDevice holds an inside interface, a static second uplink on opt1 that
// selects its gateway, and a group per question asked of it. The interesting
// member of each group is listed second.
func uplinkDevice() *common.CommonDevice {
	return &common.CommonDevice{
		Interfaces: []common.Interface{
			{Name: "wan", Enabled: true, IPAddress: "dhcp"},
			{Name: "lan", Enabled: true, IPAddress: "192.168.1.1"},
			{Name: "opt1", Enabled: true, IPAddress: "198.51.100.2", Gateway: "ISP2_GW"},
			{Name: "opt2", Enabled: true, IPAddress: "10.0.2.1"},
			{Name: "UPLINKS", Enabled: true, Type: "group", Virtual: true},
		},
		InterfaceGroups: []common.InterfaceGroup{
			{Name: "UPLINKS", Members: []string{"lan", "opt1"}},
			{Name: "INSIDE", Members: []string{"lan", "opt2"}},
			{Name: "wanside", Members: []string{"lan", "opt2"}},
		},
		Routing: common.Routing{
			Gateways: []common.Gateway{
				{Name: "ISP2_GW", Interface: "opt1", Address: "198.51.100.1"},
				{Name: "CORE_GW", Interface: "opt2", Address: "10.0.2.254", DefaultGW: "0"},
			},
		},
	}
}

func TestIsWANInterface_UplinkSignals(t *testing.T) {
	t.Parallel()

	device := uplinkDevice()

	tests := []struct {
		name string
		want bool
	}{
		{"wan", true},
		{"opt1", true},
		{"lan", false},
		{"opt2", false},
		{"UPLINKS", true},
		{"INSIDE", false},
		// A listed group is decided by its members, not its name.
		{"wanside", false},
		// A name nothing defines keeps the key test.
		{"wan2", true},
		{"opt9", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, tt.want, analysis.IsWANInterface(device, tt.name))
		})
	}
}

func TestInterfaceReachability_UplinkSignals(t *testing.T) {
	t.Parallel()

	device := uplinkDevice()
	device.Routing.Gateways = append(device.Routing.Gateways,
		common.Gateway{Name: "ISP3_GW", Interface: "opt3", Address: "203.0.113.1", DefaultGW: "1"},
		common.Gateway{Name: "ISP4_GW", Interface: "opt4", Address: "203.0.113.9", DefaultGW: "1", Disabled: true},
	)

	tests := []struct {
		name  string
		iface common.Interface
		want  analysis.Reachability
	}{
		{"selects a gateway", common.Interface{Name: "opt1", Enabled: true, Gateway: "ISP2_GW"}, analysis.WANReachable},
		{
			"selects an IPv6 gateway",
			common.Interface{Name: "opt5", Enabled: true, GatewayV6: "ISP2_GWv6"},
			analysis.WANReachable,
		},
		{
			"gateway selection disabled",
			common.Interface{Name: "opt5", Enabled: true, Gateway: "none"},
			analysis.LANOnly,
		},
		{
			"carries the default gateway",
			common.Interface{Name: "opt3", Enabled: true, IPAddress: "203.0.113.2"},
			analysis.WANReachable,
		},
		{
			"default gateway disabled",
			common.Interface{Name: "opt4", Enabled: true, IPAddress: "203.0.113.10"},
			analysis.LANOnly,
		},
		{
			"gateway that is not the default",
			common.Interface{Name: "opt2", Enabled: true, IPAddress: "10.0.2.1"},
			analysis.LANOnly,
		},
		{"pppoe", common.Interface{Name: "opt5", Enabled: true, IPAddress: "pppoe"}, analysis.WANReachable},
		{"dhcp", common.Interface{Name: "opt5", Enabled: true, IPAddress: "dhcp"}, analysis.WANReachable},
		{"slaac", common.Interface{Name: "opt5", Enabled: true, IPv6Address: "slaac"}, analysis.WANReachable},
		{"track6", common.Interface{Name: "opt5", Enabled: true, IPv6Address: "track6"}, analysis.LANOnly},
		{"disabled uplink", common.Interface{Name: "opt1", Gateway: "ISP2_GW"}, analysis.Local},
		// The entry OPNsense writes for a group under <interfaces> is not an
		// uplink of its own, so interface-level controls do not read it.
		{
			"group entry",
			common.Interface{Name: "UPLINKS", Enabled: true, Type: "group", Virtual: true},
			analysis.LANOnly,
		},
		{
			"wan-prefixed group entry",
			common.Interface{Name: "WAN_ALL", Enabled: true, Type: "group", Virtual: true},
			analysis.LANOnly,
		},
		{
			"left selecting a gateway that is on another interface",
			common.Interface{Name: "opt5", Enabled: true, IPAddress: "10.0.5.1", Gateway: "ISP2_GW"},
			analysis.LANOnly,
		},
		{
			"selects a gateway the config does not define",
			common.Interface{Name: "opt5", Enabled: true, IPAddress: "10.0.5.1", Gateway: "OPT5_DHCP"},
			analysis.WANReachable,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, tt.want, analysis.InterfaceReachability(tt.iface, device))
		})
	}
}

func TestDetectUnusedInterfaces_GroupRuleUsesMembers(t *testing.T) {
	t.Parallel()

	device := uplinkDevice()
	device.FirewallRules = []common.FirewallRule{
		{Type: common.RuleTypePass, Interfaces: []string{"UPLINKS"}},
	}

	unused := make([]string, 0, len(device.Interfaces))
	for _, finding := range analysis.DetectUnusedInterfaces(device) {
		unused = append(unused, finding.InterfaceName)
	}

	assert.NotContains(t, unused, "lan")
	assert.NotContains(t, unused, "opt1")
	assert.NotContains(t, unused, "UPLINKS")
	assert.Contains(t, unused, "opt2")
}

// TestRuleReachability_FloatingRuleOnSecondUplinkOnly covers the unscoped
// floating path on a device whose only uplink is an optN interface, so the
// "wan" key cannot decide it.
func TestRuleReachability_FloatingRuleOnSecondUplinkOnly(t *testing.T) {
	t.Parallel()

	floating := common.FirewallRule{Type: common.RuleTypePass, Floating: true}

	for _, tt := range []struct {
		name string
		opt1 common.Interface
		want analysis.Reachability
	}{
		{
			"opt1 selects its gateway",
			common.Interface{Name: "opt1", Enabled: true, IPAddress: "198.51.100.2", Gateway: "ISP2_GW"},
			analysis.WANReachable,
		},
		{"opt1 is static", common.Interface{Name: "opt1", Enabled: true, IPAddress: "10.0.1.1"}, analysis.LANOnly},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			device := &common.CommonDevice{
				Interfaces: []common.Interface{{Name: "lan", Enabled: true, IPAddress: "192.168.1.1"}, tt.opt1},
				Routing: common.Routing{
					Gateways: []common.Gateway{{Name: "ISP2_GW", Interface: "opt1", Address: "198.51.100.1"}},
				},
			}

			assert.Equal(t, tt.want, analysis.RuleReachability(floating, device))
		})
	}
}

// TestComputeStatistics_SecondUplinkBlockingFlags covers the security
// features list, which reports Block Private and Block Bogon networks when an
// uplink has them. The only uplink here is opt1.
func TestComputeStatistics_SecondUplinkBlockingFlags(t *testing.T) {
	t.Parallel()

	device := &common.CommonDevice{
		Interfaces: []common.Interface{
			{Name: "lan", Enabled: true, IPAddress: "192.168.1.1"},
			{Name: "opt1", Enabled: true, IPAddress: "pppoe", BlockPrivate: true, BlockBogons: true},
		},
	}

	features := analysis.ComputeStatistics(device).SecurityFeatures
	assert.Contains(t, features, "Block Private Networks")
	assert.Contains(t, features, "Block Bogon Networks")
}

// groupDevice holds a pass-any rule above a block of SSH from 10.0.0.0/8,
// both on group G, whose members are given. The block is narrower than a
// block-all, so it is reported as shadowed rather than taken for the default
// deny.
func groupDevice(members ...string) *common.CommonDevice {
	anyEndpoint := common.RuleEndpoint{Address: "any"}

	return &common.CommonDevice{
		Interfaces: []common.Interface{
			{Name: "wan", Enabled: true, IPAddress: "dhcp"},
			{Name: "lan", Enabled: true, IPAddress: "192.168.1.1"},
			{Name: "opt2", Enabled: true, IPAddress: "10.0.2.1"},
			{Name: "G", Enabled: true, Type: "group", Virtual: true},
		},
		InterfaceGroups: []common.InterfaceGroup{{Name: "G", Members: members}},
		FirewallRules: []common.FirewallRule{
			{
				Type:        common.RuleTypePass,
				Interfaces:  []string{"G"},
				Source:      anyEndpoint,
				Destination: anyEndpoint,
				Quick:       true,
			},
			{
				Type:        common.RuleTypeBlock,
				Interfaces:  []string{"G"},
				Source:      common.RuleEndpoint{Address: "10.0.0.0/8"},
				Destination: common.RuleEndpoint{Address: "any", Port: "22"},
				Quick:       true,
			},
		},
	}
}

// TestGroupRules_ShadowSeverityAndObservation covers the consumers that tag a
// finding with the rule's reachability: a shadowed deny is critical on the WAN
// and high elsewhere, and the any-to-any observation carries the reachability.
func TestGroupRules_ShadowSeverityAndObservation(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		members      []string
		wantSeverity common.Severity
		wantReach    analysis.Reachability
	}{
		{[]string{"lan", "wan"}, common.SeverityCritical, analysis.WANReachable},
		{[]string{"lan", "opt2"}, common.SeverityHigh, analysis.LANOnly},
	} {
		t.Run(strings.Join(tt.members, ","), func(t *testing.T) {
			t.Parallel()

			device := groupDevice(tt.members...)

			shadows := analysis.DetectShadowedRules(device)
			if assert.Len(t, shadows, 1) {
				assert.Equal(t, tt.wantSeverity, shadows[0].Severity)
			}

			var reach []analysis.Reachability

			for _, obs := range analysis.ScanObservations(device) {
				if obs.Title == "Any-to-Any Pass Rule" {
					reach = append(reach, obs.Reachability)
				}
			}

			assert.Equal(t, []analysis.Reachability{tt.wantReach}, reach)
		})
	}
}

// TestDetectUnusedInterfaces_SkipsGroupEntries covers the entry OPNsense
// writes under <interfaces> for each group: it is not an interface anyone
// could disable, so it is never reported unused, even with no rule on it.
func TestDetectUnusedInterfaces_SkipsGroupEntries(t *testing.T) {
	t.Parallel()

	device := uplinkDevice()

	for _, finding := range analysis.DetectUnusedInterfaces(device) {
		assert.NotEqual(t, "UPLINKS", finding.InterfaceName)
	}
}
