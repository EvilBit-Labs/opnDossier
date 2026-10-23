package stig

import (
	"slices"
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/constants"
	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
)

func TestPlugin_hasDefaultDenyPolicy(t *testing.T) {
	plugin := NewPlugin()

	tests := []struct {
		name     string
		config   *common.CommonDevice
		expected bool
	}{
		{
			name:     "empty config - conservative approach",
			config:   &common.CommonDevice{},
			expected: true,
		},
		{
			name: "config with explicit deny rules",
			config: &common.CommonDevice{
				FirewallRules: []common.FirewallRule{
					{
						Type:        common.RuleTypeBlock,
						Source:      common.RuleEndpoint{Address: constants.NetworkAny},
						Destination: common.RuleEndpoint{Address: constants.NetworkAny},
					},
				},
			},
			expected: true,
		},
		{
			name: "config with any/any allow rules",
			config: &common.CommonDevice{
				FirewallRules: []common.FirewallRule{
					{
						Type:        common.RuleTypePass,
						Source:      common.RuleEndpoint{Address: constants.NetworkAny},
						Destination: common.RuleEndpoint{Address: constants.NetworkAny},
					},
				},
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := plugin.hasDefaultDenyPolicy(tt.config)
			if result != tt.expected {
				t.Errorf("hasDefaultDenyPolicy() = %v, want %v", result, tt.expected)
			}
		})
	}
}

//nolint:funlen // test table or data declaration; length is in data not logic
func TestPlugin_hasOverlyPermissiveRules(t *testing.T) {
	plugin := NewPlugin()

	tests := []struct {
		name     string
		config   *common.CommonDevice
		expected bool
	}{
		{
			name:     "empty config",
			config:   &common.CommonDevice{},
			expected: false,
		},
		{
			name: "config with any/any rules",
			config: &common.CommonDevice{
				FirewallRules: []common.FirewallRule{
					{
						Type:        common.RuleTypePass,
						Source:      common.RuleEndpoint{Address: constants.NetworkAny},
						Destination: common.RuleEndpoint{Address: constants.NetworkAny},
					},
				},
			},
			expected: true,
		},
		{
			name: "config with specific rules",
			config: &common.CommonDevice{
				FirewallRules: []common.FirewallRule{
					{
						Type:        common.RuleTypePass,
						Source:      common.RuleEndpoint{Address: "192.168.1.0/24"},
						Destination: common.RuleEndpoint{Address: "10.0.0.0/24", Port: "80"},
					},
				},
			},
			expected: false,
		},
		{
			name: "config with broad network range 10.0.0.0/8 to broad destination",
			config: &common.CommonDevice{
				FirewallRules: []common.FirewallRule{
					{
						Type:        common.RuleTypePass,
						Source:      common.RuleEndpoint{Address: "10.0.0.0/8"},
						Destination: common.RuleEndpoint{Address: "192.168.0.0/16", Port: "443"},
					},
				},
			},
			expected: true,
		},
		{
			name: "config with broad network range 192.168.0.0/16 to any destination",
			config: &common.CommonDevice{
				FirewallRules: []common.FirewallRule{
					{
						Type:        common.RuleTypePass,
						Source:      common.RuleEndpoint{Address: "192.168.0.0/16"},
						Destination: common.RuleEndpoint{Address: "any", Port: "22"},
					},
				},
			},
			expected: true,
		},
		{
			name: "config with broad network range 172.16.0.0/12 to empty destination",
			config: &common.CommonDevice{
				FirewallRules: []common.FirewallRule{
					{
						Type:        common.RuleTypePass,
						Source:      common.RuleEndpoint{Address: "172.16.0.0/12"},
						Destination: common.RuleEndpoint{Address: "", Port: "80"},
					},
				},
			},
			expected: true,
		},
		{
			name: "config with no port restrictions but narrow src/dst (not flagged)",
			config: &common.CommonDevice{
				FirewallRules: []common.FirewallRule{
					{
						Type:        common.RuleTypePass,
						Protocol:    "tcp",
						Source:      common.RuleEndpoint{Address: "192.168.1.0/24"},
						Destination: common.RuleEndpoint{Address: "10.0.0.0/24", Port: ""},
					},
				},
			},
			expected: false,
		},
		{
			name: "config with any port but narrow src/dst (not flagged)",
			config: &common.CommonDevice{
				FirewallRules: []common.FirewallRule{
					{
						Type:        common.RuleTypePass,
						Protocol:    "udp",
						Source:      common.RuleEndpoint{Address: "172.16.1.0/24"},
						Destination: common.RuleEndpoint{Address: "192.168.1.0/24", Port: "any"},
					},
				},
			},
			expected: false,
		},
		{
			name: "config with broad network and no port restrictions",
			config: &common.CommonDevice{
				FirewallRules: []common.FirewallRule{
					{
						Type:        common.RuleTypePass,
						Source:      common.RuleEndpoint{Address: "10.0.0.0/8"},
						Destination: common.RuleEndpoint{Address: "192.168.0.0/16", Port: ""},
					},
				},
			},
			expected: true,
		},
		{
			name: "ICMP rule without port is not flagged (non-TCP/UDP)",
			config: &common.CommonDevice{
				FirewallRules: []common.FirewallRule{
					{
						Type:        common.RuleTypePass,
						Protocol:    "icmp",
						Source:      common.RuleEndpoint{Address: "192.168.1.0/24"},
						Destination: common.RuleEndpoint{Address: "10.0.0.0/24", Port: ""},
					},
				},
			},
			expected: false,
		},
		{
			name: "config with broad source and any destination",
			config: &common.CommonDevice{
				FirewallRules: []common.FirewallRule{
					{
						Type:        common.RuleTypePass,
						Source:      common.RuleEndpoint{Address: "10.0.0.0/8"},
						Destination: common.RuleEndpoint{Address: "any", Port: "80"},
					},
				},
			},
			expected: true,
		},
		{
			name: "any/any via Address fields",
			config: &common.CommonDevice{
				FirewallRules: []common.FirewallRule{
					{
						Type:        common.RuleTypePass,
						Source:      common.RuleEndpoint{Address: "any"},
						Destination: common.RuleEndpoint{Address: "any"},
					},
				},
			},
			expected: true,
		},
		{
			name: "broad source with no port restrictions (flagged)",
			config: &common.CommonDevice{
				FirewallRules: []common.FirewallRule{
					{
						Type:        common.RuleTypePass,
						Protocol:    "tcp",
						Source:      common.RuleEndpoint{Address: "10.0.0.0/8"},
						Destination: common.RuleEndpoint{Address: "192.168.0.0/16", Port: ""},
					},
				},
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := plugin.hasOverlyPermissiveRules(tt.config)
			if result != tt.expected {
				t.Errorf("hasOverlyPermissiveRules() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestPlugin_hasUnnecessaryServices(t *testing.T) {
	plugin := NewPlugin()

	tests := []struct {
		name     string
		config   *common.CommonDevice
		expected bool
	}{
		{
			name:     "empty config",
			config:   &common.CommonDevice{},
			expected: false,
		},
		{
			name: "config with SNMP enabled",
			config: &common.CommonDevice{
				SNMP: common.SNMPConfig{
					ROCommunity: "public",
				},
			},
			expected: true,
		},
		{
			name: "config with DNSSEC stripping",
			config: &common.CommonDevice{
				DNS: common.DNSConfig{
					Unbound: common.UnboundConfig{
						Enabled:        true,
						DNSSECStripped: true,
					},
				},
			},
			expected: true,
		},
		{
			name: "config with more than MaxDHCPInterfaces DHCP interfaces",
			config: &common.CommonDevice{
				DHCP: []common.DHCPScope{
					{
						Interface: "lan",
						Enabled:   true,
						Range:     common.DHCPRange{From: "192.168.1.100", To: "192.168.1.200"},
					},
					{Interface: "opt1", Enabled: true, Range: common.DHCPRange{From: "10.0.1.100", To: "10.0.1.200"}},
					{
						Interface: "opt2",
						Enabled:   true,
						Range:     common.DHCPRange{From: "172.16.1.100", To: "172.16.1.200"},
					},
				},
			},
			expected: true,
		},
		{
			name: "config with load balancer services enabled",
			config: &common.CommonDevice{
				LoadBalancer: common.LoadBalancerConfig{
					MonitorTypes: []common.MonitorType{{Name: "http_monitor"}, {Name: "tcp_monitor"}},
				},
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := plugin.hasUnnecessaryServices(tt.config)
			if result != tt.expected {
				t.Errorf("hasUnnecessaryServices() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestBroadNetworks(t *testing.T) {
	t.Parallel()

	expectedRanges := []string{
		"0.0.0.0/0",
		"::/0",
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		constants.NetworkAny,
	}

	if len(broadNetworks) != len(expectedRanges) {
		t.Errorf("broadNetworks has %d entries, want %d", len(broadNetworks), len(expectedRanges))
	}

	for _, expected := range expectedRanges {
		found := slices.Contains(broadNetworks, expected)
		if !found {
			t.Errorf("broadNetworks missing expected range: %s", expected)
		}
	}
}

func TestPlugin_FindingSeverityMatchesControl(t *testing.T) {
	t.Parallel()

	plugin := NewPlugin()

	// Build a device that triggers every STIG finding:
	// - V-206694: any/any pass rule without deny → missing default deny
	// - V-206674: any/any pass rule → overly permissive
	// - V-206690: SNMP community string → unnecessary services
	// - V-206682: no syslog → insufficient logging
	device := &common.CommonDevice{
		FirewallRules: []common.FirewallRule{
			{
				Type:        common.RuleTypePass,
				Source:      common.RuleEndpoint{Address: constants.NetworkAny},
				Destination: common.RuleEndpoint{Address: constants.NetworkAny},
			},
		},
		SNMP: common.SNMPConfig{
			ROCommunity: "public",
		},
	}

	findings, _, err := plugin.RunChecks(device)
	if err != nil {
		t.Fatalf("unexpected RunChecks error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected at least one finding to validate severity invariant")
	}

	// Every emitted finding's severity must match its referenced control.
	for _, finding := range findings {
		if len(finding.References) == 0 {
			t.Fatalf("finding %q has no references", finding.Title)
		}

		control, err := plugin.GetControlByID(finding.References[0])
		if err != nil {
			t.Fatalf("finding references unknown control %s: %v", finding.References[0], err)
		}

		if finding.Severity != control.Severity {
			t.Errorf("finding %s severity %q does not match control severity %q",
				finding.References[0], finding.Severity, control.Severity)
		}
	}
}

type loggingTestCase struct {
	name     string
	config   *common.CommonDevice
	expected any
}

func getLoggingTestCases() []loggingTestCase {
	return []loggingTestCase{
		{
			name:     "empty config",
			config:   &common.CommonDevice{},
			expected: false,
		},
		{
			name: "config with syslog enabled and system/auth logging",
			config: &common.CommonDevice{
				Syslog: common.SyslogConfig{
					Enabled:       true,
					SystemLogging: true,
					AuthLogging:   true,
				},
			},
			expected: true,
		},
		{
			name: "config with syslog enabled but missing system/auth logging",
			config: &common.CommonDevice{
				Syslog: common.SyslogConfig{
					Enabled:       true,
					SystemLogging: false,
					AuthLogging:   false,
				},
			},
			expected: false,
		},
		{
			name: "config with IDS configured but no syslog",
			config: &common.CommonDevice{
				IDS: &common.IDSConfig{},
			},
			expected: false,
		},
		{
			name: "config with firewall rules but no syslog",
			config: &common.CommonDevice{
				FirewallRules: []common.FirewallRule{
					{
						Type:        common.RuleTypePass,
						Source:      common.RuleEndpoint{Address: "192.168.1.0/24"},
						Destination: common.RuleEndpoint{Address: "10.0.0.0/24", Port: "80"},
					},
				},
			},
			expected: false,
		},
	}
}

func TestPlugin_hasComprehensiveLogging(t *testing.T) {
	plugin := NewPlugin()

	for _, tt := range getLoggingTestCases() {
		t.Run(tt.name, func(t *testing.T) {
			result := plugin.hasComprehensiveLogging(tt.config)
			if result != tt.expected {
				t.Errorf("hasComprehensiveLogging() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestPlugin_analyzeLoggingConfiguration(t *testing.T) {
	plugin := NewPlugin()

	tests := []struct {
		name     string
		config   *common.CommonDevice
		expected LoggingStatus
	}{
		{
			name:     "empty config",
			config:   &common.CommonDevice{},
			expected: LoggingStatusNotConfigured,
		},
		{
			name: "config with syslog enabled and system/auth logging",
			config: &common.CommonDevice{
				Syslog: common.SyslogConfig{
					Enabled:       true,
					SystemLogging: true,
					AuthLogging:   true,
				},
			},
			expected: LoggingStatusComprehensive,
		},
		{
			name: "config with syslog enabled but missing system/auth logging",
			config: &common.CommonDevice{
				Syslog: common.SyslogConfig{
					Enabled:       true,
					SystemLogging: false,
					AuthLogging:   false,
				},
			},
			expected: LoggingStatusPartial,
		},
		{
			name: "config with IDS configured but no syslog",
			config: &common.CommonDevice{
				IDS: &common.IDSConfig{},
			},
			expected: LoggingStatusUnableToDetermine,
		},
		{
			name: "config with firewall rules but no syslog",
			config: &common.CommonDevice{
				FirewallRules: []common.FirewallRule{
					{
						Type:        common.RuleTypePass,
						Source:      common.RuleEndpoint{Address: "192.168.1.0/24"},
						Destination: common.RuleEndpoint{Address: "10.0.0.0/24", Port: "80"},
					},
				},
			},
			expected: LoggingStatusUnableToDetermine,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := plugin.analyzeLoggingConfiguration(tt.config)
			if result != tt.expected {
				t.Errorf("analyzeLoggingConfiguration() = %v, want %v", result, tt.expected)
			}
		})
	}
}

// TestHasOverlyPermissiveRules_NegatedWildcardIsNotBroad covers the half of the
// broad-network test that inverts. broadNetworks holds the wildcards ("any",
// 0.0.0.0/0, ::/0) alongside genuinely large but bounded ranges, and the two
// invert differently: a negated 0.0.0.0/0 or ::/0 matches nothing and is not
// broad, while a negated bounded range is everything outside it and stays
// broad. Testing membership on the raw address alone reported a rule that
// matches no traffic as overly permissive. Neither firewall inverts any, so a
// negated any stays broad.
func TestHasOverlyPermissiveRules_NegatedWildcardIsNotBroad(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		address string
		negated bool
		want    bool
	}{
		{"any", "any", false, true},
		{"wildcard v4", "0.0.0.0/0", false, true},
		{"wildcard v6", "::/0", false, true},
		{"bounded broad range", "10.0.0.0/8", false, true},

		// Negating a wildcard network yields the empty set.
		{"negated wildcard v4", "0.0.0.0/0", true, false},
		{"negated wildcard v6", "::/0", true, false},

		// Negation on any is ignored, so the rule still matches every host.
		{"negated any", "any", true, true},

		// Negating a bounded range leaves everything outside it, still broad.
		{"negated bounded range", "10.0.0.0/8", true, true},

		// An omitted endpoint counts as any, so its negation is ignored too.
		{"empty address", "", false, true},
		{"negated empty address", "", true, true},

		{"scoped host", "192.168.1.5", false, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			device := &common.CommonDevice{FirewallRules: []common.FirewallRule{{
				Type:        common.RuleTypePass,
				Source:      common.RuleEndpoint{Address: tt.address, Negated: tt.negated},
				Destination: common.RuleEndpoint{Address: tt.address, Negated: tt.negated},
			}}}

			got := (&Plugin{}).hasOverlyPermissiveRules(device)
			if got != tt.want {
				t.Errorf("hasOverlyPermissiveRules(%q, negated=%v) = %v, want %v",
					tt.address, tt.negated, got, tt.want)
			}
		})
	}
}

// TestHasOverlyPermissiveRules_DisabledRuleIsNotPermissive guards the other
// consequence of treating an omitted address as a wildcard: a disabled pass
// rule with no endpoints set now looks maximally permissive rather than unset,
// even though it forwards nothing.
func TestHasOverlyPermissiveRules_DisabledRuleIsNotPermissive(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		disabled bool
		want     bool
	}{
		{"enabled any/any rule is permissive", false, true},
		{"disabled any/any rule forwards nothing", true, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			device := &common.CommonDevice{FirewallRules: []common.FirewallRule{{
				Type:     common.RuleTypePass,
				Disabled: tt.disabled,
			}}}

			if got := (&Plugin{}).hasOverlyPermissiveRules(device); got != tt.want {
				t.Errorf("hasOverlyPermissiveRules(disabled=%v) = %v, want %v", tt.disabled, got, tt.want)
			}
		})
	}
}
