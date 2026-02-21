package stig

import (
	"slices"
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/constants"
	"github.com/EvilBit-Labs/opnDossier/internal/model/common"
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
						Type:        "block",
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
						Type:        "pass",
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
						Type:        "pass",
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
						Type:        "pass",
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
						Type:        "pass",
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
						Type:        "pass",
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
						Type:        "pass",
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
						Type:        "pass",
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
						Type:        "pass",
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
						Type:        "pass",
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
						Type:        "pass",
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
						Type:        "pass",
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
						Type:        "pass",
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
						Type:        "pass",
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

func TestPlugin_broadNetworkRanges(t *testing.T) {
	plugin := NewPlugin()
	ranges := plugin.broadNetworkRanges()

	expectedRanges := []string{
		"0.0.0.0/0",
		"::/0",
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		constants.NetworkAny,
	}

	if len(ranges) != len(expectedRanges) {
		t.Errorf("broadNetworkRanges() returned %d ranges, want %d", len(ranges), len(expectedRanges))
	}

	for _, expected := range expectedRanges {
		found := slices.Contains(ranges, expected)
		if !found {
			t.Errorf("broadNetworkRanges() missing expected range: %s", expected)
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
						Type:        "pass",
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
						Type:        "pass",
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
