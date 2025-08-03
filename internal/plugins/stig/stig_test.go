package stig

import (
	"slices"
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/model"
)

func TestPlugin_hasDefaultDenyPolicy(t *testing.T) {
	plugin := NewPlugin()

	tests := []struct {
		name     string
		config   *model.OpnSenseDocument
		expected bool
	}{
		{
			name:     "empty config - conservative approach",
			config:   &model.OpnSenseDocument{},
			expected: true,
		},
		{
			name: "config with explicit deny rules",
			config: &model.OpnSenseDocument{
				Filter: model.Filter{
					Rule: []model.Rule{
						{
							Type: "block",
							Source: model.Source{
								Any: "1",
							},
							Destination: model.Destination{
								Any: "1",
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "config with any/any allow rules",
			config: &model.OpnSenseDocument{
				Filter: model.Filter{
					Rule: []model.Rule{
						{
							Type: "pass",
							Source: model.Source{
								Any: "1",
							},
							Destination: model.Destination{
								Any: "1",
							},
						},
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
		config   *model.OpnSenseDocument
		expected bool
	}{
		{
			name:     "empty config",
			config:   &model.OpnSenseDocument{},
			expected: false,
		},
		{
			name: "config with any/any rules",
			config: &model.OpnSenseDocument{
				Filter: model.Filter{
					Rule: []model.Rule{
						{
							Type: "pass",
							Source: model.Source{
								Any: "1",
							},
							Destination: model.Destination{
								Any: "1",
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "config with specific rules",
			config: &model.OpnSenseDocument{
				Filter: model.Filter{
					Rule: []model.Rule{
						{
							Type: "pass",
							Source: model.Source{
								Network: "192.168.1.0/24",
							},
							Destination: model.Destination{
								Network: "10.0.0.0/24",
								Port:    "80",
							},
						},
					},
				},
			},
			expected: false,
		},
		{
			name: "config with broad network range 10.0.0.0/8 to broad destination",
			config: &model.OpnSenseDocument{
				Filter: model.Filter{
					Rule: []model.Rule{
						{
							Type: "pass",
							Source: model.Source{
								Network: "10.0.0.0/8",
							},
							Destination: model.Destination{
								Network: "192.168.0.0/16",
								Port:    "443",
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "config with broad network range 192.168.0.0/16 to any destination",
			config: &model.OpnSenseDocument{
				Filter: model.Filter{
					Rule: []model.Rule{
						{
							Type: "pass",
							Source: model.Source{
								Network: "192.168.0.0/16",
							},
							Destination: model.Destination{
								Network: "any",
								Port:    "22",
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "config with broad network range 172.16.0.0/12 to empty destination",
			config: &model.OpnSenseDocument{
				Filter: model.Filter{
					Rule: []model.Rule{
						{
							Type: "pass",
							Source: model.Source{
								Network: "172.16.0.0/12",
							},
							Destination: model.Destination{
								Network: "",
								Port:    "80",
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "config with no port restrictions (empty port)",
			config: &model.OpnSenseDocument{
				Filter: model.Filter{
					Rule: []model.Rule{
						{
							Type: "pass",
							Source: model.Source{
								Network: "192.168.1.0/24",
							},
							Destination: model.Destination{
								Network: "10.0.0.0/24",
								Port:    "",
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "config with no port restrictions (any port)",
			config: &model.OpnSenseDocument{
				Filter: model.Filter{
					Rule: []model.Rule{
						{
							Type: "pass",
							Source: model.Source{
								Network: "172.16.1.0/24",
							},
							Destination: model.Destination{
								Network: "192.168.1.0/24",
								Port:    "any",
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "config with broad network and no port restrictions",
			config: &model.OpnSenseDocument{
				Filter: model.Filter{
					Rule: []model.Rule{
						{
							Type: "pass",
							Source: model.Source{
								Network: "10.0.0.0/8",
							},
							Destination: model.Destination{
								Network: "192.168.0.0/16",
								Port:    "",
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "config with broad source and any destination",
			config: &model.OpnSenseDocument{
				Filter: model.Filter{
					Rule: []model.Rule{
						{
							Type: "pass",
							Source: model.Source{
								Network: "10.0.0.0/8",
							},
							Destination: model.Destination{
								Network: "any",
								Port:    "80",
							},
						},
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
		config   *model.OpnSenseDocument
		expected bool
	}{
		{
			name:     "empty config",
			config:   &model.OpnSenseDocument{},
			expected: false,
		},
		{
			name: "config with SNMP enabled",
			config: &model.OpnSenseDocument{
				Snmpd: model.Snmpd{
					ROCommunity: "public",
				},
			},
			expected: true,
		},
		{
			name: "config with DNSSEC stripping",
			config: &model.OpnSenseDocument{
				Unbound: model.Unbound{
					Enable:         "1",
					Dnssecstripped: "1",
				},
			},
			expected: true,
		},
		{
			name: "config with more than MaxDHCPInterfaces DHCP interfaces",
			config: &model.OpnSenseDocument{
				Dhcpd: model.Dhcpd{
					Items: map[string]model.DhcpdInterface{
						"lan": {
							Enable: "1",
							Range: model.Range{
								From: "192.168.1.100",
								To:   "192.168.1.200",
							},
						},
						"opt1": {
							Enable: "1",
							Range: model.Range{
								From: "10.0.1.100",
								To:   "10.0.1.200",
							},
						},
						"opt2": {
							Enable: "1",
							Range: model.Range{
								From: "172.16.1.100",
								To:   "172.16.1.200",
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "config with load balancer services enabled",
			config: &model.OpnSenseDocument{
				LoadBalancer: model.LoadBalancer{
					MonitorType: []model.MonitorType{
						{
							Name:  "http_monitor",
							Type:  "http",
							Descr: "HTTP health check",
							Options: model.Options{
								Path: "/health",
								Code: "200",
							},
						},
						{
							Name:  "tcp_monitor",
							Type:  "tcp",
							Descr: "TCP health check",
							Options: model.Options{
								Host: "example.com",
								Code: "80",
							},
						},
					},
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
		NetworkAny,
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
	config   *model.OpnSenseDocument
	expected any
}

func getLoggingTestCases() []loggingTestCase {
	return []loggingTestCase{
		{
			name:     "empty config",
			config:   &model.OpnSenseDocument{},
			expected: false,
		},
		{
			name: "config with syslog enabled and system/auth logging",
			config: &model.OpnSenseDocument{
				Syslog: model.Syslog{
					Enable: model.BoolFlag(true),
					System: model.BoolFlag(true),
					Auth:   model.BoolFlag(true),
				},
			},
			expected: true,
		},
		{
			name: "config with syslog enabled but missing system/auth logging",
			config: &model.OpnSenseDocument{
				Syslog: model.Syslog{
					Enable: model.BoolFlag(true),
					System: model.BoolFlag(false),
					Auth:   model.BoolFlag(false),
				},
			},
			expected: false,
		},
		{
			name: "config with firewall configured but no syslog",
			config: &model.OpnSenseDocument{
				OPNsense: model.OPNsense{
					Firewall: &model.Firewall{},
				},
			},
			expected: false,
		},
		{
			name: "config with firewall rules but no syslog",
			config: &model.OpnSenseDocument{
				Filter: model.Filter{
					Rule: []model.Rule{
						{
							Type: "pass",
							Source: model.Source{
								Network: "192.168.1.0/24",
							},
							Destination: model.Destination{
								Network: "10.0.0.0/24",
								Port:    "80",
							},
						},
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
		config   *model.OpnSenseDocument
		expected LoggingStatus
	}{
		{
			name:     "empty config",
			config:   &model.OpnSenseDocument{},
			expected: LoggingStatusNotConfigured,
		},
		{
			name: "config with syslog enabled and system/auth logging",
			config: &model.OpnSenseDocument{
				Syslog: model.Syslog{
					Enable: model.BoolFlag(true),
					System: model.BoolFlag(true),
					Auth:   model.BoolFlag(true),
				},
			},
			expected: LoggingStatusComprehensive,
		},
		{
			name: "config with syslog enabled but missing system/auth logging",
			config: &model.OpnSenseDocument{
				Syslog: model.Syslog{
					Enable: model.BoolFlag(true),
					System: model.BoolFlag(false),
					Auth:   model.BoolFlag(false),
				},
			},
			expected: LoggingStatusPartial,
		},
		{
			name: "config with firewall configured but no syslog",
			config: &model.OpnSenseDocument{
				OPNsense: model.OPNsense{
					Firewall: &model.Firewall{},
				},
			},
			expected: LoggingStatusUnableToDetermine,
		},
		{
			name: "config with firewall rules but no syslog",
			config: &model.OpnSenseDocument{
				Filter: model.Filter{
					Rule: []model.Rule{
						{
							Type: "pass",
							Source: model.Source{
								Network: "192.168.1.0/24",
							},
							Destination: model.Destination{
								Network: "10.0.0.0/24",
								Port:    "80",
							},
						},
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
