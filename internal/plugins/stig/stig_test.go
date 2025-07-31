package stig

import (
	"slices"
	"testing"

	"github.com/unclesp1d3r/opnFocus/internal/model"
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

func TestPlugin_hasComprehensiveLogging(t *testing.T) {
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
			name: "config with firewall configured",
			config: &model.OpnSenseDocument{
				OPNsense: model.OPNsense{
					Firewall: &model.Firewall{},
				},
			},
			expected: true,
		},
		{
			name: "config with syslog enabled and firewall rules",
			config: &model.OpnSenseDocument{
				Syslog: model.Syslog{
					Enable: model.BoolFlag(true),
				},
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
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := plugin.hasComprehensiveLogging(tt.config)
			if result != tt.expected {
				t.Errorf("hasComprehensiveLogging() = %v, want %v", result, tt.expected)
			}
		})
	}
}
