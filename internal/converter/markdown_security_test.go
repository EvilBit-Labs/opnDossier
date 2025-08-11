package converter

import (
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/model"
	"github.com/stretchr/testify/assert"
)

func TestMarkdownBuilder_AssessRiskLevel(t *testing.T) {
	b := NewMarkdownBuilder()

	tests := map[string]string{
		"critical":      "🔴 Critical Risk",
		"CRITICAL":      "🔴 Critical Risk",
		" critical ":    "🔴 Critical Risk",
		"high":          "🟠 High Risk",
		"HIGH":          "🟠 High Risk",
		"medium":        "🟡 Medium Risk",
		"MEDIUM":        "🟡 Medium Risk",
		"low":           "🟢 Low Risk",
		"LOW":           "🟢 Low Risk",
		"info":          "ℹ️ Informational",
		"INFO":          "ℹ️ Informational",
		"informational": "ℹ️ Informational",
		"INFORMATIONAL": "ℹ️ Informational",
		"unknown":       "⚪ Unknown Risk",
		"invalid":       "⚪ Unknown Risk",
		"":              "⚪ Unknown Risk",
		"   ":           "⚪ Unknown Risk",
	}

	for input, expected := range tests {
		t.Run(input, func(t *testing.T) {
			actual := b.AssessRiskLevel(input)
			assert.Equal(t, expected, actual, "Risk level for %q should be %q, got %q", input, expected, actual)
		})
	}
}

func TestMarkdownBuilder_AssessServiceRisk(t *testing.T) {
	b := NewMarkdownBuilder()

	tests := []struct {
		name         string
		service      model.Service
		expectedRisk string
	}{
		{
			name:         "Telnet service - critical risk",
			service:      model.Service{Name: "Telnet Server"},
			expectedRisk: "🔴 Critical Risk",
		},
		{
			name:         "Telnet case insensitive",
			service:      model.Service{Name: "TELNET daemon"},
			expectedRisk: "🔴 Critical Risk",
		},
		{
			name:         "FTP service - high risk",
			service:      model.Service{Name: "vsftpd FTP"},
			expectedRisk: "🟠 High Risk",
		},
		{
			name:         "FTP case insensitive",
			service:      model.Service{Name: "FTP Server"},
			expectedRisk: "🟠 High Risk",
		},
		{
			name:         "VNC service - high risk",
			service:      model.Service{Name: "VNC Server"},
			expectedRisk: "🟠 High Risk",
		},
		{
			name:         "RDP service - medium risk",
			service:      model.Service{Name: "RDP listener"},
			expectedRisk: "🟡 Medium Risk",
		},
		{
			name:         "RDP case insensitive",
			service:      model.Service{Name: "rdp service"},
			expectedRisk: "🟡 Medium Risk",
		},
		{
			name:         "SSH service - low risk",
			service:      model.Service{Name: "ssh"},
			expectedRisk: "🟢 Low Risk",
		},
		{
			name:         "SSH case insensitive",
			service:      model.Service{Name: "SSH Daemon"},
			expectedRisk: "🟢 Low Risk",
		},
		{
			name:         "HTTPS service - informational",
			service:      model.Service{Name: "https"},
			expectedRisk: "ℹ️ Informational",
		},
		{
			name:         "HTTPS case insensitive",
			service:      model.Service{Name: "HTTPS Server"},
			expectedRisk: "ℹ️ Informational",
		},
		{
			name:         "Unknown service - informational",
			service:      model.Service{Name: "custom"},
			expectedRisk: "ℹ️ Informational",
		},
		{
			name:         "Empty service name - informational",
			service:      model.Service{Name: ""},
			expectedRisk: "ℹ️ Informational",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := b.AssessServiceRisk(tt.service)
			assert.Equal(t, tt.expectedRisk, actual)
		})
	}
}

func TestMarkdownBuilder_CalculateSecurityScore(t *testing.T) {
	b := NewMarkdownBuilder()

	t.Run("nil configuration", func(t *testing.T) {
		score := b.CalculateSecurityScore(nil)
		assert.Equal(t, 0, score)
	})

	t.Run("good baseline configuration", func(t *testing.T) {
		cfg := &model.OpnSenseDocument{
			Filter: model.Filter{
				Rule: []model.Rule{{Type: "block"}}, // at least one rule
			},
			Sysctl: []model.SysctlItem{
				{Tunable: "net.inet.ip.forwarding", Value: "0"},
				{Tunable: "net.inet6.ip6.forwarding", Value: "0"},
				{Tunable: "net.inet.tcp.blackhole", Value: "2"},
				{Tunable: "net.inet.udp.blackhole", Value: "1"},
			},
			System: model.System{
				User: []model.User{
					{Name: "john"}, // non-default user
				},
			},
		}
		score := b.CalculateSecurityScore(cfg)
		assert.GreaterOrEqual(t, score, 80)
		assert.LessOrEqual(t, score, 100)
	})

	t.Run("poor configuration with management on WAN", func(t *testing.T) {
		cfg := &model.OpnSenseDocument{
			Filter: model.Filter{
				Rule: []model.Rule{
					{ // Management on WAN
						Type:      "pass",
						Interface: model.InterfaceList{"wan"},
						Destination: model.Destination{
							Port: "22",
						},
					},
				},
			},
			System: model.System{
				User: []model.User{
					{Name: "admin"}, // default user
				},
			},
		}
		score := b.CalculateSecurityScore(cfg)
		assert.Less(t, score, 80)
	})

	t.Run("no firewall rules", func(t *testing.T) {
		cfg := &model.OpnSenseDocument{
			Filter: model.Filter{
				Rule: []model.Rule{}, // no rules
			},
			System: model.System{
				User: []model.User{
					{Name: "normaluser"},
				},
			},
		}
		score := b.CalculateSecurityScore(cfg)
		assert.LessOrEqual(t, score, 80) // Should lose points for no firewall rules
	})

	t.Run("bad sysctl settings", func(t *testing.T) {
		cfg := &model.OpnSenseDocument{
			Filter: model.Filter{
				Rule: []model.Rule{{Type: "block"}},
			},
			Sysctl: []model.SysctlItem{
				{Tunable: "net.inet.ip.forwarding", Value: "1"}, // Bad: forwarding enabled
				{Tunable: "net.inet.tcp.blackhole", Value: "0"}, // Bad: blackhole disabled
			},
			System: model.System{
				User: []model.User{
					{Name: "normaluser"},
				},
			},
		}
		score := b.CalculateSecurityScore(cfg)
		assert.Less(t, score, 100) // Should lose points for bad sysctl settings
	})

	t.Run("score bounds", func(t *testing.T) {
		// Test extreme case that would result in negative score
		cfg := &model.OpnSenseDocument{
			Filter: model.Filter{
				Rule: []model.Rule{
					{ // Management on WAN
						Type:      "pass",
						Interface: model.InterfaceList{"wan"},
						Destination: model.Destination{
							Port: "22",
						},
					},
				},
			},
			System: model.System{
				User: []model.User{
					{Name: "admin"}, // -15
					{Name: "root"},  // -15
					{Name: "user"},  // -15
				},
			},
		}
		score := b.CalculateSecurityScore(cfg)
		assert.GreaterOrEqual(t, score, 0, "Score should not go below 0")
		assert.LessOrEqual(t, score, 100, "Score should not exceed 100")
	})
}

func TestMarkdownBuilder_hasManagementOnWAN(t *testing.T) {
	b := NewMarkdownBuilder()

	t.Run("no WAN rules", func(t *testing.T) {
		cfg := &model.OpnSenseDocument{
			Filter: model.Filter{
				Rule: []model.Rule{
					{
						Interface:   model.InterfaceList{"lan"},
						Destination: model.Destination{Port: "22"},
					},
				},
			},
		}
		assert.False(t, b.hasManagementOnWAN(cfg))
	})

	t.Run("WAN rule with management port", func(t *testing.T) {
		cfg := &model.OpnSenseDocument{
			Filter: model.Filter{
				Rule: []model.Rule{
					{
						Interface:   model.InterfaceList{"wan"},
						Destination: model.Destination{Port: "22"},
					},
				},
			},
		}
		assert.True(t, b.hasManagementOnWAN(cfg))
	})

	t.Run("WAN rule with multiple management ports", func(t *testing.T) {
		cfg := &model.OpnSenseDocument{
			Filter: model.Filter{
				Rule: []model.Rule{
					{
						Interface:   model.InterfaceList{"wan"},
						Destination: model.Destination{Port: "443"},
					},
					{
						Interface:   model.InterfaceList{"wan"},
						Destination: model.Destination{Port: "8080"},
					},
				},
			},
		}
		assert.True(t, b.hasManagementOnWAN(cfg))
	})

	t.Run("WAN rule with non-management port", func(t *testing.T) {
		cfg := &model.OpnSenseDocument{
			Filter: model.Filter{
				Rule: []model.Rule{
					{
						Interface:   model.InterfaceList{"wan"},
						Destination: model.Destination{Port: "53"},
					},
				},
			},
		}
		assert.False(t, b.hasManagementOnWAN(cfg))
	})

	t.Run("WAN rule with direction check", func(t *testing.T) {
		cfg := &model.OpnSenseDocument{
			Filter: model.Filter{
				Rule: []model.Rule{
					{
						Interface:   model.InterfaceList{"wan"},
						Direction:   "out",
						Destination: model.Destination{Port: "22"},
					},
				},
			},
		}
		assert.False(t, b.hasManagementOnWAN(cfg), "Outbound rules should not trigger management on WAN warning")
	})

	t.Run("WAN rule with inbound direction", func(t *testing.T) {
		cfg := &model.OpnSenseDocument{
			Filter: model.Filter{
				Rule: []model.Rule{
					{
						Interface:   model.InterfaceList{"wan"},
						Direction:   "in",
						Destination: model.Destination{Port: "22"},
					},
				},
			},
		}
		assert.True(t, b.hasManagementOnWAN(cfg), "Inbound rules should trigger management on WAN warning")
	})
}

func TestMarkdownBuilder_checkTunable(t *testing.T) {
	b := NewMarkdownBuilder()

	tunables := []model.SysctlItem{
		{Tunable: "net.inet.ip.forwarding", Value: "0"},
		{Tunable: "net.inet.tcp.blackhole", Value: "2"},
		{Tunable: "kern.securelevel", Value: "1"},
	}

	t.Run("existing tunable with correct value", func(t *testing.T) {
		result := b.checkTunable(tunables, "net.inet.ip.forwarding", "0")
		assert.True(t, result)
	})

	t.Run("existing tunable with incorrect value", func(t *testing.T) {
		result := b.checkTunable(tunables, "net.inet.ip.forwarding", "1")
		assert.False(t, result)
	})

	t.Run("non-existing tunable", func(t *testing.T) {
		result := b.checkTunable(tunables, "net.inet.nonexistent", "0")
		assert.False(t, result)
	})

	t.Run("empty tunables list", func(t *testing.T) {
		result := b.checkTunable([]model.SysctlItem{}, "net.inet.ip.forwarding", "0")
		assert.False(t, result)
	})
}

func TestMarkdownBuilder_isDefaultUser(t *testing.T) {
	b := NewMarkdownBuilder()

	tests := []struct {
		name     string
		user     model.User
		expected bool
	}{
		{
			name:     "admin user",
			user:     model.User{Name: "admin"},
			expected: true,
		},
		{
			name:     "Admin user (capitalized)",
			user:     model.User{Name: "Admin"},
			expected: true,
		},
		{
			name:     "root user",
			user:     model.User{Name: "root"},
			expected: true,
		},
		{
			name:     "ROOT user (uppercase)",
			user:     model.User{Name: "ROOT"},
			expected: true,
		},
		{
			name:     "user user",
			user:     model.User{Name: "user"},
			expected: true,
		},
		{
			name:     "USER user (uppercase)",
			user:     model.User{Name: "USER"},
			expected: true,
		},
		{
			name:     "custom user",
			user:     model.User{Name: "john"},
			expected: false,
		},
		{
			name:     "empty user name",
			user:     model.User{Name: ""},
			expected: false,
		},
		{
			name:     "partial match",
			user:     model.User{Name: "administrator"},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := b.isDefaultUser(tt.user)
			assert.Equal(t, tt.expected, result)
		})
	}
}
