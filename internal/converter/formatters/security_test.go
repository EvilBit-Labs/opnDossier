package formatters

import (
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/model/common"
)

func TestAssessRiskLevel(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		severity string
		want     string
	}{
		{"critical", "critical", "🔴 Critical Risk"},
		{"critical uppercase", "CRITICAL", "🔴 Critical Risk"},
		{"critical with spaces", " critical ", "🔴 Critical Risk"},
		{"high", "high", "🟠 High Risk"},
		{"high uppercase", "HIGH", "🟠 High Risk"},
		{"medium", "medium", "🟡 Medium Risk"},
		{"low", "low", "🟢 Low Risk"},
		{"info", "info", "ℹ️ Informational"},
		{"informational", "informational", "ℹ️ Informational"},
		{"informational uppercase", "INFORMATIONAL", "ℹ️ Informational"},
		{"unknown", "unknown", "⚪ Unknown Risk"},
		{"empty", "", "⚪ Unknown Risk"},
		{"random", "random", "⚪ Unknown Risk"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := AssessRiskLevel(tt.severity)
			if got != tt.want {
				t.Errorf("AssessRiskLevel(%q) = %q, want %q", tt.severity, got, tt.want)
			}
		})
	}
}

func TestCalculateSecurityScore(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		data *common.CommonDevice
		want int
	}{
		{
			name: "nil document",
			data: nil,
			want: 0,
		},
		{
			name: "empty document - no firewall rules",
			data: &common.CommonDevice{
				FirewallRules: []common.FirewallRule{},
				Users:         []common.User{},
				Sysctl:        []common.SysctlItem{},
			},
			want: 60, // 100 - 20 (no firewall rules) - 20 (4 missing tunables × 5)
		},
		{
			name: "document with firewall rules",
			data: &common.CommonDevice{
				FirewallRules: []common.FirewallRule{{Type: "pass"}},
				Users:         []common.User{},
				Sysctl:        []common.SysctlItem{},
			},
			want: 80, // 100 - 20 (4 missing tunables × 5)
		},
		{
			name: "document with management on WAN",
			data: &common.CommonDevice{
				FirewallRules: []common.FirewallRule{
					{
						Interfaces:  []string{"wan"},
						Direction:   "in",
						Destination: common.RuleEndpoint{Port: "443"},
					},
				},
				Users:  []common.User{},
				Sysctl: []common.SysctlItem{},
			},
			want: 50, // 100 - 30 (management on WAN) - 20 (4 missing tunables × 5)
		},
		{
			name: "document with default user",
			data: &common.CommonDevice{
				FirewallRules: []common.FirewallRule{{Type: "pass"}},
				Users: []common.User{
					{Name: "admin"},
				},
				Sysctl: []common.SysctlItem{},
			},
			want: 65, // 100 - 15 (default user) - 20 (4 missing tunables × 5)
		},
		{
			name: "document with insecure tunable",
			data: &common.CommonDevice{
				FirewallRules: []common.FirewallRule{{Type: "pass"}},
				Users:         []common.User{},
				Sysctl: []common.SysctlItem{
					{Tunable: "net.inet.ip.forwarding", Value: "1"}, // Should be "0"
				},
			},
			want: 80, // 100 - 5 (insecure tunable) - 15 (3 missing tunables × 5)
		},
		{
			name: "document with secure tunable",
			data: &common.CommonDevice{
				FirewallRules: []common.FirewallRule{{Type: "pass"}},
				Users:         []common.User{},
				Sysctl: []common.SysctlItem{
					{Tunable: "net.inet.ip.forwarding", Value: "0"}, // Correct value
				},
			},
			want: 85, // 100 - 15 (3 missing tunables × 5)
		},
		{
			name: "document with all secure tunables",
			data: &common.CommonDevice{
				FirewallRules: []common.FirewallRule{{Type: "pass"}},
				Users:         []common.User{},
				Sysctl: []common.SysctlItem{
					{Tunable: "net.inet.ip.forwarding", Value: "0"},
					{Tunable: "net.inet6.ip6.forwarding", Value: "0"},
					{Tunable: "net.inet.tcp.blackhole", Value: "2"},
					{Tunable: "net.inet.udp.blackhole", Value: "1"},
				},
			},
			want: 100, // No penalties
		},
		{
			name: "document with multiple penalties",
			data: &common.CommonDevice{
				FirewallRules: []common.FirewallRule{}, // No rules: -20
				Users: []common.User{
					{Name: "admin"}, // Default user: -15
					{Name: "root"},  // Another default user: -15
				},
				Sysctl: []common.SysctlItem{
					{Tunable: "net.inet.ip.forwarding", Value: "1"},   // Wrong: -5
					{Tunable: "net.inet6.ip6.forwarding", Value: "1"}, // Wrong: -5
					// Missing 2 other tunables: -10 (2 × 5)
				},
			},
			want: 30,
		},
		{
			name: "document with extreme penalties - score clamps to 0",
			data: &common.CommonDevice{
				FirewallRules: []common.FirewallRule{}, // No rules: -20
				Users: []common.User{
					{Name: "admin"}, // Default user: -15
					{Name: "root"},  // Default user: -15
					{Name: "user"},  // Default user: -15
					// Add more default users to force negative
					{Name: "admin"}, // Default user: -15
					{Name: "root"},  // Default user: -15
					{Name: "user"},  // Default user: -15
					{Name: "admin"}, // Default user: -15
				},
				Sysctl: []common.SysctlItem{
					{Tunable: "net.inet.ip.forwarding", Value: "1"},   // Wrong: -5
					{Tunable: "net.inet6.ip6.forwarding", Value: "1"}, // Wrong: -5
					{Tunable: "net.inet.tcp.blackhole", Value: "1"},   // Wrong: -5
					{Tunable: "net.inet.udp.blackhole", Value: "0"},   // Wrong: -5
				},
			},
			want: 0, // 100 - 20 - (7*15) - (4*5) = 100 - 20 - 105 - 20 = -45, clamped to 0
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := CalculateSecurityScore(tt.data)
			if got != tt.want {
				t.Errorf("CalculateSecurityScore() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestAssessServiceRisk(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		service string
		want    string
	}{
		{
			name:    "telnet service",
			service: "telnet",
			want:    "🔴 Critical Risk",
		},
		{
			name:    "ftp service",
			service: "ftp",
			want:    "🟠 High Risk",
		},
		{
			name:    "vnc service",
			service: "vnc-server",
			want:    "🟠 High Risk",
		},
		{
			name:    "rdp service",
			service: "rdp",
			want:    "🟡 Medium Risk",
		},
		{
			name:    "ssh service",
			service: "ssh",
			want:    "🟢 Low Risk",
		},
		{
			name:    "https service",
			service: "https",
			want:    "ℹ️ Informational",
		},
		{
			name:    "unknown service",
			service: "unknown",
			want:    "ℹ️ Informational",
		},
		{
			name:    "case insensitive matching",
			service: "TELNET",
			want:    "🔴 Critical Risk",
		},
		{
			name:    "service name contains pattern",
			service: "openssh",
			want:    "🟢 Low Risk",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := AssessServiceRisk(tt.service)
			if got != tt.want {
				t.Errorf("AssessServiceRisk(%v) = %q, want %q", tt.service, got, tt.want)
			}
		})
	}
}

func TestHasManagementOnWAN(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		data *common.CommonDevice
		want bool
	}{
		{
			name: "no rules",
			data: &common.CommonDevice{
				FirewallRules: []common.FirewallRule{},
			},
			want: false,
		},
		{
			name: "rule on LAN interface",
			data: &common.CommonDevice{
				FirewallRules: []common.FirewallRule{
					{
						Interfaces:  []string{"lan"},
						Direction:   "in",
						Destination: common.RuleEndpoint{Port: "443"},
					},
				},
			},
			want: false,
		},
		{
			name: "rule on WAN but outbound",
			data: &common.CommonDevice{
				FirewallRules: []common.FirewallRule{
					{
						Interfaces:  []string{"wan"},
						Direction:   "out",
						Destination: common.RuleEndpoint{Port: "443"},
					},
				},
			},
			want: false,
		},
		{
			name: "rule on WAN with non-management port",
			data: &common.CommonDevice{
				FirewallRules: []common.FirewallRule{
					{
						Interfaces:  []string{"wan"},
						Direction:   "in",
						Destination: common.RuleEndpoint{Port: "9999"},
					},
				},
			},
			want: false,
		},
		{
			name: "rule on WAN with HTTPS port",
			data: &common.CommonDevice{
				FirewallRules: []common.FirewallRule{
					{
						Interfaces:  []string{"wan"},
						Direction:   "in",
						Destination: common.RuleEndpoint{Port: "443"},
					},
				},
			},
			want: true,
		},
		{
			name: "rule on WAN with mixed-case interface name",
			data: &common.CommonDevice{
				FirewallRules: []common.FirewallRule{
					{
						Interfaces:  []string{"WAN"},
						Direction:   "in",
						Destination: common.RuleEndpoint{Port: "443"},
					},
				},
			},
			want: true,
		},
		{
			name: "rule on WAN with HTTP port",
			data: &common.CommonDevice{
				FirewallRules: []common.FirewallRule{
					{
						Interfaces:  []string{"wan"},
						Direction:   "in",
						Destination: common.RuleEndpoint{Port: "80"},
					},
				},
			},
			want: true,
		},
		{
			name: "rule on WAN with SSH port",
			data: &common.CommonDevice{
				FirewallRules: []common.FirewallRule{
					{
						Interfaces:  []string{"wan"},
						Direction:   "in",
						Destination: common.RuleEndpoint{Port: "22"},
					},
				},
			},
			want: true,
		},
		{
			name: "rule on WAN with alternative HTTP port",
			data: &common.CommonDevice{
				FirewallRules: []common.FirewallRule{
					{
						Interfaces:  []string{"wan"},
						Direction:   "in",
						Destination: common.RuleEndpoint{Port: "8080"},
					},
				},
			},
			want: true,
		},
		{
			name: "rule on WAN with empty direction (defaults to inbound)",
			data: &common.CommonDevice{
				FirewallRules: []common.FirewallRule{
					{
						Interfaces:  []string{"wan"},
						Direction:   "",
						Destination: common.RuleEndpoint{Port: "443"},
					},
				},
			},
			want: true,
		},
		{
			name: "rule on WAN with port in destination string",
			data: &common.CommonDevice{
				FirewallRules: []common.FirewallRule{
					{
						Interfaces:  []string{"wan"},
						Direction:   "in",
						Destination: common.RuleEndpoint{Port: "range:80-90"},
					},
				},
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := hasManagementOnWAN(tt.data)
			if got != tt.want {
				t.Errorf("hasManagementOnWAN() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCheckTunable(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		tunables    []common.SysctlItem
		tunableName string
		expected    string
		want        bool
	}{
		{
			name:        "empty tunables",
			tunables:    []common.SysctlItem{},
			tunableName: "net.inet.ip.forwarding",
			expected:    "0",
			want:        false,
		},
		{
			name: "tunable found with correct value",
			tunables: []common.SysctlItem{
				{Tunable: "net.inet.ip.forwarding", Value: "0"},
			},
			tunableName: "net.inet.ip.forwarding",
			expected:    "0",
			want:        true,
		},
		{
			name: "tunable found with incorrect value",
			tunables: []common.SysctlItem{
				{Tunable: "net.inet.ip.forwarding", Value: "1"},
			},
			tunableName: "net.inet.ip.forwarding",
			expected:    "0",
			want:        false,
		},
		{
			name: "tunable not found",
			tunables: []common.SysctlItem{
				{Tunable: "net.inet.ip.forwarding", Value: "0"},
			},
			tunableName: "net.inet6.ip6.forwarding",
			expected:    "0",
			want:        false,
		},
		{
			name: "multiple tunables",
			tunables: []common.SysctlItem{
				{Tunable: "net.inet.ip.forwarding", Value: "0"},
				{Tunable: "net.inet6.ip6.forwarding", Value: "0"},
				{Tunable: "net.inet.tcp.blackhole", Value: "2"},
			},
			tunableName: "net.inet.tcp.blackhole",
			expected:    "2",
			want:        true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := checkTunable(tt.tunables, tt.tunableName, tt.expected)
			if got != tt.want {
				t.Errorf("checkTunable(%s, %s) = %v, want %v", tt.tunableName, tt.expected, got, tt.want)
			}
		})
	}
}

func TestIsDefaultUser(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		user common.User
		want bool
	}{
		{"admin user", common.User{Name: "admin"}, true},
		{"root user", common.User{Name: "root"}, true},
		{"user user", common.User{Name: "user"}, true},
		{"admin uppercase", common.User{Name: "ADMIN"}, true},
		{"root mixed case", common.User{Name: "Root"}, true},
		{"custom user", common.User{Name: "customuser"}, false},
		{"empty name", common.User{Name: ""}, false},
		{"similar name", common.User{Name: "administrator"}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := isDefaultUser(tt.user)
			if got != tt.want {
				t.Errorf("isDefaultUser(%v) = %v, want %v", tt.user, got, tt.want)
			}
		})
	}
}
