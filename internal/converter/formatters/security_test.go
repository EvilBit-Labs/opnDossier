package formatters

import (
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/model"
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
		data *model.OpnSenseDocument
		want int
	}{
		{
			name: "nil document",
			data: nil,
			want: 0,
		},
		{
			name: "empty document - no firewall rules",
			data: &model.OpnSenseDocument{
				Filter: model.Filter{Rule: []model.Rule{}},
				System: model.System{User: []model.User{}},
				Sysctl: []model.SysctlItem{},
			},
			want: 60, // 100 - 20 (no firewall rules) - 20 (4 missing tunables × 5)
		},
		{
			name: "document with firewall rules",
			data: &model.OpnSenseDocument{
				Filter: model.Filter{Rule: []model.Rule{{Type: "pass"}}},
				System: model.System{User: []model.User{}},
				Sysctl: []model.SysctlItem{},
			},
			want: 80, // 100 - 20 (4 missing tunables × 5)
		},
		{
			name: "document with management on WAN",
			data: &model.OpnSenseDocument{
				Filter: model.Filter{Rule: []model.Rule{
					{
						Interface:   model.InterfaceList{"wan"},
						Direction:   "in",
						Destination: model.Destination{Port: "443"},
					},
				}},
				System: model.System{User: []model.User{}},
				Sysctl: []model.SysctlItem{},
			},
			want: 50, // 100 - 30 (management on WAN) - 20 (4 missing tunables × 5)
		},
		{
			name: "document with default user",
			data: &model.OpnSenseDocument{
				Filter: model.Filter{Rule: []model.Rule{{Type: "pass"}}},
				System: model.System{User: []model.User{
					{Name: "admin"},
				}},
				Sysctl: []model.SysctlItem{},
			},
			want: 65, // 100 - 15 (default user) - 20 (4 missing tunables × 5)
		},
		{
			name: "document with insecure tunable",
			data: &model.OpnSenseDocument{
				Filter: model.Filter{Rule: []model.Rule{{Type: "pass"}}},
				System: model.System{User: []model.User{}},
				Sysctl: []model.SysctlItem{
					{Tunable: "net.inet.ip.forwarding", Value: "1"}, // Should be "0"
				},
			},
			want: 80, // 100 - 5 (insecure tunable) - 15 (3 missing tunables × 5)
		},
		{
			name: "document with secure tunable",
			data: &model.OpnSenseDocument{
				Filter: model.Filter{Rule: []model.Rule{{Type: "pass"}}},
				System: model.System{User: []model.User{}},
				Sysctl: []model.SysctlItem{
					{Tunable: "net.inet.ip.forwarding", Value: "0"}, // Correct value
				},
			},
			want: 85, // 100 - 15 (3 missing tunables × 5)
		},
		{
			name: "document with all secure tunables",
			data: &model.OpnSenseDocument{
				Filter: model.Filter{Rule: []model.Rule{{Type: "pass"}}},
				System: model.System{User: []model.User{}},
				Sysctl: []model.SysctlItem{
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
			data: &model.OpnSenseDocument{
				Filter: model.Filter{Rule: []model.Rule{}}, // No rules: -20
				System: model.System{User: []model.User{
					{Name: "admin"}, // Default user: -15
					{Name: "root"},  // Another default user: -15
				}},
				Sysctl: []model.SysctlItem{
					{Tunable: "net.inet.ip.forwarding", Value: "1"},   // Wrong: -5
					{Tunable: "net.inet6.ip6.forwarding", Value: "1"}, // Wrong: -5
					// Missing 2 other tunables: -10 (2 × 5)
				},
			},
			want: 30,
		},
		{
			name: "document with extreme penalties - score clamps to 0",
			data: &model.OpnSenseDocument{
				Filter: model.Filter{Rule: []model.Rule{}}, // No rules: -20
				System: model.System{User: []model.User{
					{Name: "admin"}, // Default user: -15
					{Name: "root"},  // Default user: -15
					{Name: "user"},  // Default user: -15
					// Add more default users to force negative
					{Name: "admin"}, // Default user: -15
					{Name: "root"},  // Default user: -15
					{Name: "user"},  // Default user: -15
					{Name: "admin"}, // Default user: -15
				}},
				Sysctl: []model.SysctlItem{
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
		service model.Service
		want    string
	}{
		{
			name:    "telnet service",
			service: model.Service{Name: "telnet"},
			want:    "🔴 Critical Risk",
		},
		{
			name:    "ftp service",
			service: model.Service{Name: "ftp"},
			want:    "🟠 High Risk",
		},
		{
			name:    "vnc service",
			service: model.Service{Name: "vnc-server"},
			want:    "🟠 High Risk",
		},
		{
			name:    "rdp service",
			service: model.Service{Name: "rdp"},
			want:    "🟡 Medium Risk",
		},
		{
			name:    "ssh service",
			service: model.Service{Name: "ssh"},
			want:    "🟢 Low Risk",
		},
		{
			name:    "https service",
			service: model.Service{Name: "https"},
			want:    "ℹ️ Informational",
		},
		{
			name:    "unknown service",
			service: model.Service{Name: "unknown"},
			want:    "ℹ️ Informational",
		},
		{
			name:    "case insensitive matching",
			service: model.Service{Name: "TELNET"},
			want:    "🔴 Critical Risk",
		},
		{
			name:    "service name contains pattern",
			service: model.Service{Name: "openssh"},
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
		data *model.OpnSenseDocument
		want bool
	}{
		{
			name: "no rules",
			data: &model.OpnSenseDocument{
				Filter: model.Filter{Rule: []model.Rule{}},
			},
			want: false,
		},
		{
			name: "rule on LAN interface",
			data: &model.OpnSenseDocument{
				Filter: model.Filter{Rule: []model.Rule{
					{
						Interface:   model.InterfaceList{"lan"},
						Direction:   "in",
						Destination: model.Destination{Port: "443"},
					},
				}},
			},
			want: false,
		},
		{
			name: "rule on WAN but outbound",
			data: &model.OpnSenseDocument{
				Filter: model.Filter{Rule: []model.Rule{
					{
						Interface:   model.InterfaceList{"wan"},
						Direction:   "out",
						Destination: model.Destination{Port: "443"},
					},
				}},
			},
			want: false,
		},
		{
			name: "rule on WAN with non-management port",
			data: &model.OpnSenseDocument{
				Filter: model.Filter{Rule: []model.Rule{
					{
						Interface:   model.InterfaceList{"wan"},
						Direction:   "in",
						Destination: model.Destination{Port: "9999"},
					},
				}},
			},
			want: false,
		},
		{
			name: "rule on WAN with HTTPS port",
			data: &model.OpnSenseDocument{
				Filter: model.Filter{Rule: []model.Rule{
					{
						Interface:   model.InterfaceList{"wan"},
						Direction:   "in",
						Destination: model.Destination{Port: "443"},
					},
				}},
			},
			want: true,
		},
		{
			name: "rule on WAN with HTTP port",
			data: &model.OpnSenseDocument{
				Filter: model.Filter{Rule: []model.Rule{
					{
						Interface:   model.InterfaceList{"wan"},
						Direction:   "in",
						Destination: model.Destination{Port: "80"},
					},
				}},
			},
			want: true,
		},
		{
			name: "rule on WAN with SSH port",
			data: &model.OpnSenseDocument{
				Filter: model.Filter{Rule: []model.Rule{
					{
						Interface:   model.InterfaceList{"wan"},
						Direction:   "in",
						Destination: model.Destination{Port: "22"},
					},
				}},
			},
			want: true,
		},
		{
			name: "rule on WAN with alternative HTTP port",
			data: &model.OpnSenseDocument{
				Filter: model.Filter{Rule: []model.Rule{
					{
						Interface:   model.InterfaceList{"wan"},
						Direction:   "in",
						Destination: model.Destination{Port: "8080"},
					},
				}},
			},
			want: true,
		},
		{
			name: "rule on WAN with empty direction (defaults to inbound)",
			data: &model.OpnSenseDocument{
				Filter: model.Filter{Rule: []model.Rule{
					{
						Interface:   model.InterfaceList{"wan"},
						Direction:   "",
						Destination: model.Destination{Port: "443"},
					},
				}},
			},
			want: true,
		},
		{
			name: "rule on WAN with port in destination string",
			data: &model.OpnSenseDocument{
				Filter: model.Filter{Rule: []model.Rule{
					{
						Interface:   model.InterfaceList{"wan"},
						Direction:   "in",
						Destination: model.Destination{Port: "range:80-90"},
					},
				}},
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
		tunables    []model.SysctlItem
		tunableName string
		expected    string
		want        bool
	}{
		{
			name:        "empty tunables",
			tunables:    []model.SysctlItem{},
			tunableName: "net.inet.ip.forwarding",
			expected:    "0",
			want:        false,
		},
		{
			name: "tunable found with correct value",
			tunables: []model.SysctlItem{
				{Tunable: "net.inet.ip.forwarding", Value: "0"},
			},
			tunableName: "net.inet.ip.forwarding",
			expected:    "0",
			want:        true,
		},
		{
			name: "tunable found with incorrect value",
			tunables: []model.SysctlItem{
				{Tunable: "net.inet.ip.forwarding", Value: "1"},
			},
			tunableName: "net.inet.ip.forwarding",
			expected:    "0",
			want:        false,
		},
		{
			name: "tunable not found",
			tunables: []model.SysctlItem{
				{Tunable: "net.inet.ip.forwarding", Value: "0"},
			},
			tunableName: "net.inet6.ip6.forwarding",
			expected:    "0",
			want:        false,
		},
		{
			name: "multiple tunables",
			tunables: []model.SysctlItem{
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
		user model.User
		want bool
	}{
		{"admin user", model.User{Name: "admin"}, true},
		{"root user", model.User{Name: "root"}, true},
		{"user user", model.User{Name: "user"}, true},
		{"admin uppercase", model.User{Name: "ADMIN"}, true},
		{"root mixed case", model.User{Name: "Root"}, true},
		{"custom user", model.User{Name: "customuser"}, false},
		{"empty name", model.User{Name: ""}, false},
		{"similar name", model.User{Name: "administrator"}, false},
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
