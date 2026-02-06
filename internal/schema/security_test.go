package schema

import (
	"testing"
)

// newTestIDs creates an IDS with the given general field values for testing.
func newTestIDs(opts func(ids *IDS)) *IDS {
	ids := &IDS{}
	opts(ids)
	return ids
}

func TestIDS_IsEnabled(t *testing.T) {
	tests := []struct {
		name string
		ids  *IDS
		want bool
	}{
		{
			name: "nil IDS",
			ids:  nil,
			want: false,
		},
		{
			name: "enabled",
			ids:  newTestIDs(func(ids *IDS) { ids.General.Enabled = "1" }),
			want: true,
		},
		{
			name: "disabled",
			ids:  newTestIDs(func(ids *IDS) { ids.General.Enabled = "0" }),
			want: false,
		},
		{
			name: "empty",
			ids:  &IDS{},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.ids.IsEnabled(); got != tt.want {
				t.Errorf("IDS.IsEnabled() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIDS_IsIPSMode(t *testing.T) {
	tests := []struct {
		name string
		ids  *IDS
		want bool
	}{
		{
			name: "nil IDS",
			ids:  nil,
			want: false,
		},
		{
			name: "IPS mode enabled",
			ids:  newTestIDs(func(ids *IDS) { ids.General.Ips = "1" }),
			want: true,
		},
		{
			name: "IPS mode disabled",
			ids:  newTestIDs(func(ids *IDS) { ids.General.Ips = "0" }),
			want: false,
		},
		{
			name: "empty",
			ids:  &IDS{},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.ids.IsIPSMode(); got != tt.want {
				t.Errorf("IDS.IsIPSMode() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIDS_GetMonitoredInterfaces(t *testing.T) {
	tests := []struct {
		name string
		ids  *IDS
		want []string
	}{
		{
			name: "nil IDS",
			ids:  nil,
			want: nil,
		},
		{
			name: "single interface",
			ids:  newTestIDs(func(ids *IDS) { ids.General.Interfaces = "wan" }),
			want: []string{"wan"},
		},
		{
			name: "multiple interfaces",
			ids:  newTestIDs(func(ids *IDS) { ids.General.Interfaces = "wan,lan,opt1" }),
			want: []string{"wan", "lan", "opt1"},
		},
		{
			name: "interfaces with spaces",
			ids:  newTestIDs(func(ids *IDS) { ids.General.Interfaces = "wan, lan, opt1" }),
			want: []string{"wan", "lan", "opt1"},
		},
		{
			name: "empty string",
			ids:  newTestIDs(func(ids *IDS) { ids.General.Interfaces = "" }),
			want: nil,
		},
		{
			name: "empty IDS",
			ids:  &IDS{},
			want: nil,
		},
		{
			name: "leading comma",
			ids:  newTestIDs(func(ids *IDS) { ids.General.Interfaces = ",wan,lan" }),
			want: []string{"wan", "lan"},
		},
		{
			name: "trailing comma",
			ids:  newTestIDs(func(ids *IDS) { ids.General.Interfaces = "wan,lan," }),
			want: []string{"wan", "lan"},
		},
		{
			name: "double comma",
			ids:  newTestIDs(func(ids *IDS) { ids.General.Interfaces = "wan,,lan" }),
			want: []string{"wan", "lan"},
		},
		{
			name: "only commas",
			ids:  newTestIDs(func(ids *IDS) { ids.General.Interfaces = ",,," }),
			want: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.ids.GetMonitoredInterfaces()
			if len(got) != len(tt.want) {
				t.Errorf("IDS.GetMonitoredInterfaces() length = %d, want %d", len(got), len(tt.want))
				return
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("IDS.GetMonitoredInterfaces()[%d] = %q, want %q", i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestIDS_GetHomeNetworks(t *testing.T) {
	tests := []struct {
		name string
		ids  *IDS
		want []string
	}{
		{
			name: "nil IDS",
			ids:  nil,
			want: nil,
		},
		{
			name: "single network",
			ids:  newTestIDs(func(ids *IDS) { ids.General.Homenet = "192.168.1.0/24" }),
			want: []string{"192.168.1.0/24"},
		},
		{
			name: "multiple networks",
			ids:  newTestIDs(func(ids *IDS) { ids.General.Homenet = "192.168.1.0/24,10.0.0.0/8,172.16.0.0/12" }),
			want: []string{"192.168.1.0/24", "10.0.0.0/8", "172.16.0.0/12"},
		},
		{
			name: "networks with spaces",
			ids:  newTestIDs(func(ids *IDS) { ids.General.Homenet = "192.168.1.0/24, 10.0.0.0/8" }),
			want: []string{"192.168.1.0/24", "10.0.0.0/8"},
		},
		{
			name: "empty string",
			ids:  newTestIDs(func(ids *IDS) { ids.General.Homenet = "" }),
			want: nil,
		},
		{
			name: "leading comma",
			ids:  newTestIDs(func(ids *IDS) { ids.General.Homenet = ",192.168.1.0/24,10.0.0.0/8" }),
			want: []string{"192.168.1.0/24", "10.0.0.0/8"},
		},
		{
			name: "trailing comma",
			ids:  newTestIDs(func(ids *IDS) { ids.General.Homenet = "192.168.1.0/24,10.0.0.0/8," }),
			want: []string{"192.168.1.0/24", "10.0.0.0/8"},
		},
		{
			name: "double comma",
			ids:  newTestIDs(func(ids *IDS) { ids.General.Homenet = "192.168.1.0/24,,10.0.0.0/8" }),
			want: []string{"192.168.1.0/24", "10.0.0.0/8"},
		},
		{
			name: "only commas",
			ids:  newTestIDs(func(ids *IDS) { ids.General.Homenet = ",,," }),
			want: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.ids.GetHomeNetworks()
			if len(got) != len(tt.want) {
				t.Errorf("IDS.GetHomeNetworks() length = %d, want %d", len(got), len(tt.want))
				return
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("IDS.GetHomeNetworks()[%d] = %q, want %q", i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestIDS_GetDetectionMode(t *testing.T) {
	tests := []struct {
		name string
		ids  *IDS
		want string
	}{
		{
			name: "nil IDS",
			ids:  nil,
			want: "Disabled",
		},
		{
			name: "IPS mode",
			ids:  newTestIDs(func(ids *IDS) { ids.General.Ips = "1" }),
			want: "IPS (Prevention)",
		},
		{
			name: "IDS mode",
			ids:  newTestIDs(func(ids *IDS) { ids.General.Ips = "0" }),
			want: "IDS (Detection Only)",
		},
		{
			name: "default IDS mode",
			ids:  &IDS{},
			want: "IDS (Detection Only)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.ids.GetDetectionMode(); got != tt.want {
				t.Errorf("IDS.GetDetectionMode() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestIDS_IsSyslogEnabled(t *testing.T) {
	tests := []struct {
		name string
		ids  *IDS
		want bool
	}{
		{
			name: "nil IDS",
			ids:  nil,
			want: false,
		},
		{
			name: "syslog enabled",
			ids:  newTestIDs(func(ids *IDS) { ids.General.Syslog = "1" }),
			want: true,
		},
		{
			name: "syslog disabled",
			ids:  newTestIDs(func(ids *IDS) { ids.General.Syslog = "0" }),
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.ids.IsSyslogEnabled(); got != tt.want {
				t.Errorf("IDS.IsSyslogEnabled() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIDS_IsSyslogEveEnabled(t *testing.T) {
	tests := []struct {
		name string
		ids  *IDS
		want bool
	}{
		{
			name: "nil IDS",
			ids:  nil,
			want: false,
		},
		{
			name: "eve syslog enabled",
			ids:  newTestIDs(func(ids *IDS) { ids.General.SyslogEve = "1" }),
			want: true,
		},
		{
			name: "eve syslog disabled",
			ids:  newTestIDs(func(ids *IDS) { ids.General.SyslogEve = "0" }),
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.ids.IsSyslogEveEnabled(); got != tt.want {
				t.Errorf("IDS.IsSyslogEveEnabled() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIDS_IsPromiscuousMode(t *testing.T) {
	tests := []struct {
		name string
		ids  *IDS
		want bool
	}{
		{
			name: "nil IDS",
			ids:  nil,
			want: false,
		},
		{
			name: "promiscuous enabled",
			ids:  newTestIDs(func(ids *IDS) { ids.General.Promisc = "1" }),
			want: true,
		},
		{
			name: "promiscuous disabled",
			ids:  newTestIDs(func(ids *IDS) { ids.General.Promisc = "0" }),
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.ids.IsPromiscuousMode(); got != tt.want {
				t.Errorf("IDS.IsPromiscuousMode() = %v, want %v", got, tt.want)
			}
		})
	}
}
