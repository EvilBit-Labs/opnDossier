package schema

import (
	"encoding/xml"
	"testing"
)

// newTestIDs creates an IDS with the given general field values for testing.
func newTestIDs(opts func(ids *IDS)) *IDS {
	ids := &IDS{}
	opts(ids)
	return ids
}

func TestStringPtr(t *testing.T) {
	t.Parallel()

	s := StringPtr("hello")
	if s == nil {
		t.Fatal("StringPtr returned nil")
	}
	if *s != "hello" {
		t.Errorf("StringPtr() = %q, want %q", *s, "hello")
	}

	empty := StringPtr("")
	if empty == nil {
		t.Fatal("StringPtr(\"\") returned nil")
	}
	if *empty != "" {
		t.Errorf("StringPtr(\"\") = %q, want %q", *empty, "")
	}
}

//nolint:dupl // Source/Destination IsAny tests are structurally similar by design
func TestSource_IsAny(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		src  Source
		want bool
	}{
		{name: "nil any", src: Source{}, want: false},
		{name: "empty string any", src: Source{Any: StringPtr("")}, want: true},
		{name: "non-empty any", src: Source{Any: StringPtr("1")}, want: true},
		{name: "network only", src: Source{Network: "lan"}, want: false},
		{name: "address only", src: Source{Address: "192.168.1.0/24"}, want: false},
		{name: "address with not", src: Source{Address: "10.0.0.0/8", Not: BoolFlag(true)}, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.src.IsAny(); got != tt.want {
				t.Errorf("Source.IsAny() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSource_Equal(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		a, b Source
		want bool
	}{
		{name: "both zero", a: Source{}, b: Source{}, want: true},
		{name: "both any nil", a: Source{Network: "lan"}, b: Source{Network: "lan"}, want: true},
		{name: "different network", a: Source{Network: "lan"}, b: Source{Network: "wan"}, want: false},
		{name: "one any nil other not", a: Source{}, b: Source{Any: StringPtr("")}, want: false},
		{name: "both any present same value", a: Source{Any: StringPtr("")}, b: Source{Any: StringPtr("")}, want: true},
		{
			name: "both any present different values",
			a:    Source{Any: StringPtr("")},
			b:    Source{Any: StringPtr("1")},
			want: true,
		},
		{name: "any presence differs", a: Source{Any: StringPtr("1")}, b: Source{Network: "lan"}, want: false},
		{name: "same address", a: Source{Address: "192.168.1.0/24"}, b: Source{Address: "192.168.1.0/24"}, want: true},
		{
			name: "different address",
			a:    Source{Address: "192.168.1.0/24"},
			b:    Source{Address: "10.0.0.0/8"},
			want: false,
		},
		{
			name: "same port",
			a:    Source{Network: "lan", Port: "8080"},
			b:    Source{Network: "lan", Port: "8080"},
			want: true,
		},
		{
			name: "different port",
			a:    Source{Network: "lan", Port: "80"},
			b:    Source{Network: "lan", Port: "443"},
			want: false,
		},
		{
			name: "same not flag",
			a:    Source{Network: "lan", Not: BoolFlag(true)},
			b:    Source{Network: "lan", Not: BoolFlag(true)},
			want: true,
		},
		{
			name: "different not flag",
			a:    Source{Network: "lan", Not: BoolFlag(true)},
			b:    Source{Network: "lan"},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.a.Equal(tt.b); got != tt.want {
				t.Errorf("Source.Equal() = %v, want %v", got, tt.want)
			}
		})
	}
}

//nolint:dupl // Source/Destination EffectiveAddress tests are structurally similar by design
func TestSource_EffectiveAddress(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		src  Source
		want string
	}{
		{
			name: "network takes priority",
			src:  Source{Network: "lan", Address: "192.168.1.0/24", Any: StringPtr("")},
			want: "lan",
		},
		{
			name: "address when no network",
			src:  Source{Address: "192.168.1.0/24", Any: StringPtr("")},
			want: "192.168.1.0/24",
		},
		{name: "any when no network or address", src: Source{Any: StringPtr("")}, want: "any"},
		{name: "empty when nothing set", src: Source{}, want: ""},
		{name: "network only", src: Source{Network: "wan"}, want: "wan"},
		{name: "address only", src: Source{Address: "10.0.0.5"}, want: "10.0.0.5"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.src.EffectiveAddress(); got != tt.want {
				t.Errorf("Source.EffectiveAddress() = %q, want %q", got, tt.want)
			}
		})
	}
}

//nolint:dupl // Source/Destination IsAny tests are structurally similar by design
func TestDestination_IsAny(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		dst  Destination
		want bool
	}{
		{name: "nil any", dst: Destination{}, want: false},
		{name: "empty string any", dst: Destination{Any: StringPtr("")}, want: true},
		{name: "non-empty any", dst: Destination{Any: StringPtr("1")}, want: true},
		{name: "network only", dst: Destination{Network: "lan"}, want: false},
		{name: "address only", dst: Destination{Address: "10.0.0.1"}, want: false},
		{name: "address with not", dst: Destination{Address: "10.0.0.0/8", Not: BoolFlag(true)}, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.dst.IsAny(); got != tt.want {
				t.Errorf("Destination.IsAny() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDestination_Equal(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		a, b Destination
		want bool
	}{
		{name: "both zero", a: Destination{}, b: Destination{}, want: true},
		{
			name: "same network and port",
			a:    Destination{Network: "lan", Port: "443"},
			b:    Destination{Network: "lan", Port: "443"},
			want: true,
		},
		{name: "different network", a: Destination{Network: "lan"}, b: Destination{Network: "wan"}, want: false},
		{name: "different port", a: Destination{Port: "80"}, b: Destination{Port: "443"}, want: false},
		{name: "one any nil other not", a: Destination{}, b: Destination{Any: StringPtr("")}, want: false},
		{
			name: "both any present same value",
			a:    Destination{Any: StringPtr("")},
			b:    Destination{Any: StringPtr("")},
			want: true,
		},
		{
			name: "both any present different values",
			a:    Destination{Any: StringPtr("")},
			b:    Destination{Any: StringPtr("1")},
			want: true,
		},
		{
			name: "any with port match",
			a:    Destination{Any: StringPtr(""), Port: "22"},
			b:    Destination{Any: StringPtr("1"), Port: "22"},
			want: true,
		},
		{
			name: "any with port mismatch",
			a:    Destination{Any: StringPtr(""), Port: "22"},
			b:    Destination{Any: StringPtr(""), Port: "80"},
			want: false,
		},
		{
			name: "same address",
			a:    Destination{Address: "192.168.1.0/24", Port: "443"},
			b:    Destination{Address: "192.168.1.0/24", Port: "443"},
			want: true,
		},
		{
			name: "different address",
			a:    Destination{Address: "192.168.1.0/24"},
			b:    Destination{Address: "10.0.0.0/8"},
			want: false,
		},
		{
			name: "same not flag",
			a:    Destination{Network: "lan", Not: BoolFlag(true)},
			b:    Destination{Network: "lan", Not: BoolFlag(true)},
			want: true,
		},
		{
			name: "different not flag",
			a:    Destination{Network: "lan", Not: BoolFlag(true)},
			b:    Destination{Network: "lan"},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.a.Equal(tt.b); got != tt.want {
				t.Errorf("Destination.Equal() = %v, want %v", got, tt.want)
			}
		})
	}
}

//nolint:dupl // Source/Destination EffectiveAddress tests are structurally similar by design
func TestDestination_EffectiveAddress(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		dst  Destination
		want string
	}{
		{
			name: "network takes priority",
			dst:  Destination{Network: "lan", Address: "192.168.1.0/24", Any: StringPtr("")},
			want: "lan",
		},
		{
			name: "address when no network",
			dst:  Destination{Address: "192.168.1.0/24", Any: StringPtr("")},
			want: "192.168.1.0/24",
		},
		{name: "any when no network or address", dst: Destination{Any: StringPtr("")}, want: "any"},
		{name: "empty when nothing set", dst: Destination{}, want: ""},
		{name: "network only", dst: Destination{Network: "wan"}, want: "wan"},
		{name: "address only", dst: Destination{Address: "10.0.0.5"}, want: "10.0.0.5"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.dst.EffectiveAddress(); got != tt.want {
				t.Errorf("Destination.EffectiveAddress() = %q, want %q", got, tt.want)
			}
		})
	}
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

func TestSource_XMLRoundTrip(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		xml  string
		want Source
	}{
		{
			name: "any self-closing",
			xml:  `<source><any/></source>`,
			want: Source{Any: StringPtr("")},
		},
		{
			name: "network only",
			xml:  `<source><network>lan</network></source>`,
			want: Source{Network: "lan"},
		},
		{
			name: "address IP/CIDR",
			xml:  `<source><address>192.168.1.0/24</address></source>`,
			want: Source{Address: "192.168.1.0/24"},
		},
		{
			name: "address alias",
			xml:  `<source><address>MyAlias</address></source>`,
			want: Source{Address: "MyAlias"},
		},
		{
			name: "negated network",
			xml:  `<source><not/><network>lan</network></source>`,
			want: Source{Network: "lan", Not: BoolFlag(true)},
		},
		{
			name: "network with port",
			xml:  `<source><network>lan</network><port>8080</port></source>`,
			want: Source{Network: "lan", Port: "8080"},
		},
		{
			name: "negated address with port",
			xml:  `<source><not/><address>10.0.0.0/8</address><port>22</port></source>`,
			want: Source{Address: "10.0.0.0/8", Port: "22", Not: BoolFlag(true)},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var got Source
			if err := xml.Unmarshal([]byte(tt.xml), &got); err != nil {
				t.Fatalf("xml.Unmarshal() error = %v", err)
			}
			if !got.Equal(tt.want) {
				t.Errorf("xml.Unmarshal() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestDestination_XMLRoundTrip(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		xml  string
		want Destination
	}{
		{
			name: "any self-closing",
			xml:  `<destination><any/></destination>`,
			want: Destination{Any: StringPtr("")},
		},
		{
			name: "network with port",
			xml:  `<destination><network>wan</network><port>443</port></destination>`,
			want: Destination{Network: "wan", Port: "443"},
		},
		{
			name: "address IP/CIDR",
			xml:  `<destination><address>10.0.0.1</address></destination>`,
			want: Destination{Address: "10.0.0.1"},
		},
		{
			name: "any with port range",
			xml:  `<destination><any/><port>8000-9000</port></destination>`,
			want: Destination{Any: StringPtr(""), Port: "8000-9000"},
		},
		{
			name: "negated network with port",
			xml:  `<destination><not/><network>lan</network><port>22</port></destination>`,
			want: Destination{Network: "lan", Port: "22", Not: BoolFlag(true)},
		},
		{
			name: "address alias",
			xml:  `<destination><address>WebServers</address><port>80</port></destination>`,
			want: Destination{Address: "WebServers", Port: "80"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var got Destination
			if err := xml.Unmarshal([]byte(tt.xml), &got); err != nil {
				t.Fatalf("xml.Unmarshal() error = %v", err)
			}
			if !got.Equal(tt.want) {
				t.Errorf("xml.Unmarshal() = %+v, want %+v", got, tt.want)
			}
		})
	}
}
