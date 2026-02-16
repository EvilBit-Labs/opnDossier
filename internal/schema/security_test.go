package schema

import (
	"encoding/xml"
	"strings"
	"testing"
)

// Test constants for commonly repeated string literals.
const (
	floatingYes   = "yes"            // OPNsense XML value indicating a floating firewall rule
	testWAN       = "wan"            // Common test interface name
	testInet      = "inet"           // IPv4 protocol family
	testTCP       = "tcp"            // TCP protocol
	testPortRange = "1024-65535"     // Common ephemeral port range
	testAdminUser = "admin@10.0.0.1" // Test admin username for NAT rule tests
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

//nolint:dupl // Source/Destination XMLRoundTrip tests are structurally similar by design
func TestSource_XMLRoundTrip(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		xml          string
		want         Source
		wantElements []string // substrings expected in marshaled XML
	}{
		{
			name:         "any self-closing",
			xml:          `<source><any/></source>`,
			want:         Source{Any: StringPtr("")},
			wantElements: []string{"<any>"},
		},
		{
			name:         "network only",
			xml:          `<source><network>lan</network></source>`,
			want:         Source{Network: "lan"},
			wantElements: []string{"<network>lan</network>"},
		},
		{
			name:         "address IP/CIDR",
			xml:          `<source><address>192.168.1.0/24</address></source>`,
			want:         Source{Address: "192.168.1.0/24"},
			wantElements: []string{"<address>192.168.1.0/24</address>"},
		},
		{
			name:         "address alias",
			xml:          `<source><address>MyAlias</address></source>`,
			want:         Source{Address: "MyAlias"},
			wantElements: []string{"<address>MyAlias</address>"},
		},
		{
			name:         "negated network",
			xml:          `<source><not/><network>lan</network></source>`,
			want:         Source{Network: "lan", Not: BoolFlag(true)},
			wantElements: []string{"<not>", "<network>lan</network>"},
		},
		{
			name:         "network with port",
			xml:          `<source><network>lan</network><port>8080</port></source>`,
			want:         Source{Network: "lan", Port: "8080"},
			wantElements: []string{"<network>lan</network>", "<port>8080</port>"},
		},
		{
			name:         "negated address with port",
			xml:          `<source><not/><address>10.0.0.0/8</address><port>22</port></source>`,
			want:         Source{Address: "10.0.0.0/8", Port: "22", Not: BoolFlag(true)},
			wantElements: []string{"<not>", "<address>10.0.0.0/8</address>", "<port>22</port>"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// Unmarshal from input XML and verify
			var got Source
			if err := xml.Unmarshal([]byte(tt.xml), &got); err != nil {
				t.Fatalf("xml.Unmarshal() error = %v", err)
			}
			if !got.Equal(tt.want) {
				t.Errorf("xml.Unmarshal() = %+v, want %+v", got, tt.want)
			}

			// Marshal the expected struct
			marshaled, err := xml.Marshal(tt.want)
			if err != nil {
				t.Fatalf("xml.Marshal() error = %v", err)
			}
			marshaledStr := string(marshaled)

			// Verify expected elements are present in marshaled XML
			for _, elem := range tt.wantElements {
				if !strings.Contains(marshaledStr, elem) {
					t.Errorf("marshaled XML %q does not contain expected element %q", marshaledStr, elem)
				}
			}

			// Unmarshal marshaled XML back and compare
			var roundTripped Source
			if err := xml.Unmarshal(marshaled, &roundTripped); err != nil {
				t.Fatalf("round-trip xml.Unmarshal() error = %v", err)
			}
			if !roundTripped.Equal(tt.want) {
				t.Errorf("round-trip result = %+v, want %+v", roundTripped, tt.want)
			}
		})
	}
}

//nolint:dupl // Source/Destination XMLRoundTrip tests are structurally similar by design
func TestDestination_XMLRoundTrip(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		xml          string
		want         Destination
		wantElements []string // substrings expected in marshaled XML
	}{
		{
			name:         "any self-closing",
			xml:          `<destination><any/></destination>`,
			want:         Destination{Any: StringPtr("")},
			wantElements: []string{"<any>"},
		},
		{
			name:         "network with port",
			xml:          `<destination><network>wan</network><port>443</port></destination>`,
			want:         Destination{Network: "wan", Port: "443"},
			wantElements: []string{"<network>wan</network>", "<port>443</port>"},
		},
		{
			name:         "address IP/CIDR",
			xml:          `<destination><address>10.0.0.1</address></destination>`,
			want:         Destination{Address: "10.0.0.1"},
			wantElements: []string{"<address>10.0.0.1</address>"},
		},
		{
			name:         "any with port range",
			xml:          `<destination><any/><port>8000-9000</port></destination>`,
			want:         Destination{Any: StringPtr(""), Port: "8000-9000"},
			wantElements: []string{"<any>", "<port>8000-9000</port>"},
		},
		{
			name:         "negated network with port",
			xml:          `<destination><not/><network>lan</network><port>22</port></destination>`,
			want:         Destination{Network: "lan", Port: "22", Not: BoolFlag(true)},
			wantElements: []string{"<not>", "<network>lan</network>", "<port>22</port>"},
		},
		{
			name:         "address alias",
			xml:          `<destination><address>WebServers</address><port>80</port></destination>`,
			want:         Destination{Address: "WebServers", Port: "80"},
			wantElements: []string{"<address>WebServers</address>", "<port>80</port>"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// Unmarshal from input XML and verify
			var got Destination
			if err := xml.Unmarshal([]byte(tt.xml), &got); err != nil {
				t.Fatalf("xml.Unmarshal() error = %v", err)
			}
			if !got.Equal(tt.want) {
				t.Errorf("xml.Unmarshal() = %+v, want %+v", got, tt.want)
			}

			// Marshal the expected struct
			marshaled, err := xml.Marshal(tt.want)
			if err != nil {
				t.Fatalf("xml.Marshal() error = %v", err)
			}
			marshaledStr := string(marshaled)

			// Verify expected elements are present in marshaled XML
			for _, elem := range tt.wantElements {
				if !strings.Contains(marshaledStr, elem) {
					t.Errorf("marshaled XML %q does not contain expected element %q", marshaledStr, elem)
				}
			}

			// Unmarshal marshaled XML back and compare
			var roundTripped Destination
			if err := xml.Unmarshal(marshaled, &roundTripped); err != nil {
				t.Fatalf("round-trip xml.Unmarshal() error = %v", err)
			}
			if !roundTripped.Equal(tt.want) {
				t.Errorf("round-trip result = %+v, want %+v", roundTripped, tt.want)
			}
		})
	}
}

func TestRule_BoolFlagFields_XMLRoundTrip(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		xml          string
		wantDisabled BoolFlag
		wantQuick    BoolFlag
		wantLog      BoolFlag
	}{
		{
			name:         "all presence flags set",
			xml:          `<rule><disabled/><quick/><log/></rule>`,
			wantDisabled: true,
			wantQuick:    true,
			wantLog:      true,
		},
		{
			name:         "no presence flags",
			xml:          `<rule></rule>`,
			wantDisabled: false,
			wantQuick:    false,
			wantLog:      false,
		},
		{
			name:         "only disabled",
			xml:          `<rule><disabled/></rule>`,
			wantDisabled: true,
			wantQuick:    false,
			wantLog:      false,
		},
		{
			name:         "only log",
			xml:          `<rule><log/></rule>`,
			wantDisabled: false,
			wantQuick:    false,
			wantLog:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var got Rule
			if err := xml.Unmarshal([]byte(tt.xml), &got); err != nil {
				t.Fatalf("xml.Unmarshal() error = %v", err)
			}
			if got.Disabled != tt.wantDisabled {
				t.Errorf("Disabled = %v, want %v", got.Disabled, tt.wantDisabled)
			}
			if got.Quick != tt.wantQuick {
				t.Errorf("Quick = %v, want %v", got.Quick, tt.wantQuick)
			}
			if got.Log != tt.wantLog {
				t.Errorf("Log = %v, want %v", got.Log, tt.wantLog)
			}
		})
	}
}

func TestRule_NewStringFields_XMLRoundTrip(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		xml          string
		wantFloating string
		wantGateway  string
		wantTracker  string
	}{
		{
			name:         "all string fields set",
			xml:          `<rule><floating>yes</floating><gateway>WAN_GW</gateway><tracker>12345</tracker></rule>`,
			wantFloating: floatingYes,
			wantGateway:  "WAN_GW",
			wantTracker:  "12345",
		},
		{
			name:         "no string fields",
			xml:          `<rule></rule>`,
			wantFloating: "",
			wantGateway:  "",
			wantTracker:  "",
		},
		{
			name:         "only gateway",
			xml:          `<rule><gateway>LAN_GW</gateway></rule>`,
			wantFloating: "",
			wantGateway:  "LAN_GW",
			wantTracker:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var got Rule
			if err := xml.Unmarshal([]byte(tt.xml), &got); err != nil {
				t.Fatalf("xml.Unmarshal() error = %v", err)
			}
			if got.Floating != tt.wantFloating {
				t.Errorf("Floating = %q, want %q", got.Floating, tt.wantFloating)
			}
			if got.Gateway != tt.wantGateway {
				t.Errorf("Gateway = %q, want %q", got.Gateway, tt.wantGateway)
			}
			if got.Tracker != tt.wantTracker {
				t.Errorf("Tracker = %q, want %q", got.Tracker, tt.wantTracker)
			}
		})
	}
}

//nolint:dupl // StateTypeDirection/ICMP tests are structurally similar by design (two string fields each)
func TestRule_StateTypeAndDirection_XMLRoundTrip(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		xml           string
		wantStateType string
		wantDirection string
	}{
		{
			name:          "keep state",
			xml:           `<rule><statetype>keep state</statetype></rule>`,
			wantStateType: "keep state",
			wantDirection: "",
		},
		{
			name:          "sloppy state",
			xml:           `<rule><statetype>sloppy state</statetype></rule>`,
			wantStateType: "sloppy state",
			wantDirection: "",
		},
		{
			name:          "synproxy state",
			xml:           `<rule><statetype>synproxy state</statetype></rule>`,
			wantStateType: "synproxy state",
			wantDirection: "",
		},
		{
			name:          "none state",
			xml:           `<rule><statetype>none</statetype></rule>`,
			wantStateType: "none",
			wantDirection: "",
		},
		{
			name:          "empty statetype",
			xml:           `<rule><statetype></statetype></rule>`,
			wantStateType: "",
			wantDirection: "",
		},
		{
			name:          "direction in",
			xml:           `<rule><direction>in</direction></rule>`,
			wantStateType: "",
			wantDirection: "in",
		},
		{
			name:          "direction out",
			xml:           `<rule><direction>out</direction></rule>`,
			wantStateType: "",
			wantDirection: "out",
		},
		{
			name:          "direction any",
			xml:           `<rule><direction>any</direction></rule>`,
			wantStateType: "",
			wantDirection: "any",
		},
		{
			name:          "empty direction",
			xml:           `<rule><direction></direction></rule>`,
			wantStateType: "",
			wantDirection: "",
		},
		{
			name:          "both fields present",
			xml:           `<rule><statetype>keep state</statetype><direction>in</direction></rule>`,
			wantStateType: "keep state",
			wantDirection: "in",
		},
		{
			name:          "statetype without direction",
			xml:           `<rule><statetype>sloppy state</statetype></rule>`,
			wantStateType: "sloppy state",
			wantDirection: "",
		},
		{
			name:          "direction without statetype",
			xml:           `<rule><direction>out</direction></rule>`,
			wantStateType: "",
			wantDirection: "out",
		},
		{
			name:          "neither field present",
			xml:           `<rule></rule>`,
			wantStateType: "",
			wantDirection: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// Unmarshal and verify field values
			var got Rule
			if err := xml.Unmarshal([]byte(tt.xml), &got); err != nil {
				t.Fatalf("xml.Unmarshal() error = %v", err)
			}
			if got.StateType != tt.wantStateType {
				t.Errorf("StateType = %q, want %q", got.StateType, tt.wantStateType)
			}
			if got.Direction != tt.wantDirection {
				t.Errorf("Direction = %q, want %q", got.Direction, tt.wantDirection)
			}

			// Round-trip: marshal → unmarshal → compare
			marshaled, err := xml.Marshal(got)
			if err != nil {
				t.Fatalf("xml.Marshal() error = %v", err)
			}
			var roundTripped Rule
			if err := xml.Unmarshal(marshaled, &roundTripped); err != nil {
				t.Fatalf("round-trip xml.Unmarshal() error = %v", err)
			}
			if roundTripped.StateType != tt.wantStateType {
				t.Errorf("round-trip StateType = %q, want %q", roundTripped.StateType, tt.wantStateType)
			}
			if roundTripped.Direction != tt.wantDirection {
				t.Errorf("round-trip Direction = %q, want %q", roundTripped.Direction, tt.wantDirection)
			}
		})
	}
}

func TestRule_FloatingRules_XMLRoundTrip(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		xml          string
		wantFloating string
		wantDir      string
		wantGateway  string
		wantQuick    BoolFlag
		wantLog      BoolFlag
		wantTracker  string
		wantState    string
	}{
		{
			name:         "floating in with gateway and quick",
			xml:          `<rule><floating>yes</floating><direction>in</direction><gateway>WAN_GW</gateway><quick/></rule>`,
			wantFloating: floatingYes,
			wantDir:      "in",
			wantGateway:  "WAN_GW",
			wantQuick:    true,
		},
		{
			name:         "floating out no gateway",
			xml:          `<rule><floating>yes</floating><direction>out</direction></rule>`,
			wantFloating: floatingYes,
			wantDir:      "out",
		},
		{
			name:         "floating any with gateway",
			xml:          `<rule><floating>yes</floating><direction>any</direction><gateway>LAN_GW</gateway></rule>`,
			wantFloating: floatingYes,
			wantDir:      "any",
			wantGateway:  "LAN_GW",
		},
		{
			name:         "non-floating with direction and gateway",
			xml:          `<rule><direction>in</direction><gateway>WAN_GW</gateway></rule>`,
			wantFloating: "",
			wantDir:      "in",
			wantGateway:  "WAN_GW",
		},
		{
			name: "floating with all optional fields",
			xml: `<rule><floating>yes</floating><direction>in</direction>` +
				`<gateway>WAN_GW</gateway><tracker>98765</tracker>` +
				`<statetype>keep state</statetype><quick/><log/></rule>`,
			wantFloating: floatingYes,
			wantDir:      "in",
			wantGateway:  "WAN_GW",
			wantQuick:    true,
			wantLog:      true,
			wantTracker:  "98765",
			wantState:    "keep state",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var got Rule
			if err := xml.Unmarshal([]byte(tt.xml), &got); err != nil {
				t.Fatalf("xml.Unmarshal() error = %v", err)
			}
			if got.Floating != tt.wantFloating {
				t.Errorf("Floating = %q, want %q", got.Floating, tt.wantFloating)
			}
			if got.Direction != tt.wantDir {
				t.Errorf("Direction = %q, want %q", got.Direction, tt.wantDir)
			}
			if got.Gateway != tt.wantGateway {
				t.Errorf("Gateway = %q, want %q", got.Gateway, tt.wantGateway)
			}
			if got.Quick != tt.wantQuick {
				t.Errorf("Quick = %v, want %v", got.Quick, tt.wantQuick)
			}
			if got.Log != tt.wantLog {
				t.Errorf("Log = %v, want %v", got.Log, tt.wantLog)
			}
			if got.Tracker != tt.wantTracker {
				t.Errorf("Tracker = %q, want %q", got.Tracker, tt.wantTracker)
			}
			if got.StateType != tt.wantState {
				t.Errorf("StateType = %q, want %q", got.StateType, tt.wantState)
			}

			// Round-trip validation
			marshaled, err := xml.Marshal(got)
			if err != nil {
				t.Fatalf("xml.Marshal() error = %v", err)
			}
			var roundTripped Rule
			if err := xml.Unmarshal(marshaled, &roundTripped); err != nil {
				t.Fatalf("round-trip xml.Unmarshal() error = %v", err)
			}
			if roundTripped.Floating != tt.wantFloating {
				t.Errorf("round-trip Floating = %q, want %q", roundTripped.Floating, tt.wantFloating)
			}
			if roundTripped.Direction != tt.wantDir {
				t.Errorf("round-trip Direction = %q, want %q", roundTripped.Direction, tt.wantDir)
			}
			if roundTripped.Gateway != tt.wantGateway {
				t.Errorf("round-trip Gateway = %q, want %q", roundTripped.Gateway, tt.wantGateway)
			}
			if roundTripped.Quick != tt.wantQuick {
				t.Errorf("round-trip Quick = %v, want %v", roundTripped.Quick, tt.wantQuick)
			}
			if roundTripped.Log != tt.wantLog {
				t.Errorf("round-trip Log = %v, want %v", roundTripped.Log, tt.wantLog)
			}
			if roundTripped.Tracker != tt.wantTracker {
				t.Errorf("round-trip Tracker = %q, want %q", roundTripped.Tracker, tt.wantTracker)
			}
			if roundTripped.StateType != tt.wantState {
				t.Errorf("round-trip StateType = %q, want %q", roundTripped.StateType, tt.wantState)
			}
		})
	}
}

//nolint:dupl // Rule/NATRule round-trip test loops are structurally similar by design
func TestRule_RateLimitingFields_XMLRoundTrip(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name                string
		xml                 string
		wantMaxSrcNodes     string
		wantMaxSrcConn      string
		wantMaxSrcConnRate  string
		wantMaxSrcConnRates string
	}{
		{
			name: "all rate-limiting fields set",
			xml: `<rule>` +
				`<max-src-nodes>100</max-src-nodes>` +
				`<max-src-conn>50</max-src-conn>` +
				`<max-src-conn-rate>10/second</max-src-conn-rate>` +
				`<max-src-conn-rates>15</max-src-conn-rates>` +
				`</rule>`,
			wantMaxSrcNodes:     "100",
			wantMaxSrcConn:      "50",
			wantMaxSrcConnRate:  "10/second",
			wantMaxSrcConnRates: "15",
		},
		{
			name:                "no rate-limiting fields",
			xml:                 `<rule></rule>`,
			wantMaxSrcNodes:     "",
			wantMaxSrcConn:      "",
			wantMaxSrcConnRate:  "",
			wantMaxSrcConnRates: "",
		},
		{
			name:                "only max-src-nodes",
			xml:                 `<rule><max-src-nodes>200</max-src-nodes></rule>`,
			wantMaxSrcNodes:     "200",
			wantMaxSrcConn:      "",
			wantMaxSrcConnRate:  "",
			wantMaxSrcConnRates: "",
		},
		{
			name:                "only max-src-conn",
			xml:                 `<rule><max-src-conn>25</max-src-conn></rule>`,
			wantMaxSrcNodes:     "",
			wantMaxSrcConn:      "25",
			wantMaxSrcConnRate:  "",
			wantMaxSrcConnRates: "",
		},
		{
			name:                "only max-src-conn-rate",
			xml:                 `<rule><max-src-conn-rate>5/second</max-src-conn-rate></rule>`,
			wantMaxSrcNodes:     "",
			wantMaxSrcConn:      "",
			wantMaxSrcConnRate:  "5/second",
			wantMaxSrcConnRates: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var got Rule
			if err := xml.Unmarshal([]byte(tt.xml), &got); err != nil {
				t.Fatalf("xml.Unmarshal() error = %v", err)
			}
			if got.MaxSrcNodes != tt.wantMaxSrcNodes {
				t.Errorf("MaxSrcNodes = %q, want %q", got.MaxSrcNodes, tt.wantMaxSrcNodes)
			}
			if got.MaxSrcConn != tt.wantMaxSrcConn {
				t.Errorf("MaxSrcConn = %q, want %q", got.MaxSrcConn, tt.wantMaxSrcConn)
			}
			if got.MaxSrcConnRate != tt.wantMaxSrcConnRate {
				t.Errorf("MaxSrcConnRate = %q, want %q", got.MaxSrcConnRate, tt.wantMaxSrcConnRate)
			}
			if got.MaxSrcConnRates != tt.wantMaxSrcConnRates {
				t.Errorf("MaxSrcConnRates = %q, want %q", got.MaxSrcConnRates, tt.wantMaxSrcConnRates)
			}

			// Round-trip: marshal → unmarshal → compare
			marshaled, err := xml.Marshal(got)
			if err != nil {
				t.Fatalf("xml.Marshal() error = %v", err)
			}
			var roundTripped Rule
			if err := xml.Unmarshal(marshaled, &roundTripped); err != nil {
				t.Fatalf("round-trip xml.Unmarshal() error = %v", err)
			}
			if roundTripped.MaxSrcNodes != tt.wantMaxSrcNodes {
				t.Errorf("round-trip MaxSrcNodes = %q, want %q", roundTripped.MaxSrcNodes, tt.wantMaxSrcNodes)
			}
			if roundTripped.MaxSrcConn != tt.wantMaxSrcConn {
				t.Errorf("round-trip MaxSrcConn = %q, want %q", roundTripped.MaxSrcConn, tt.wantMaxSrcConn)
			}
			if roundTripped.MaxSrcConnRate != tt.wantMaxSrcConnRate {
				t.Errorf("round-trip MaxSrcConnRate = %q, want %q", roundTripped.MaxSrcConnRate, tt.wantMaxSrcConnRate)
			}
			if roundTripped.MaxSrcConnRates != tt.wantMaxSrcConnRates {
				t.Errorf(
					"round-trip MaxSrcConnRates = %q, want %q",
					roundTripped.MaxSrcConnRates,
					tt.wantMaxSrcConnRates,
				)
			}
		})
	}
}

func TestRule_TCPFlags_XMLRoundTrip(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name            string
		xml             string
		wantTCPFlags1   string
		wantTCPFlags2   string
		wantTCPFlagsAny BoolFlag
	}{
		{
			name:            "flags1 and flags2 set",
			xml:             `<rule><tcpflags1>S/SA</tcpflags1><tcpflags2>FSRPAUEW</tcpflags2></rule>`,
			wantTCPFlags1:   "S/SA",
			wantTCPFlags2:   "FSRPAUEW",
			wantTCPFlagsAny: false,
		},
		{
			name:            "tcpflags_any set",
			xml:             `<rule><tcpflags_any/></rule>`,
			wantTCPFlags1:   "",
			wantTCPFlags2:   "",
			wantTCPFlagsAny: true,
		},
		{
			name:            "all TCP flag fields set",
			xml:             `<rule><tcpflags1>SA</tcpflags1><tcpflags2>SA</tcpflags2><tcpflags_any/></rule>`,
			wantTCPFlags1:   "SA",
			wantTCPFlags2:   "SA",
			wantTCPFlagsAny: true,
		},
		{
			name:            "no TCP flag fields",
			xml:             `<rule></rule>`,
			wantTCPFlags1:   "",
			wantTCPFlags2:   "",
			wantTCPFlagsAny: false,
		},
		{
			name:            "only tcpflags1",
			xml:             `<rule><tcpflags1>S</tcpflags1></rule>`,
			wantTCPFlags1:   "S",
			wantTCPFlags2:   "",
			wantTCPFlagsAny: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var got Rule
			if err := xml.Unmarshal([]byte(tt.xml), &got); err != nil {
				t.Fatalf("xml.Unmarshal() error = %v", err)
			}
			if got.TCPFlags1 != tt.wantTCPFlags1 {
				t.Errorf("TCPFlags1 = %q, want %q", got.TCPFlags1, tt.wantTCPFlags1)
			}
			if got.TCPFlags2 != tt.wantTCPFlags2 {
				t.Errorf("TCPFlags2 = %q, want %q", got.TCPFlags2, tt.wantTCPFlags2)
			}
			if got.TCPFlagsAny != tt.wantTCPFlagsAny {
				t.Errorf("TCPFlagsAny = %v, want %v", got.TCPFlagsAny, tt.wantTCPFlagsAny)
			}

			// Round-trip: marshal → unmarshal → compare
			marshaled, err := xml.Marshal(got)
			if err != nil {
				t.Fatalf("xml.Marshal() error = %v", err)
			}
			var roundTripped Rule
			if err := xml.Unmarshal(marshaled, &roundTripped); err != nil {
				t.Fatalf("round-trip xml.Unmarshal() error = %v", err)
			}
			if roundTripped.TCPFlags1 != tt.wantTCPFlags1 {
				t.Errorf("round-trip TCPFlags1 = %q, want %q", roundTripped.TCPFlags1, tt.wantTCPFlags1)
			}
			if roundTripped.TCPFlags2 != tt.wantTCPFlags2 {
				t.Errorf("round-trip TCPFlags2 = %q, want %q", roundTripped.TCPFlags2, tt.wantTCPFlags2)
			}
			if roundTripped.TCPFlagsAny != tt.wantTCPFlagsAny {
				t.Errorf("round-trip TCPFlagsAny = %v, want %v", roundTripped.TCPFlagsAny, tt.wantTCPFlagsAny)
			}
		})
	}
}

//nolint:dupl // ICMP/StateTypeDirection tests are structurally similar by design (two string fields each)
func TestRule_ICMPTypes_XMLRoundTrip(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		xml           string
		wantICMPType  string
		wantICMP6Type string
	}{
		{
			name:          "single ICMP type",
			xml:           `<rule><icmptype>8</icmptype></rule>`,
			wantICMPType:  "8",
			wantICMP6Type: "",
		},
		{
			name:          "comma-separated ICMP types",
			xml:           `<rule><icmptype>3,11,0</icmptype></rule>`,
			wantICMPType:  "3,11,0",
			wantICMP6Type: "",
		},
		{
			name:          "ICMPv6 type",
			xml:           `<rule><icmp6-type>128</icmp6-type></rule>`,
			wantICMPType:  "",
			wantICMP6Type: "128",
		},
		{
			name:          "both ICMP and ICMPv6 types",
			xml:           `<rule><icmptype>8</icmptype><icmp6-type>128</icmp6-type></rule>`,
			wantICMPType:  "8",
			wantICMP6Type: "128",
		},
		{
			name:          "no ICMP fields",
			xml:           `<rule></rule>`,
			wantICMPType:  "",
			wantICMP6Type: "",
		},
		{
			name:          "multiple ICMPv6 types",
			xml:           `<rule><icmp6-type>128,129,1</icmp6-type></rule>`,
			wantICMPType:  "",
			wantICMP6Type: "128,129,1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var got Rule
			if err := xml.Unmarshal([]byte(tt.xml), &got); err != nil {
				t.Fatalf("xml.Unmarshal() error = %v", err)
			}
			if got.ICMPType != tt.wantICMPType {
				t.Errorf("ICMPType = %q, want %q", got.ICMPType, tt.wantICMPType)
			}
			if got.ICMP6Type != tt.wantICMP6Type {
				t.Errorf("ICMP6Type = %q, want %q", got.ICMP6Type, tt.wantICMP6Type)
			}

			// Round-trip: marshal → unmarshal → compare
			marshaled, err := xml.Marshal(got)
			if err != nil {
				t.Fatalf("xml.Marshal() error = %v", err)
			}
			var roundTripped Rule
			if err := xml.Unmarshal(marshaled, &roundTripped); err != nil {
				t.Fatalf("round-trip xml.Unmarshal() error = %v", err)
			}
			if roundTripped.ICMPType != tt.wantICMPType {
				t.Errorf("round-trip ICMPType = %q, want %q", roundTripped.ICMPType, tt.wantICMPType)
			}
			if roundTripped.ICMP6Type != tt.wantICMP6Type {
				t.Errorf("round-trip ICMP6Type = %q, want %q", roundTripped.ICMP6Type, tt.wantICMP6Type)
			}
		})
	}
}

//nolint:dupl // Rule/InboundRule round-trip test loops are structurally similar by design
func TestRule_StateAndAdvancedFields_XMLRoundTrip(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name               string
		xml                string
		wantStateTimeout   string
		wantAllowOpts      BoolFlag
		wantDisableReplyTo BoolFlag
		wantNoPfSync       BoolFlag
		wantNoSync         BoolFlag
	}{
		{
			name:             "state timeout only",
			xml:              `<rule><statetimeout>3600</statetimeout></rule>`,
			wantStateTimeout: "3600",
		},
		{
			name:          "allowopts only",
			xml:           `<rule><allowopts/></rule>`,
			wantAllowOpts: true,
		},
		{
			name:               "disablereplyto only",
			xml:                `<rule><disablereplyto/></rule>`,
			wantDisableReplyTo: true,
		},
		{
			name:         "nopfsync only",
			xml:          `<rule><nopfsync/></rule>`,
			wantNoPfSync: true,
		},
		{
			name:       "nosync only",
			xml:        `<rule><nosync/></rule>`,
			wantNoSync: true,
		},
		{
			name:               "all BoolFlag fields set",
			xml:                `<rule><allowopts/><disablereplyto/><nopfsync/><nosync/></rule>`,
			wantAllowOpts:      true,
			wantDisableReplyTo: true,
			wantNoPfSync:       true,
			wantNoSync:         true,
		},
		{
			name: "all state and advanced fields set",
			xml: `<rule>` +
				`<statetimeout>86400</statetimeout>` +
				`<allowopts/>` +
				`<disablereplyto/>` +
				`<nopfsync/>` +
				`<nosync/>` +
				`</rule>`,
			wantStateTimeout:   "86400",
			wantAllowOpts:      true,
			wantDisableReplyTo: true,
			wantNoPfSync:       true,
			wantNoSync:         true,
		},
		{
			name: "no state or advanced fields",
			xml:  `<rule></rule>`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var got Rule
			if err := xml.Unmarshal([]byte(tt.xml), &got); err != nil {
				t.Fatalf("xml.Unmarshal() error = %v", err)
			}
			if got.StateTimeout != tt.wantStateTimeout {
				t.Errorf("StateTimeout = %q, want %q", got.StateTimeout, tt.wantStateTimeout)
			}
			if got.AllowOpts != tt.wantAllowOpts {
				t.Errorf("AllowOpts = %v, want %v", got.AllowOpts, tt.wantAllowOpts)
			}
			if got.DisableReplyTo != tt.wantDisableReplyTo {
				t.Errorf("DisableReplyTo = %v, want %v", got.DisableReplyTo, tt.wantDisableReplyTo)
			}
			if got.NoPfSync != tt.wantNoPfSync {
				t.Errorf("NoPfSync = %v, want %v", got.NoPfSync, tt.wantNoPfSync)
			}
			if got.NoSync != tt.wantNoSync {
				t.Errorf("NoSync = %v, want %v", got.NoSync, tt.wantNoSync)
			}

			// Round-trip: marshal → unmarshal → compare
			marshaled, err := xml.Marshal(got)
			if err != nil {
				t.Fatalf("xml.Marshal() error = %v", err)
			}
			var roundTripped Rule
			if err := xml.Unmarshal(marshaled, &roundTripped); err != nil {
				t.Fatalf("round-trip xml.Unmarshal() error = %v", err)
			}
			if roundTripped.StateTimeout != tt.wantStateTimeout {
				t.Errorf("round-trip StateTimeout = %q, want %q", roundTripped.StateTimeout, tt.wantStateTimeout)
			}
			if roundTripped.AllowOpts != tt.wantAllowOpts {
				t.Errorf("round-trip AllowOpts = %v, want %v", roundTripped.AllowOpts, tt.wantAllowOpts)
			}
			if roundTripped.DisableReplyTo != tt.wantDisableReplyTo {
				t.Errorf("round-trip DisableReplyTo = %v, want %v", roundTripped.DisableReplyTo, tt.wantDisableReplyTo)
			}
			if roundTripped.NoPfSync != tt.wantNoPfSync {
				t.Errorf("round-trip NoPfSync = %v, want %v", roundTripped.NoPfSync, tt.wantNoPfSync)
			}
			if roundTripped.NoSync != tt.wantNoSync {
				t.Errorf("round-trip NoSync = %v, want %v", roundTripped.NoSync, tt.wantNoSync)
			}
		})
	}
}

func TestRule_BackwardCompatibility_MissingFields(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		xml  string
	}{
		{
			name: "minimal rule with any source and destination",
			xml:  `<rule><type>pass</type><source><any/></source><destination><any/></destination></rule>`,
		},
		{
			name: "legacy rule without new fields",
			xml: `<rule><type>pass</type><interface>wan</interface>` +
				`<ipprotocol>inet</ipprotocol><protocol>tcp</protocol>` +
				`<source><network>lan</network></source>` +
				`<destination><network>wan</network><port>443</port></destination></rule>`,
		},
		{
			name: "rule with only type",
			xml:  `<rule><type>block</type></rule>`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var got Rule
			if err := xml.Unmarshal([]byte(tt.xml), &got); err != nil {
				t.Fatalf("xml.Unmarshal() error = %v", err)
			}

			// All new string fields default to empty
			if got.Floating != "" {
				t.Errorf("Floating = %q, want empty", got.Floating)
			}
			if got.Gateway != "" {
				t.Errorf("Gateway = %q, want empty", got.Gateway)
			}
			if got.Direction != "" {
				t.Errorf("Direction = %q, want empty", got.Direction)
			}
			if got.StateType != "" {
				t.Errorf("StateType = %q, want empty", got.StateType)
			}
			if got.Tracker != "" {
				t.Errorf("Tracker = %q, want empty", got.Tracker)
			}

			// All BoolFlag fields default to false
			if got.Log {
				t.Errorf("Log = %v, want false", got.Log)
			}
			if got.Disabled {
				t.Errorf("Disabled = %v, want false", got.Disabled)
			}
			if got.Quick {
				t.Errorf("Quick = %v, want false", got.Quick)
			}

			// New rate-limiting fields default to empty
			if got.MaxSrcNodes != "" {
				t.Errorf("MaxSrcNodes = %q, want empty", got.MaxSrcNodes)
			}
			if got.MaxSrcConn != "" {
				t.Errorf("MaxSrcConn = %q, want empty", got.MaxSrcConn)
			}
			if got.MaxSrcConnRate != "" {
				t.Errorf("MaxSrcConnRate = %q, want empty", got.MaxSrcConnRate)
			}
			if got.MaxSrcConnRates != "" {
				t.Errorf("MaxSrcConnRates = %q, want empty", got.MaxSrcConnRates)
			}

			// New TCP/ICMP fields default to zero values
			if got.TCPFlags1 != "" {
				t.Errorf("TCPFlags1 = %q, want empty", got.TCPFlags1)
			}
			if got.TCPFlags2 != "" {
				t.Errorf("TCPFlags2 = %q, want empty", got.TCPFlags2)
			}
			if got.TCPFlagsAny {
				t.Errorf("TCPFlagsAny = %v, want false", got.TCPFlagsAny)
			}
			if got.ICMPType != "" {
				t.Errorf("ICMPType = %q, want empty", got.ICMPType)
			}
			if got.ICMP6Type != "" {
				t.Errorf("ICMP6Type = %q, want empty", got.ICMP6Type)
			}

			// New state and advanced fields default to zero values
			if got.StateTimeout != "" {
				t.Errorf("StateTimeout = %q, want empty", got.StateTimeout)
			}
			if got.AllowOpts {
				t.Errorf("AllowOpts = %v, want false", got.AllowOpts)
			}
			if got.DisableReplyTo {
				t.Errorf("DisableReplyTo = %v, want false", got.DisableReplyTo)
			}
			if got.NoPfSync {
				t.Errorf("NoPfSync = %v, want false", got.NoPfSync)
			}
			if got.NoSync {
				t.Errorf("NoSync = %v, want false", got.NoSync)
			}
		})
	}
}

func TestRule_BackwardCompatibility_EffectiveAddress(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		xml       string
		wantSrcEA string
		wantDstEA string
	}{
		{
			name:      "any source and destination",
			xml:       `<rule><type>pass</type><source><any/></source><destination><any/></destination></rule>`,
			wantSrcEA: "any",
			wantDstEA: "any",
		},
		{
			name: "network source and destination with port",
			xml: `<rule><type>pass</type>` +
				`<source><network>lan</network></source>` +
				`<destination><network>wan</network><port>443</port></destination></rule>`,
			wantSrcEA: "lan",
			wantDstEA: "wan",
		},
		{
			name: "address source and destination",
			xml: `<rule><type>pass</type>` +
				`<source><address>192.168.1.0/24</address></source>` +
				`<destination><address>10.0.0.1</address></destination></rule>`,
			wantSrcEA: "192.168.1.0/24",
			wantDstEA: "10.0.0.1",
		},
		{
			name:      "empty source and destination",
			xml:       `<rule><type>block</type><source></source><destination></destination></rule>`,
			wantSrcEA: "",
			wantDstEA: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var got Rule
			if err := xml.Unmarshal([]byte(tt.xml), &got); err != nil {
				t.Fatalf("xml.Unmarshal() error = %v", err)
			}
			if ea := got.Source.EffectiveAddress(); ea != tt.wantSrcEA {
				t.Errorf("Source.EffectiveAddress() = %q, want %q", ea, tt.wantSrcEA)
			}
			if ea := got.Destination.EffectiveAddress(); ea != tt.wantDstEA {
				t.Errorf("Destination.EffectiveAddress() = %q, want %q", ea, tt.wantDstEA)
			}
		})
	}
}

// verifyCompleteRuleFields checks all fields of a Rule against expected values.
func verifyCompleteRuleFields(t *testing.T, got Rule, prefix string) {
	t.Helper()

	if got.UUID != "a1b2c3d4-e5f6-7890-abcd-ef1234567890" {
		t.Errorf("%s UUID = %q, want %q", prefix, got.UUID, "a1b2c3d4-e5f6-7890-abcd-ef1234567890")
	}
	if got.Type != "pass" {
		t.Errorf("%s Type = %q, want %q", prefix, got.Type, "pass")
	}
	if got.Descr != "Allow HTTPS from LAN to WAN" {
		t.Errorf("%s Descr = %q, want %q", prefix, got.Descr, "Allow HTTPS from LAN to WAN")
	}
	if got.Interface.String() != "lan,wan" {
		t.Errorf("%s Interface = %q, want %q", prefix, got.Interface.String(), "lan,wan")
	}
	if got.IPProtocol != testInet {
		t.Errorf("%s IPProtocol = %q, want %q", prefix, got.IPProtocol, testInet)
	}
	if got.StateType != "keep state" {
		t.Errorf("%s StateType = %q, want %q", prefix, got.StateType, "keep state")
	}
	if got.Direction != "in" {
		t.Errorf("%s Direction = %q, want %q", prefix, got.Direction, "in")
	}
	if got.Floating != floatingYes {
		t.Errorf("%s Floating = %q, want %q", prefix, got.Floating, floatingYes)
	}
	if got.Quick != true {
		t.Errorf("%s Quick = %v, want true", prefix, got.Quick)
	}
	if got.Protocol != testTCP {
		t.Errorf("%s Protocol = %q, want %q", prefix, got.Protocol, testTCP)
	}
	if got.Source.Network != "lan" {
		t.Errorf("%s Source.Network = %q, want %q", prefix, got.Source.Network, "lan")
	}
	if got.Source.Port != testPortRange {
		t.Errorf("%s Source.Port = %q, want %q", prefix, got.Source.Port, testPortRange)
	}
	if !got.Destination.IsAny() {
		t.Errorf("%s Destination.IsAny() = false, want true", prefix)
	}
	if got.Destination.Port != "443" {
		t.Errorf("%s Destination.Port = %q, want %q", prefix, got.Destination.Port, "443")
	}
	if got.Target != "10.0.0.1" {
		t.Errorf("%s Target = %q, want %q", prefix, got.Target, "10.0.0.1")
	}
	if got.Gateway != "WAN_GW" {
		t.Errorf("%s Gateway = %q, want %q", prefix, got.Gateway, "WAN_GW")
	}
	if got.SourcePort != testPortRange {
		t.Errorf("%s SourcePort = %q, want %q", prefix, got.SourcePort, testPortRange)
	}
	if got.Log != true {
		t.Errorf("%s Log = %v, want true", prefix, got.Log)
	}
	if got.Disabled {
		t.Errorf("%s Disabled = %v, want false", prefix, got.Disabled)
	}
	if got.Tracker != "1234567890" {
		t.Errorf("%s Tracker = %q, want %q", prefix, got.Tracker, "1234567890")
	}
	// Rate-limiting fields
	if got.MaxSrcNodes != "100" {
		t.Errorf("%s MaxSrcNodes = %q, want %q", prefix, got.MaxSrcNodes, "100")
	}
	if got.MaxSrcConn != "50" {
		t.Errorf("%s MaxSrcConn = %q, want %q", prefix, got.MaxSrcConn, "50")
	}
	if got.MaxSrcConnRate != "10/second" {
		t.Errorf("%s MaxSrcConnRate = %q, want %q", prefix, got.MaxSrcConnRate, "10/second")
	}
	if got.MaxSrcConnRates != "15" {
		t.Errorf("%s MaxSrcConnRates = %q, want %q", prefix, got.MaxSrcConnRates, "15")
	}
	// TCP/ICMP fields
	if got.TCPFlags1 != "S/SA" {
		t.Errorf("%s TCPFlags1 = %q, want %q", prefix, got.TCPFlags1, "S/SA")
	}
	if got.TCPFlags2 != "FSRPAUEW" {
		t.Errorf("%s TCPFlags2 = %q, want %q", prefix, got.TCPFlags2, "FSRPAUEW")
	}
	if !got.TCPFlagsAny {
		t.Errorf("%s TCPFlagsAny = %v, want true", prefix, got.TCPFlagsAny)
	}
	if got.ICMPType != "3,11,0" {
		t.Errorf("%s ICMPType = %q, want %q", prefix, got.ICMPType, "3,11,0")
	}
	if got.ICMP6Type != "128" {
		t.Errorf("%s ICMP6Type = %q, want %q", prefix, got.ICMP6Type, "128")
	}
	// State and advanced fields
	if got.StateTimeout != "3600" {
		t.Errorf("%s StateTimeout = %q, want %q", prefix, got.StateTimeout, "3600")
	}
	if !got.AllowOpts {
		t.Errorf("%s AllowOpts = %v, want true", prefix, got.AllowOpts)
	}
	if !got.DisableReplyTo {
		t.Errorf("%s DisableReplyTo = %v, want true", prefix, got.DisableReplyTo)
	}
	if !got.NoPfSync {
		t.Errorf("%s NoPfSync = %v, want true", prefix, got.NoPfSync)
	}
	if !got.NoSync {
		t.Errorf("%s NoSync = %v, want true", prefix, got.NoSync)
	}
	if got.Updated == nil {
		t.Fatalf("%s Updated is nil, want non-nil", prefix)
	}
	if got.Updated.Username != "admin@192.168.1.1" {
		t.Errorf("%s Updated.Username = %q, want %q", prefix, got.Updated.Username, "admin@192.168.1.1")
	}
	if got.Updated.Time != "1700000000" {
		t.Errorf("%s Updated.Time = %q, want %q", prefix, got.Updated.Time, "1700000000")
	}
	if got.Created == nil {
		t.Fatalf("%s Created is nil, want non-nil", prefix)
	}
	if got.Created.Username != "admin@192.168.1.1" {
		t.Errorf("%s Created.Username = %q, want %q", prefix, got.Created.Username, "admin@192.168.1.1")
	}
	if got.Created.Time != "1699000000" {
		t.Errorf("%s Created.Time = %q, want %q", prefix, got.Created.Time, "1699000000")
	}
}

func TestRule_CompleteRule_XMLRoundTrip(t *testing.T) {
	t.Parallel()

	inputXML := `<rule uuid="a1b2c3d4-e5f6-7890-abcd-ef1234567890">` +
		`<type>pass</type>` +
		`<descr>Allow HTTPS from LAN to WAN</descr>` +
		`<interface>lan,wan</interface>` +
		`<ipprotocol>inet</ipprotocol>` +
		`<statetype>keep state</statetype>` +
		`<direction>in</direction>` +
		`<floating>yes</floating>` +
		`<quick/>` +
		`<protocol>tcp</protocol>` +
		`<source><network>lan</network><port>1024-65535</port></source>` +
		`<destination><any/><port>443</port></destination>` +
		`<target>10.0.0.1</target>` +
		`<gateway>WAN_GW</gateway>` +
		`<sourceport>1024-65535</sourceport>` +
		`<log/>` +
		`<tracker>1234567890</tracker>` +
		`<max-src-nodes>100</max-src-nodes>` +
		`<max-src-conn>50</max-src-conn>` +
		`<max-src-conn-rate>10/second</max-src-conn-rate>` +
		`<max-src-conn-rates>15</max-src-conn-rates>` +
		`<tcpflags1>S/SA</tcpflags1>` +
		`<tcpflags2>FSRPAUEW</tcpflags2>` +
		`<tcpflags_any/>` +
		`<icmptype>3,11,0</icmptype>` +
		`<icmp6-type>128</icmp6-type>` +
		`<statetimeout>3600</statetimeout>` +
		`<allowopts/>` +
		`<disablereplyto/>` +
		`<nopfsync/>` +
		`<nosync/>` +
		`<updated><username>admin@192.168.1.1</username><time>1700000000</time>` +
		`<description>/firewall_rules_edit.php made changes</description></updated>` +
		`<created><username>admin@192.168.1.1</username><time>1699000000</time>` +
		`<description>/firewall_rules_edit.php made changes</description></created>` +
		`</rule>`

	var got Rule
	if err := xml.Unmarshal([]byte(inputXML), &got); err != nil {
		t.Fatalf("xml.Unmarshal() error = %v", err)
	}

	t.Run("unmarshal", func(t *testing.T) {
		t.Parallel()
		verifyCompleteRuleFields(t, got, "unmarshal")
	})

	t.Run("round-trip", func(t *testing.T) {
		t.Parallel()

		// Use pointer so InterfaceList's custom MarshalXML (pointer receiver) is called
		marshaled, err := xml.Marshal(&got)
		if err != nil {
			t.Fatalf("xml.Marshal() error = %v", err)
		}
		var roundTripped Rule
		if err := xml.Unmarshal(marshaled, &roundTripped); err != nil {
			t.Fatalf("round-trip xml.Unmarshal() error = %v", err)
		}
		verifyCompleteRuleFields(t, roundTripped, "round-trip")
	})
}

func TestNATRule_BoolFlagFields_XMLRoundTrip(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		xml          string
		wantDisabled BoolFlag
		wantLog      BoolFlag
	}{
		{
			name:         "both flags set",
			xml:          `<rule><disabled/><log/></rule>`,
			wantDisabled: true,
			wantLog:      true,
		},
		{
			name:         "no flags",
			xml:          `<rule></rule>`,
			wantDisabled: false,
			wantLog:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var got NATRule
			if err := xml.Unmarshal([]byte(tt.xml), &got); err != nil {
				t.Fatalf("xml.Unmarshal() error = %v", err)
			}
			if got.Disabled != tt.wantDisabled {
				t.Errorf("Disabled = %v, want %v", got.Disabled, tt.wantDisabled)
			}
			if got.Log != tt.wantLog {
				t.Errorf("Log = %v, want %v", got.Log, tt.wantLog)
			}
		})
	}
}

//nolint:dupl // NATRule/Rule round-trip test loops are structurally similar by design
func TestNATRule_NewFields_XMLRoundTrip(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name               string
		xml                string
		wantStaticNatPort  BoolFlag
		wantNoNat          BoolFlag
		wantNatPort        string
		wantPoolOptsHshKey string
	}{
		{
			name:              "all BoolFlag fields present",
			xml:               `<rule><staticnatport/><nonat/></rule>`,
			wantStaticNatPort: true,
			wantNoNat:         true,
		},
		{
			name:              "no BoolFlag fields",
			xml:               `<rule></rule>`,
			wantStaticNatPort: false,
			wantNoNat:         false,
		},
		{
			name:               "string fields with values",
			xml:                `<rule><natport>8080-8090</natport><poolopts_sourcehashkey>key123</poolopts_sourcehashkey></rule>`,
			wantNatPort:        "8080-8090",
			wantPoolOptsHshKey: "key123",
		},
		{
			name:               "mixed BoolFlag and string fields",
			xml:                `<rule><staticnatport/><natport>443</natport><poolopts_sourcehashkey>abc</poolopts_sourcehashkey></rule>`,
			wantStaticNatPort:  true,
			wantNatPort:        "443",
			wantPoolOptsHshKey: "abc",
		},
		{
			name:              "only staticnatport",
			xml:               `<rule><staticnatport/></rule>`,
			wantStaticNatPort: true,
		},
		{
			name:      "only nonat",
			xml:       `<rule><nonat/></rule>`,
			wantNoNat: true,
		},
		{
			name:        "only natport",
			xml:         `<rule><natport>5000</natport></rule>`,
			wantNatPort: "5000",
		},
		{
			name:               "self-closing poolopts_sourcehashkey",
			xml:                `<rule><poolopts_sourcehashkey/></rule>`,
			wantPoolOptsHshKey: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var got NATRule
			if err := xml.Unmarshal([]byte(tt.xml), &got); err != nil {
				t.Fatalf("xml.Unmarshal() error = %v", err)
			}
			if got.StaticNatPort != tt.wantStaticNatPort {
				t.Errorf("StaticNatPort = %v, want %v", got.StaticNatPort, tt.wantStaticNatPort)
			}
			if got.NoNat != tt.wantNoNat {
				t.Errorf("NoNat = %v, want %v", got.NoNat, tt.wantNoNat)
			}
			if got.NatPort != tt.wantNatPort {
				t.Errorf("NatPort = %q, want %q", got.NatPort, tt.wantNatPort)
			}
			if got.PoolOptsSrcHashKey != tt.wantPoolOptsHshKey {
				t.Errorf("PoolOptsSrcHashKey = %q, want %q", got.PoolOptsSrcHashKey, tt.wantPoolOptsHshKey)
			}

			// Round-trip: marshal → unmarshal → compare
			marshaled, err := xml.Marshal(got)
			if err != nil {
				t.Fatalf("xml.Marshal() error = %v", err)
			}
			var roundTripped NATRule
			if err := xml.Unmarshal(marshaled, &roundTripped); err != nil {
				t.Fatalf("round-trip xml.Unmarshal() error = %v", err)
			}
			if roundTripped.StaticNatPort != tt.wantStaticNatPort {
				t.Errorf("round-trip StaticNatPort = %v, want %v", roundTripped.StaticNatPort, tt.wantStaticNatPort)
			}
			if roundTripped.NoNat != tt.wantNoNat {
				t.Errorf("round-trip NoNat = %v, want %v", roundTripped.NoNat, tt.wantNoNat)
			}
			if roundTripped.NatPort != tt.wantNatPort {
				t.Errorf("round-trip NatPort = %q, want %q", roundTripped.NatPort, tt.wantNatPort)
			}
			if roundTripped.PoolOptsSrcHashKey != tt.wantPoolOptsHshKey {
				t.Errorf(
					"round-trip PoolOptsSrcHashKey = %q, want %q",
					roundTripped.PoolOptsSrcHashKey,
					tt.wantPoolOptsHshKey,
				)
			}
		})
	}
}

func TestNATRule_CompleteWithNewFields_XMLRoundTrip(t *testing.T) {
	t.Parallel()

	inputXML := `<rule uuid="nat-uuid-1234">` +
		`<interface>wan</interface>` +
		`<ipprotocol>inet</ipprotocol>` +
		`<protocol>tcp</protocol>` +
		`<source><any/></source>` +
		`<destination><network>wan</network><port>443</port></destination>` +
		`<target>192.168.1.100</target>` +
		`<sourceport>1024-65535</sourceport>` +
		`<natport>8443</natport>` +
		`<poolopts>round-robin</poolopts>` +
		`<poolopts_sourcehashkey>hashkey99</poolopts_sourcehashkey>` +
		`<staticnatport/>` +
		`<nonat/>` +
		`<disabled/>` +
		`<log/>` +
		`<descr>Complete NAT rule test</descr>` +
		`<category>test</category>` +
		`<tag>mytag</tag>` +
		`<tagged>mytagged</tagged>` +
		`<updated><username>admin@10.0.0.1</username><time>1700000000</time>` +
		`<description>test update</description></updated>` +
		`<created><username>admin@10.0.0.1</username><time>1699000000</time>` +
		`<description>test create</description></created>` +
		`</rule>`

	var got NATRule
	if err := xml.Unmarshal([]byte(inputXML), &got); err != nil {
		t.Fatalf("xml.Unmarshal() error = %v", err)
	}

	// Verify all fields
	if got.UUID != "nat-uuid-1234" {
		t.Errorf("UUID = %q, want %q", got.UUID, "nat-uuid-1234")
	}
	if got.Interface.String() != testWAN {
		t.Errorf("Interface = %q, want %q", got.Interface.String(), testWAN)
	}
	if got.IPProtocol != testInet {
		t.Errorf("IPProtocol = %q, want %q", got.IPProtocol, testInet)
	}
	if got.Protocol != testTCP {
		t.Errorf("Protocol = %q, want %q", got.Protocol, testTCP)
	}
	if !got.Source.IsAny() {
		t.Error("Source.IsAny() = false, want true")
	}
	if got.Destination.Network != testWAN {
		t.Errorf("Destination.Network = %q, want %q", got.Destination.Network, testWAN)
	}
	if got.Destination.Port != "443" {
		t.Errorf("Destination.Port = %q, want %q", got.Destination.Port, "443")
	}
	if got.Target != "192.168.1.100" {
		t.Errorf("Target = %q, want %q", got.Target, "192.168.1.100")
	}
	if got.SourcePort != testPortRange {
		t.Errorf("SourcePort = %q, want %q", got.SourcePort, testPortRange)
	}
	if got.NatPort != "8443" {
		t.Errorf("NatPort = %q, want %q", got.NatPort, "8443")
	}
	if got.PoolOpts != "round-robin" {
		t.Errorf("PoolOpts = %q, want %q", got.PoolOpts, "round-robin")
	}
	if got.PoolOptsSrcHashKey != "hashkey99" {
		t.Errorf("PoolOptsSrcHashKey = %q, want %q", got.PoolOptsSrcHashKey, "hashkey99")
	}
	if !got.StaticNatPort {
		t.Error("StaticNatPort = false, want true")
	}
	if !got.NoNat {
		t.Error("NoNat = false, want true")
	}
	if !got.Disabled {
		t.Error("Disabled = false, want true")
	}
	if !got.Log {
		t.Error("Log = false, want true")
	}
	if got.Descr != "Complete NAT rule test" {
		t.Errorf("Descr = %q, want %q", got.Descr, "Complete NAT rule test")
	}
	if got.Category != "test" {
		t.Errorf("Category = %q, want %q", got.Category, "test")
	}
	if got.Tag != "mytag" {
		t.Errorf("Tag = %q, want %q", got.Tag, "mytag")
	}
	if got.Tagged != "mytagged" {
		t.Errorf("Tagged = %q, want %q", got.Tagged, "mytagged")
	}
	if got.Updated == nil || got.Updated.Username != testAdminUser {
		t.Errorf("Updated.Username = %v, want %q", got.Updated, testAdminUser)
	}
	if got.Created == nil || got.Created.Username != testAdminUser {
		t.Errorf("Created.Username = %v, want %q", got.Created, testAdminUser)
	}

	// Round-trip
	marshaled, err := xml.Marshal(&got)
	if err != nil {
		t.Fatalf("xml.Marshal() error = %v", err)
	}
	var roundTripped NATRule
	if err := xml.Unmarshal(marshaled, &roundTripped); err != nil {
		t.Fatalf("round-trip xml.Unmarshal() error = %v", err)
	}
	if roundTripped.UUID != got.UUID {
		t.Errorf("round-trip UUID = %q, want %q", roundTripped.UUID, got.UUID)
	}
	if roundTripped.NatPort != got.NatPort {
		t.Errorf("round-trip NatPort = %q, want %q", roundTripped.NatPort, got.NatPort)
	}
	if roundTripped.PoolOptsSrcHashKey != got.PoolOptsSrcHashKey {
		t.Errorf("round-trip PoolOptsSrcHashKey = %q, want %q", roundTripped.PoolOptsSrcHashKey, got.PoolOptsSrcHashKey)
	}
	if roundTripped.StaticNatPort != got.StaticNatPort {
		t.Errorf("round-trip StaticNatPort = %v, want %v", roundTripped.StaticNatPort, got.StaticNatPort)
	}
	if roundTripped.NoNat != got.NoNat {
		t.Errorf("round-trip NoNat = %v, want %v", roundTripped.NoNat, got.NoNat)
	}
}

func TestNATRule_BackwardCompatibility(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		xml  string
	}{
		{
			name: "minimal NAT rule",
			xml:  `<rule><source><any/></source><destination><any/></destination></rule>`,
		},
		{
			name: "legacy NAT rule without new fields",
			xml: `<rule><interface>wan</interface>` +
				`<ipprotocol>inet</ipprotocol><protocol>tcp</protocol>` +
				`<source><network>lan</network></source>` +
				`<destination><network>wan</network><port>443</port></destination>` +
				`<target>192.168.1.10</target>` +
				`<poolopts>round-robin</poolopts></rule>`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var got NATRule
			if err := xml.Unmarshal([]byte(tt.xml), &got); err != nil {
				t.Fatalf("xml.Unmarshal() error = %v", err)
			}

			// New BoolFlag fields default to false
			if got.StaticNatPort {
				t.Errorf("StaticNatPort = %v, want false", got.StaticNatPort)
			}
			if got.NoNat {
				t.Errorf("NoNat = %v, want false", got.NoNat)
			}

			// New string fields default to empty
			if got.NatPort != "" {
				t.Errorf("NatPort = %q, want empty", got.NatPort)
			}
			if got.PoolOptsSrcHashKey != "" {
				t.Errorf("PoolOptsSrcHashKey = %q, want empty", got.PoolOptsSrcHashKey)
			}
		})
	}
}

//nolint:dupl // InboundRule/Rule round-trip test loops are structurally similar by design
func TestInboundRule_NewFields_XMLRoundTrip(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name                 string
		xml                  string
		wantNATReflection    string
		wantAssociatedRuleID string
		wantLocalPort        string
		wantNoRDR            BoolFlag
		wantNoSync           BoolFlag
	}{
		{
			name:       "all BoolFlag fields present",
			xml:        `<rule><nordr/><nosync/></rule>`,
			wantNoRDR:  true,
			wantNoSync: true,
		},
		{
			name:       "no BoolFlag fields",
			xml:        `<rule></rule>`,
			wantNoRDR:  false,
			wantNoSync: false,
		},
		{
			name: "string fields with values",
			xml: `<rule>` +
				`<natreflection>enable</natreflection>` +
				`<associated-rule-id>rule-123</associated-rule-id>` +
				`<local-port>443</local-port>` +
				`</rule>`,
			wantNATReflection:    "enable",
			wantAssociatedRuleID: "rule-123",
			wantLocalPort:        "443",
		},
		{
			name: "mixed BoolFlag and string fields",
			xml: `<rule>` +
				`<natreflection>purenat</natreflection>` +
				`<associated-rule-id>pass-456</associated-rule-id>` +
				`<local-port>8080</local-port>` +
				`<nordr/>` +
				`<nosync/>` +
				`</rule>`,
			wantNATReflection:    "purenat",
			wantAssociatedRuleID: "pass-456",
			wantLocalPort:        "8080",
			wantNoRDR:            true,
			wantNoSync:           true,
		},
		{
			name:      "only nordr",
			xml:       `<rule><nordr/></rule>`,
			wantNoRDR: true,
		},
		{
			name:       "only nosync",
			xml:        `<rule><nosync/></rule>`,
			wantNoSync: true,
		},
		{
			name:              "only natreflection",
			xml:               `<rule><natreflection>disable</natreflection></rule>`,
			wantNATReflection: "disable",
		},
		{
			name:              "reflection and natreflection both present",
			xml:               `<rule><reflection>enable</reflection><natreflection>purenat</natreflection></rule>`,
			wantNATReflection: "purenat",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var got InboundRule
			if err := xml.Unmarshal([]byte(tt.xml), &got); err != nil {
				t.Fatalf("xml.Unmarshal() error = %v", err)
			}
			if got.NATReflection != tt.wantNATReflection {
				t.Errorf("NATReflection = %q, want %q", got.NATReflection, tt.wantNATReflection)
			}
			if got.AssociatedRuleID != tt.wantAssociatedRuleID {
				t.Errorf("AssociatedRuleID = %q, want %q", got.AssociatedRuleID, tt.wantAssociatedRuleID)
			}
			if got.LocalPort != tt.wantLocalPort {
				t.Errorf("LocalPort = %q, want %q", got.LocalPort, tt.wantLocalPort)
			}
			if got.NoRDR != tt.wantNoRDR {
				t.Errorf("NoRDR = %v, want %v", got.NoRDR, tt.wantNoRDR)
			}
			if got.NoSync != tt.wantNoSync {
				t.Errorf("NoSync = %v, want %v", got.NoSync, tt.wantNoSync)
			}

			// Round-trip: marshal → unmarshal → compare
			marshaled, err := xml.Marshal(got)
			if err != nil {
				t.Fatalf("xml.Marshal() error = %v", err)
			}
			var roundTripped InboundRule
			if err := xml.Unmarshal(marshaled, &roundTripped); err != nil {
				t.Fatalf("round-trip xml.Unmarshal() error = %v", err)
			}
			if roundTripped.NATReflection != tt.wantNATReflection {
				t.Errorf("round-trip NATReflection = %q, want %q", roundTripped.NATReflection, tt.wantNATReflection)
			}
			if roundTripped.AssociatedRuleID != tt.wantAssociatedRuleID {
				t.Errorf(
					"round-trip AssociatedRuleID = %q, want %q",
					roundTripped.AssociatedRuleID,
					tt.wantAssociatedRuleID,
				)
			}
			if roundTripped.LocalPort != tt.wantLocalPort {
				t.Errorf("round-trip LocalPort = %q, want %q", roundTripped.LocalPort, tt.wantLocalPort)
			}
			if roundTripped.NoRDR != tt.wantNoRDR {
				t.Errorf("round-trip NoRDR = %v, want %v", roundTripped.NoRDR, tt.wantNoRDR)
			}
			if roundTripped.NoSync != tt.wantNoSync {
				t.Errorf("round-trip NoSync = %v, want %v", roundTripped.NoSync, tt.wantNoSync)
			}
		})
	}
}

func TestInboundRule_CompleteWithNewFields_XMLRoundTrip(t *testing.T) {
	t.Parallel()

	inputXML := `<rule uuid="inbound-uuid-5678">` +
		`<interface>wan</interface>` +
		`<ipprotocol>inet</ipprotocol>` +
		`<protocol>tcp</protocol>` +
		`<source><not/><address>10.0.0.0/8</address><port>1024-65535</port></source>` +
		`<destination><network>wan</network><port>443</port></destination>` +
		`<externalport>443</externalport>` +
		`<internalip>192.168.1.50</internalip>` +
		`<internalport>8443</internalport>` +
		`<local-port>8443</local-port>` +
		`<reflection>enable</reflection>` +
		`<natreflection>purenat</natreflection>` +
		`<associated-rule-id>pass-rule-99</associated-rule-id>` +
		`<priority>100</priority>` +
		`<nordr/>` +
		`<nosync/>` +
		`<disabled/>` +
		`<log/>` +
		`<descr>Complete inbound rule test</descr>` +
		`<updated><username>admin@10.0.0.1</username><time>1700000000</time>` +
		`<description>test update</description></updated>` +
		`<created><username>admin@10.0.0.1</username><time>1699000000</time>` +
		`<description>test create</description></created>` +
		`</rule>`

	var got InboundRule
	if err := xml.Unmarshal([]byte(inputXML), &got); err != nil {
		t.Fatalf("xml.Unmarshal() error = %v", err)
	}

	// Verify all fields
	if got.UUID != "inbound-uuid-5678" {
		t.Errorf("UUID = %q, want %q", got.UUID, "inbound-uuid-5678")
	}
	if got.Interface.String() != testWAN {
		t.Errorf("Interface = %q, want %q", got.Interface.String(), testWAN)
	}
	if got.IPProtocol != testInet {
		t.Errorf("IPProtocol = %q, want %q", got.IPProtocol, testInet)
	}
	if got.Protocol != testTCP {
		t.Errorf("Protocol = %q, want %q", got.Protocol, testTCP)
	}
	if got.Source.Address != "10.0.0.0/8" {
		t.Errorf("Source.Address = %q, want %q", got.Source.Address, "10.0.0.0/8")
	}
	if got.Source.Port != testPortRange {
		t.Errorf("Source.Port = %q, want %q", got.Source.Port, testPortRange)
	}
	if !got.Source.Not {
		t.Error("Source.Not = false, want true")
	}
	if got.Destination.Network != testWAN {
		t.Errorf("Destination.Network = %q, want %q", got.Destination.Network, testWAN)
	}
	if got.Destination.Port != "443" {
		t.Errorf("Destination.Port = %q, want %q", got.Destination.Port, "443")
	}
	if got.ExternalPort != "443" {
		t.Errorf("ExternalPort = %q, want %q", got.ExternalPort, "443")
	}
	if got.InternalIP != "192.168.1.50" {
		t.Errorf("InternalIP = %q, want %q", got.InternalIP, "192.168.1.50")
	}
	if got.InternalPort != "8443" {
		t.Errorf("InternalPort = %q, want %q", got.InternalPort, "8443")
	}
	if got.LocalPort != "8443" {
		t.Errorf("LocalPort = %q, want %q", got.LocalPort, "8443")
	}
	if got.Reflection != "enable" {
		t.Errorf("Reflection = %q, want %q", got.Reflection, "enable")
	}
	if got.NATReflection != "purenat" {
		t.Errorf("NATReflection = %q, want %q", got.NATReflection, "purenat")
	}
	if got.AssociatedRuleID != "pass-rule-99" {
		t.Errorf("AssociatedRuleID = %q, want %q", got.AssociatedRuleID, "pass-rule-99")
	}
	if got.Priority != 100 {
		t.Errorf("Priority = %d, want %d", got.Priority, 100)
	}
	if !got.NoRDR {
		t.Error("NoRDR = false, want true")
	}
	if !got.NoSync {
		t.Error("NoSync = false, want true")
	}
	if !got.Disabled {
		t.Error("Disabled = false, want true")
	}
	if !got.Log {
		t.Error("Log = false, want true")
	}
	if got.Descr != "Complete inbound rule test" {
		t.Errorf("Descr = %q, want %q", got.Descr, "Complete inbound rule test")
	}
	if got.Updated == nil || got.Updated.Username != testAdminUser {
		t.Errorf("Updated.Username = %v, want %q", got.Updated, testAdminUser)
	}
	if got.Created == nil || got.Created.Username != testAdminUser {
		t.Errorf("Created.Username = %v, want %q", got.Created, testAdminUser)
	}

	// Round-trip
	marshaled, err := xml.Marshal(&got)
	if err != nil {
		t.Fatalf("xml.Marshal() error = %v", err)
	}
	var roundTripped InboundRule
	if err := xml.Unmarshal(marshaled, &roundTripped); err != nil {
		t.Fatalf("round-trip xml.Unmarshal() error = %v", err)
	}
	if roundTripped.UUID != got.UUID {
		t.Errorf("round-trip UUID = %q, want %q", roundTripped.UUID, got.UUID)
	}
	if roundTripped.NATReflection != got.NATReflection {
		t.Errorf("round-trip NATReflection = %q, want %q", roundTripped.NATReflection, got.NATReflection)
	}
	if roundTripped.AssociatedRuleID != got.AssociatedRuleID {
		t.Errorf("round-trip AssociatedRuleID = %q, want %q", roundTripped.AssociatedRuleID, got.AssociatedRuleID)
	}
	if roundTripped.LocalPort != got.LocalPort {
		t.Errorf("round-trip LocalPort = %q, want %q", roundTripped.LocalPort, got.LocalPort)
	}
	if roundTripped.NoRDR != got.NoRDR {
		t.Errorf("round-trip NoRDR = %v, want %v", roundTripped.NoRDR, got.NoRDR)
	}
	if roundTripped.NoSync != got.NoSync {
		t.Errorf("round-trip NoSync = %v, want %v", roundTripped.NoSync, got.NoSync)
	}
}

func TestInboundRule_BackwardCompatibility(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		xml  string
	}{
		{
			name: "minimal inbound rule",
			xml:  `<rule><source><any/></source><destination><any/></destination></rule>`,
		},
		{
			name: "legacy inbound rule without new fields",
			xml: `<rule><interface>wan</interface>` +
				`<ipprotocol>inet</ipprotocol><protocol>tcp</protocol>` +
				`<source><any/></source>` +
				`<destination><network>wan</network><port>443</port></destination>` +
				`<externalport>443</externalport>` +
				`<internalip>192.168.1.10</internalip>` +
				`<internalport>443</internalport>` +
				`<reflection>enable</reflection></rule>`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var got InboundRule
			if err := xml.Unmarshal([]byte(tt.xml), &got); err != nil {
				t.Fatalf("xml.Unmarshal() error = %v", err)
			}

			// New BoolFlag fields default to false
			if got.NoRDR {
				t.Errorf("NoRDR = %v, want false", got.NoRDR)
			}
			if got.NoSync {
				t.Errorf("NoSync = %v, want false", got.NoSync)
			}

			// New string fields default to empty
			if got.NATReflection != "" {
				t.Errorf("NATReflection = %q, want empty", got.NATReflection)
			}
			if got.AssociatedRuleID != "" {
				t.Errorf("AssociatedRuleID = %q, want empty", got.AssociatedRuleID)
			}
			if got.LocalPort != "" {
				t.Errorf("LocalPort = %q, want empty", got.LocalPort)
			}
		})
	}
}
