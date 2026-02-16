package schema

import (
	"encoding/xml"
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/constants"
)

func TestBoolFlag_String(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		flag BoolFlag
		want string
	}{
		{name: "true flag", flag: BoolFlag(true), want: "true"},
		{name: "false flag", flag: BoolFlag(false), want: "false"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.flag.String(); got != tt.want {
				t.Errorf("BoolFlag.String() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestBoolFlag_Bool(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		flag BoolFlag
		want bool
	}{
		{name: "true flag", flag: BoolFlag(true), want: true},
		{name: "false flag", flag: BoolFlag(false), want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.flag.Bool(); got != tt.want {
				t.Errorf("BoolFlag.Bool() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestBoolFlag_Set(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		initial  BoolFlag
		setValue bool
		want     bool
	}{
		{name: "set true to false", initial: BoolFlag(true), setValue: false, want: false},
		{name: "set false to true", initial: BoolFlag(false), setValue: true, want: true},
		{name: "set true to true", initial: BoolFlag(true), setValue: true, want: true},
		{name: "set false to false", initial: BoolFlag(false), setValue: false, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			flag := tt.initial
			flag.Set(tt.setValue)
			if got := flag.Bool(); got != tt.want {
				t.Errorf("BoolFlag.Set(%v) resulted in %v, want %v", tt.setValue, got, tt.want)
			}
		})
	}
}

func TestBoolFlag_MarshalXML(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		flag BoolFlag
		want string
	}{
		// For BoolFlag, true values should result in empty elements in OPNsense XML
		{name: "true flag", flag: BoolFlag(true), want: "<test><Flag></Flag></test>"},
		{name: "false flag", flag: BoolFlag(false), want: "<test></test>"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			type testStruct struct {
				XMLName xml.Name  `xml:"test"`
				Flag    *BoolFlag `xml:"Flag,omitempty"`
			}

			// Use pointer to ensure the custom marshaler is called
			var flagPtr *BoolFlag
			if tt.flag {
				flagPtr = &tt.flag
			}

			data := testStruct{Flag: flagPtr}
			result, err := xml.Marshal(data)
			if err != nil {
				t.Fatalf("xml.Marshal() failed: %v", err)
			}

			got := string(result)
			if got != tt.want {
				t.Errorf("BoolFlag.MarshalXML() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestBoolFlag_UnmarshalXML(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		xml  string
		want bool
	}{
		{name: "empty element", xml: "<test><flag/></test>", want: true},
		{name: "element with content", xml: "<test><flag>content</flag></test>", want: true},
		{name: "no flag element", xml: "<test></test>", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			type testStruct struct {
				XMLName xml.Name `xml:"test"`
				Flag    BoolFlag `xml:"flag,omitempty"`
			}

			var result testStruct
			err := xml.Unmarshal([]byte(tt.xml), &result)
			if err != nil {
				t.Fatalf("xml.Unmarshal() failed: %v", err)
			}

			if got := result.Flag.Bool(); got != tt.want {
				t.Errorf("BoolFlag.UnmarshalXML() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRuleLocation_IsAny(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		rl   RuleLocation
		want bool
	}{
		{
			name: "empty location",
			rl:   RuleLocation{},
			want: true,
		},
		{
			name: "network any",
			rl:   RuleLocation{Network: constants.NetworkAny},
			want: true,
		},
		{
			name: "network with address",
			rl:   RuleLocation{Network: "lan", Address: "192.168.1.0"},
			want: false,
		},
		{
			name: "address only",
			rl:   RuleLocation{Address: "192.168.1.0"},
			want: false,
		},
		{
			name: "port only",
			rl:   RuleLocation{Port: "80"},
			want: false,
		},
		{
			name: "subnet only",
			rl:   RuleLocation{Subnet: "24"},
			want: true,
		},
		{
			name: "not flag with empty fields",
			rl:   RuleLocation{Not: BoolFlag(true)},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.rl.IsAny(); got != tt.want {
				t.Errorf("RuleLocation.IsAny() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRuleLocation_String(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		rl   RuleLocation
		want string
	}{
		{
			name: "empty location",
			rl:   RuleLocation{},
			want: "any",
		},
		{
			name: "network only",
			rl:   RuleLocation{Network: "lan"},
			want: "lan",
		},
		{
			name: "address only",
			rl:   RuleLocation{Address: "192.168.1.0"},
			want: "192.168.1.0",
		},
		{
			name: "address with subnet",
			rl:   RuleLocation{Address: "192.168.1.0", Subnet: "24"},
			want: "192.168.1.0/24",
		},
		{
			name: "network with port",
			rl:   RuleLocation{Network: "wan", Port: "80"},
			want: "wan :80",
		},
		{
			name: "address with subnet and port",
			rl:   RuleLocation{Address: "10.0.0.0", Subnet: "8", Port: "443"},
			want: "10.0.0.0/8 :443",
		},
		{
			name: "port only",
			rl:   RuleLocation{Port: "22"},
			want: ":22",
		},
		{
			name: "not network",
			rl:   RuleLocation{Network: "dmz", Not: BoolFlag(true)},
			want: "NOT dmz",
		},
		{
			name: "not address with subnet and port",
			rl:   RuleLocation{Address: "172.16.0.0", Subnet: "16", Port: "8080", Not: BoolFlag(true)},
			want: "NOT 172.16.0.0/16 :8080",
		},
		{
			name: "network takes precedence over address",
			rl:   RuleLocation{Network: "opt1", Address: "192.168.1.0"},
			want: "opt1",
		},
		{
			name: "subnet without address ignored",
			rl:   RuleLocation{Subnet: "24"},
			want: "any",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.rl.String(); got != tt.want {
				t.Errorf("RuleLocation.String() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestRuleLocation_MarshalUnmarshalXML(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		rl   RuleLocation
	}{
		{
			name: "complete location",
			rl: RuleLocation{
				Network: "lan",
				Address: "192.168.1.0",
				Subnet:  "24",
				Port:    "80",
				Not:     BoolFlag(true),
			},
		},
		{
			name: "minimal location",
			rl: RuleLocation{
				Address: "10.0.0.1",
			},
		},
		{
			name: "empty location",
			rl:   RuleLocation{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// Marshal the location
			data, err := xml.Marshal(tt.rl)
			if err != nil {
				t.Fatalf("xml.Marshal() failed: %v", err)
			}

			// Unmarshal back
			var result RuleLocation
			err = xml.Unmarshal(data, &result)
			if err != nil {
				t.Fatalf("xml.Unmarshal() failed: %v", err)
			}

			// Compare fields
			if result.Network != tt.rl.Network {
				t.Errorf("Network = %q, want %q", result.Network, tt.rl.Network)
			}
			if result.Address != tt.rl.Address {
				t.Errorf("Address = %q, want %q", result.Address, tt.rl.Address)
			}
			if result.Subnet != tt.rl.Subnet {
				t.Errorf("Subnet = %q, want %q", result.Subnet, tt.rl.Subnet)
			}
			if result.Port != tt.rl.Port {
				t.Errorf("Port = %q, want %q", result.Port, tt.rl.Port)
			}
			if result.Not != tt.rl.Not {
				t.Errorf("Not = %v, want %v", result.Not, tt.rl.Not)
			}
		})
	}
}
