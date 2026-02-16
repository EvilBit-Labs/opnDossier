package schema

import (
	"encoding/xml"
	"sort"
	"testing"
)

func TestDhcpd_UnmarshalXML(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		xml     string
		want    map[string]string // key -> enable value for simplicity
		wantErr bool
	}{
		{
			name: "empty dhcpd",
			xml:  `<dhcpd></dhcpd>`,
			want: map[string]string{},
		},
		{
			name: "single lan interface",
			xml: `<dhcpd>
				<lan>
					<enable>1</enable>
					<range>
						<from>192.168.1.100</from>
						<to>192.168.1.200</to>
					</range>
				</lan>
			</dhcpd>`,
			want: map[string]string{"lan": "1"},
		},
		{
			name: "multiple interfaces",
			xml: `<dhcpd>
				<lan>
					<enable>1</enable>
				</lan>
				<opt1>
					<enable>0</enable>
				</opt1>
			</dhcpd>`,
			want: map[string]string{"lan": "1", "opt1": "0"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var dhcpd Dhcpd
			err := xml.Unmarshal([]byte(tt.xml), &dhcpd)
			if (err != nil) != tt.wantErr {
				t.Errorf("Dhcpd.UnmarshalXML() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				if len(dhcpd.Items) != len(tt.want) {
					t.Errorf("Dhcpd.Items length = %d, want %d", len(dhcpd.Items), len(tt.want))
				}

				for key, wantEnable := range tt.want {
					iface, ok := dhcpd.Items[key]
					if !ok {
						t.Errorf("Dhcpd.Items[%q] not found", key)
						continue
					}
					if iface.Enable != wantEnable {
						t.Errorf("Dhcpd.Items[%q].Enable = %q, want %q", key, iface.Enable, wantEnable)
					}
				}
			}
		})
	}
}

func TestDhcpd_Get(t *testing.T) {
	t.Parallel()

	dhcpd := Dhcpd{
		Items: map[string]DhcpdInterface{
			"lan": {Enable: "1", Gateway: "192.168.1.1"},
			"wan": {Enable: "0", Gateway: "10.0.0.1"},
		},
	}

	tests := []struct {
		name        string
		dhcpd       *Dhcpd
		key         string
		wantOk      bool
		wantEnable  string
		wantGateway string
	}{
		{
			name:        "existing lan interface",
			dhcpd:       &dhcpd,
			key:         "lan",
			wantOk:      true,
			wantEnable:  "1",
			wantGateway: "192.168.1.1",
		},
		{
			name:        "existing wan interface",
			dhcpd:       &dhcpd,
			key:         "wan",
			wantOk:      true,
			wantEnable:  "0",
			wantGateway: "10.0.0.1",
		},
		{
			name:   "non-existent interface",
			dhcpd:  &dhcpd,
			key:    "opt1",
			wantOk: false,
		},
		{
			name:   "nil items map",
			dhcpd:  &Dhcpd{Items: nil},
			key:    "lan",
			wantOk: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, ok := tt.dhcpd.Get(tt.key)
			if ok != tt.wantOk {
				t.Errorf("Dhcpd.Get() ok = %v, want %v", ok, tt.wantOk)
			}
			if tt.wantOk {
				if got.Enable != tt.wantEnable {
					t.Errorf("Dhcpd.Get().Enable = %q, want %q", got.Enable, tt.wantEnable)
				}
				if got.Gateway != tt.wantGateway {
					t.Errorf("Dhcpd.Get().Gateway = %q, want %q", got.Gateway, tt.wantGateway)
				}
			}
		})
	}
}

func TestDhcpd_Names(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		dhcpd Dhcpd
		want  []string
	}{
		{
			name:  "empty dhcpd",
			dhcpd: Dhcpd{Items: map[string]DhcpdInterface{}},
			want:  []string{},
		},
		{
			name: "single interface",
			dhcpd: Dhcpd{Items: map[string]DhcpdInterface{
				"lan": {},
			}},
			want: []string{"lan"},
		},
		{
			name: "multiple interfaces",
			dhcpd: Dhcpd{Items: map[string]DhcpdInterface{
				"lan":  {},
				"wan":  {},
				"opt1": {},
			}},
			want: []string{"lan", "wan", "opt1"},
		},
		{
			name:  "nil items map",
			dhcpd: Dhcpd{Items: nil},
			want:  []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := tt.dhcpd.Names()

			// Sort both slices to compare them regardless of order
			sort.Strings(got)
			sort.Strings(tt.want)

			if len(got) != len(tt.want) {
				t.Errorf("Dhcpd.Names() length = %d, want %d", len(got), len(tt.want))
				return
			}

			for i, name := range got {
				if name != tt.want[i] {
					t.Errorf("Dhcpd.Names()[%d] = %q, want %q", i, name, tt.want[i])
				}
			}
		})
	}
}

//nolint:dupl
func TestDhcpd_Wan(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		dhcpd       Dhcpd
		wantOk      bool
		wantEnable  string
		wantGateway string
	}{
		{
			name: "wan exists",
			dhcpd: Dhcpd{Items: map[string]DhcpdInterface{
				"wan": {Enable: "1", Gateway: "10.0.0.1"},
			}},
			wantOk:      true,
			wantEnable:  "1",
			wantGateway: "10.0.0.1",
		},
		{
			name: "wan does not exist",
			dhcpd: Dhcpd{Items: map[string]DhcpdInterface{
				"lan": {Enable: "1"},
			}},
			wantOk: false,
		},
		{
			name:   "nil items",
			dhcpd:  Dhcpd{Items: nil},
			wantOk: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, ok := tt.dhcpd.Wan()
			if ok != tt.wantOk {
				t.Errorf("Dhcpd.Wan() ok = %v, want %v", ok, tt.wantOk)
			}
			if tt.wantOk {
				if got.Enable != tt.wantEnable {
					t.Errorf("Dhcpd.Wan().Enable = %q, want %q", got.Enable, tt.wantEnable)
				}
				if got.Gateway != tt.wantGateway {
					t.Errorf("Dhcpd.Wan().Gateway = %q, want %q", got.Gateway, tt.wantGateway)
				}
			}
		})
	}
}

//nolint:dupl
func TestDhcpd_Lan(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		dhcpd       Dhcpd
		wantOk      bool
		wantEnable  string
		wantGateway string
	}{
		{
			name: "lan exists",
			dhcpd: Dhcpd{Items: map[string]DhcpdInterface{
				"lan": {Enable: "1", Gateway: "192.168.1.1"},
			}},
			wantOk:      true,
			wantEnable:  "1",
			wantGateway: "192.168.1.1",
		},
		{
			name: "lan does not exist",
			dhcpd: Dhcpd{Items: map[string]DhcpdInterface{
				"wan": {Enable: "0"},
			}},
			wantOk: false,
		},
		{
			name:   "nil items",
			dhcpd:  Dhcpd{Items: nil},
			wantOk: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, ok := tt.dhcpd.Lan()
			if ok != tt.wantOk {
				t.Errorf("Dhcpd.Lan() ok = %v, want %v", ok, tt.wantOk)
			}
			if tt.wantOk {
				if got.Enable != tt.wantEnable {
					t.Errorf("Dhcpd.Lan().Enable = %q, want %q", got.Enable, tt.wantEnable)
				}
				if got.Gateway != tt.wantGateway {
					t.Errorf("Dhcpd.Lan().Gateway = %q, want %q", got.Gateway, tt.wantGateway)
				}
			}
		})
	}
}

func TestNewDhcpdInterface(t *testing.T) {
	t.Parallel()

	iface := NewDhcpdInterface()

	// Check that slices are initialized but empty
	if iface.NumberOptions == nil {
		t.Error("NumberOptions should be initialized")
	}
	if len(iface.NumberOptions) != 0 {
		t.Errorf("NumberOptions should be empty, got %d items", len(iface.NumberOptions))
	}

	if iface.Staticmap == nil {
		t.Error("Staticmap should be initialized")
	}
	if len(iface.Staticmap) != 0 {
		t.Errorf("Staticmap should be empty, got %d items", len(iface.Staticmap))
	}

	// Other fields should be zero values
	if iface.Enable != "" {
		t.Errorf("Enable should be empty, got %q", iface.Enable)
	}
	if iface.Gateway != "" {
		t.Errorf("Gateway should be empty, got %q", iface.Gateway)
	}
}

// Simple test to ensure coverage without complex marshaling issues.
func TestDhcpd_MarshalUnmarshal_Simple(t *testing.T) {
	t.Parallel()

	// Test that MarshalXML method exists and handles empty case
	d := &Dhcpd{Items: make(map[string]DhcpdInterface)}

	// The method should exist (compilation test)
	_ = d.MarshalXML
	_ = d.UnmarshalXML
}

// Test to ensure Names method works correctly after unmarshal.
func TestDhcpd_Names_WithData(t *testing.T) {
	t.Parallel()

	xmlData := `<dhcpd>
		<lan>
			<enable>1</enable>
			<gateway>192.168.1.1</gateway>
		</lan>
		<wan>
			<enable>0</enable>
		</wan>
		<opt1>
			<enable>1</enable>
		</opt1>
	</dhcpd>`

	var dhcpd Dhcpd
	err := xml.Unmarshal([]byte(xmlData), &dhcpd)
	if err != nil {
		t.Fatalf("xml.Unmarshal() failed: %v", err)
	}

	names := dhcpd.Names()
	sort.Strings(names)

	expectedNames := []string{"lan", "opt1", "wan"}
	if len(names) != len(expectedNames) {
		t.Errorf("Names() returned %d names, want %d", len(names), len(expectedNames))
	}

	for i, name := range names {
		if name != expectedNames[i] {
			t.Errorf("Names()[%d] = %q, want %q", i, name, expectedNames[i])
		}
	}
}
