package builder

import (
	"slices"
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/model"
	"github.com/nao1215/markdown"
)

func TestFormatLeaseTime(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		seconds string
		want    string
	}{
		// Edge cases
		{name: "empty string", seconds: "", want: "-"},
		{name: "zero", seconds: "0", want: "-"},
		{name: "negative", seconds: "-1", want: "-"},
		{name: "invalid input", seconds: "abc", want: "abc"},
		{name: "floating point", seconds: "3600.5", want: "3600.5"},

		// Seconds
		{name: "1 second", seconds: "1", want: "1 second"},
		{name: "30 seconds", seconds: "30", want: "30 seconds"},
		{name: "59 seconds", seconds: "59", want: "59 seconds"},

		// Minutes
		{name: "1 minute", seconds: "60", want: "1 minute"},
		{name: "2 minutes", seconds: "120", want: "2 minutes"},
		{name: "1 minute 30 seconds", seconds: "90", want: "1 minute, 30 seconds"},
		{name: "5 minutes", seconds: "300", want: "5 minutes"},

		// Hours
		{name: "1 hour", seconds: "3600", want: "1 hour"},
		{name: "2 hours", seconds: "7200", want: "2 hours"},
		{name: "1 hour 30 minutes", seconds: "5400", want: "1 hour, 30 minutes"},
		{name: "12 hours", seconds: "43200", want: "12 hours"},
		{name: "23 hours 59 minutes", seconds: "86340", want: "23 hours, 59 minutes"},

		// Days
		{name: "1 day", seconds: "86400", want: "1 day"},
		{name: "2 days", seconds: "172800", want: "2 days"},
		{name: "1 day 12 hours", seconds: "129600", want: "1 day, 12 hours"},
		{name: "6 days", seconds: "518400", want: "6 days"},

		// Weeks
		{name: "1 week", seconds: "604800", want: "1 week"},
		{name: "2 weeks", seconds: "1209600", want: "2 weeks"},
		{name: "1 week 1 day", seconds: "691200", want: "1 week, 1 day"},
		{name: "1 week 3 days 12 hours", seconds: "907200", want: "1 week, 3 days, 12 hours"},

		// Common lease times
		{name: "30 day lease (common)", seconds: "2592000", want: "4 weeks, 2 days"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := FormatLeaseTime(tt.seconds)
			if got != tt.want {
				t.Errorf("FormatLeaseTime(%q) = %q, want %q", tt.seconds, got, tt.want)
			}
		})
	}
}

func TestHasAdvancedDHCPConfig(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		dhcp model.DhcpdInterface
		want bool
	}{
		{
			name: "empty config",
			dhcp: model.DhcpdInterface{},
			want: false,
		},
		{
			name: "basic config only",
			dhcp: model.DhcpdInterface{
				Enable:    "1",
				Gateway:   "192.168.1.1",
				Dnsserver: "8.8.8.8",
			},
			want: false,
		},
		// Alias fields
		{
			name: "alias address set",
			dhcp: model.DhcpdInterface{
				AliasAddress: "192.168.1.254",
			},
			want: true,
		},
		{
			name: "alias subnet set",
			dhcp: model.DhcpdInterface{
				AliasSubnet: "24",
			},
			want: true,
		},
		{
			name: "dhcp reject from set",
			dhcp: model.DhcpdInterface{
				DHCPRejectFrom: "192.168.1.100",
			},
			want: true,
		},
		// AdvDHCP* fields
		{
			name: "adv dhcp pt timeout set",
			dhcp: model.DhcpdInterface{
				AdvDHCPPTTimeout: "60",
			},
			want: true,
		},
		{
			name: "adv dhcp pt retry set",
			dhcp: model.DhcpdInterface{
				AdvDHCPPTRetry: "5",
			},
			want: true,
		},
		{
			name: "adv dhcp send options set",
			dhcp: model.DhcpdInterface{
				AdvDHCPSendOptions: "option1",
			},
			want: true,
		},
		{
			name: "adv dhcp request options set",
			dhcp: model.DhcpdInterface{
				AdvDHCPRequestOptions: "option2",
			},
			want: true,
		},
		{
			name: "adv dhcp required options set",
			dhcp: model.DhcpdInterface{
				AdvDHCPRequiredOptions: "option3",
			},
			want: true,
		},
		{
			name: "adv dhcp option modifiers set",
			dhcp: model.DhcpdInterface{
				AdvDHCPOptionModifiers: "modifier1",
			},
			want: true,
		},
		{
			name: "adv dhcp config advanced set",
			dhcp: model.DhcpdInterface{
				AdvDHCPConfigAdvanced: "advanced",
			},
			want: true,
		},
		{
			name: "adv dhcp config file override set",
			dhcp: model.DhcpdInterface{
				AdvDHCPConfigFileOverride: "1",
			},
			want: true,
		},
		{
			name: "adv dhcp config file override path set",
			dhcp: model.DhcpdInterface{
				AdvDHCPConfigFileOverridePath: "/path/to/file",
			},
			want: true,
		},
		{
			name: "multiple advanced fields set",
			dhcp: model.DhcpdInterface{
				AliasAddress:          "192.168.1.254",
				AdvDHCPSendOptions:    "option1",
				AdvDHCPConfigAdvanced: "advanced",
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := HasAdvancedDHCPConfig(tt.dhcp)
			if got != tt.want {
				t.Errorf("HasAdvancedDHCPConfig() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestHasDHCPv6Config(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		dhcp model.DhcpdInterface
		want bool
	}{
		{
			name: "empty config",
			dhcp: model.DhcpdInterface{},
			want: false,
		},
		{
			name: "basic ipv4 config only",
			dhcp: model.DhcpdInterface{
				Enable:    "1",
				Gateway:   "192.168.1.1",
				Dnsserver: "8.8.8.8",
			},
			want: false,
		},
		{
			name: "advanced ipv4 config only",
			dhcp: model.DhcpdInterface{
				AdvDHCPSendOptions: "option1",
			},
			want: false,
		},
		// Track6 fields
		{
			name: "track6 interface set",
			dhcp: model.DhcpdInterface{
				Track6Interface: "wan",
			},
			want: true,
		},
		{
			name: "track6 prefix id set",
			dhcp: model.DhcpdInterface{
				Track6PrefixID: "0",
			},
			want: true,
		},
		// AdvDHCP6* fields
		{
			name: "adv dhcp6 interface statement send options set",
			dhcp: model.DhcpdInterface{
				AdvDHCP6InterfaceStatementSendOptions: "option1",
			},
			want: true,
		},
		{
			name: "adv dhcp6 interface statement request options set",
			dhcp: model.DhcpdInterface{
				AdvDHCP6InterfaceStatementRequestOptions: "option2",
			},
			want: true,
		},
		{
			name: "adv dhcp6 information only enable set",
			dhcp: model.DhcpdInterface{
				AdvDHCP6InterfaceStatementInformationOnlyEnable: "1",
			},
			want: true,
		},
		{
			name: "adv dhcp6 interface statement script set",
			dhcp: model.DhcpdInterface{
				AdvDHCP6InterfaceStatementScript: "/path/to/script",
			},
			want: true,
		},
		{
			name: "adv dhcp6 id assoc address enable set",
			dhcp: model.DhcpdInterface{
				AdvDHCP6IDAssocStatementAddressEnable: "1",
			},
			want: true,
		},
		{
			name: "adv dhcp6 id assoc address set",
			dhcp: model.DhcpdInterface{
				AdvDHCP6IDAssocStatementAddress: "2001:db8::1",
			},
			want: true,
		},
		{
			name: "adv dhcp6 id assoc prefix enable set",
			dhcp: model.DhcpdInterface{
				AdvDHCP6IDAssocStatementPrefixEnable: "1",
			},
			want: true,
		},
		{
			name: "adv dhcp6 prefix interface sla len set",
			dhcp: model.DhcpdInterface{
				AdvDHCP6PrefixInterfaceStatementSLALen: "64",
			},
			want: true,
		},
		{
			name: "adv dhcp6 authentication auth name set",
			dhcp: model.DhcpdInterface{
				AdvDHCP6AuthenticationStatementAuthName: "authname",
			},
			want: true,
		},
		{
			name: "adv dhcp6 authentication protocol set",
			dhcp: model.DhcpdInterface{
				AdvDHCP6AuthenticationStatementProtocol: "delayed",
			},
			want: true,
		},
		{
			name: "adv dhcp6 key info key name set",
			dhcp: model.DhcpdInterface{
				AdvDHCP6KeyInfoStatementKeyName: "keyname",
			},
			want: true,
		},
		{
			name: "adv dhcp6 key info realm set",
			dhcp: model.DhcpdInterface{
				AdvDHCP6KeyInfoStatementRealm: "realm",
			},
			want: true,
		},
		{
			name: "adv dhcp6 config advanced set",
			dhcp: model.DhcpdInterface{
				AdvDHCP6ConfigAdvanced: "advanced",
			},
			want: true,
		},
		{
			name: "adv dhcp6 config file override set",
			dhcp: model.DhcpdInterface{
				AdvDHCP6ConfigFileOverride: "1",
			},
			want: true,
		},
		{
			name: "adv dhcp6 config file override path set",
			dhcp: model.DhcpdInterface{
				AdvDHCP6ConfigFileOverridePath: "/path/to/file",
			},
			want: true,
		},
		{
			name: "multiple dhcpv6 fields set",
			dhcp: model.DhcpdInterface{
				Track6Interface:                       "wan",
				AdvDHCP6IDAssocStatementAddressEnable: "1",
				AdvDHCP6ConfigAdvanced:                "advanced",
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := HasDHCPv6Config(tt.dhcp)
			if got != tt.want {
				t.Errorf("HasDHCPv6Config() = %v, want %v", got, tt.want)
			}
		})
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// DHCP Table Tests (Issue #68)
// ─────────────────────────────────────────────────────────────────────────────

func TestBuildDHCPSummaryTableSet(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		dhcpd        model.Dhcpd
		wantContains []string
		wantRows     int
	}{
		{
			name:         "empty dhcpd returns placeholder",
			dhcpd:        model.Dhcpd{Items: nil},
			wantContains: []string{"No DHCP scopes configured"},
			wantRows:     1,
		},
		{
			name: "empty items map returns placeholder",
			dhcpd: model.Dhcpd{
				Items: map[string]model.DhcpdInterface{},
			},
			wantContains: []string{"No DHCP scopes configured"},
			wantRows:     1,
		},
		{
			name: "single interface with basic config",
			dhcpd: model.Dhcpd{
				Items: map[string]model.DhcpdInterface{
					"lan": {
						Enable:    "1",
						Gateway:   "192.168.1.1",
						Range:     model.Range{From: "192.168.1.100", To: "192.168.1.200"},
						Dnsserver: "8.8.8.8",
					},
				},
			},
			wantContains: []string{"lan", "192.168.1.1", "192.168.1.100", "192.168.1.200", "8.8.8.8"},
			wantRows:     1,
		},
		{
			name: "multiple interfaces with deterministic ordering",
			dhcpd: model.Dhcpd{
				Items: map[string]model.DhcpdInterface{
					"wan": {
						Enable: "0",
					},
					"lan": {
						Enable:  "1",
						Gateway: "192.168.1.1",
						Range:   model.Range{From: "192.168.1.100", To: "192.168.1.200"},
					},
					"opt0": {
						Enable:  "1",
						Gateway: "10.0.0.1",
						Range:   model.Range{From: "10.0.0.50", To: "10.0.0.100"},
					},
				},
			},
			wantContains: []string{"lan", "wan", "opt0", "192.168.1.1", "10.0.0.1"},
			wantRows:     3,
		},
		{
			name: "interface with all fields populated",
			dhcpd: model.Dhcpd{
				Items: map[string]model.DhcpdInterface{
					"lan": {
						Enable:              "1",
						Gateway:             "192.168.1.1",
						Range:               model.Range{From: "192.168.1.100", To: "192.168.1.200"},
						Dnsserver:           "8.8.8.8",
						Winsserver:          "192.168.1.5",
						Ntpserver:           "pool.ntp.org",
						DdnsDomainAlgorithm: "hmac-md5",
					},
				},
			},
			wantContains: []string{"lan", "192.168.1.1", "8.8.8.8", "192.168.1.5", "pool.ntp.org", "hmac-md5"},
			wantRows:     1,
		},
	}

	dhcpSummaryHeaders := []string{
		"Interface", "Enabled", "Gateway", "Range Start", "Range End",
		"DNS", "WINS", "NTP", "DDNS Algorithm",
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			tableSet := BuildDHCPSummaryTableSet(tt.dhcpd)
			verifyTableSet(t, tableSet, dhcpSummaryHeaders, tt.wantRows, tt.wantContains)
		})
	}
}

func TestBuildDHCPStaticLeasesTableSet(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		leases       []model.DHCPStaticLease
		wantContains []string
		wantRows     int
	}{
		{
			name:         "empty leases returns placeholder",
			leases:       nil,
			wantContains: []string{"No static leases configured"},
			wantRows:     1,
		},
		{
			name:         "empty slice returns placeholder",
			leases:       []model.DHCPStaticLease{},
			wantContains: []string{"No static leases configured"},
			wantRows:     1,
		},
		{
			name: "basic lease with MAC IP and Hostname",
			leases: []model.DHCPStaticLease{
				{
					Mac:      "00:11:22:33:44:55",
					IPAddr:   "192.168.1.50",
					Hostname: "server1",
				},
			},
			wantContains: []string{"00:11:22:33:44:55", "192.168.1.50", "server1"},
			wantRows:     1,
		},
		{
			name: "multiple leases",
			leases: []model.DHCPStaticLease{
				{Mac: "00:11:22:33:44:55", IPAddr: "192.168.1.50", Hostname: "server1"},
				{Mac: "AA:BB:CC:DD:EE:FF", IPAddr: "192.168.1.51", Hostname: "server2"},
				{Mac: "11:22:33:44:55:66", IPAddr: "192.168.1.52", Hostname: "printer"},
			},
			wantContains: []string{
				"00:11:22:33:44:55", "192.168.1.50", "server1",
				"AA:BB:CC:DD:EE:FF", "192.168.1.51", "server2",
				"11:22:33:44:55:66", "192.168.1.52", "printer",
			},
			wantRows: 3,
		},
		{
			name: "full lease with all fields",
			leases: []model.DHCPStaticLease{
				{
					Mac:              "00:11:22:33:44:55",
					IPAddr:           "192.168.1.50",
					Hostname:         "pxe-server",
					Cid:              "client-id-123",
					Filename:         "pxelinux.0",
					Rootpath:         "/tftpboot",
					Defaultleasetime: "3600",
					Maxleasetime:     "7200",
					Descr:            "PXE boot server",
				},
			},
			wantContains: []string{
				"00:11:22:33:44:55", "192.168.1.50", "pxe-server",
				"client-id-123", "pxelinux.0", "/tftpboot",
				"1 hour", "2 hours", "PXE boot server",
			},
			wantRows: 1,
		},
	}

	staticLeasesHeaders := []string{
		"Hostname", "MAC", "IP", "CID", "Filename", "Rootpath",
		"Default Lease", "Max Lease", "Description",
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			tableSet := BuildDHCPStaticLeasesTableSet(tt.leases)
			verifyTableSet(t, tableSet, staticLeasesHeaders, tt.wantRows, tt.wantContains)
		})
	}
}

func TestBuildAdvancedDHCPItems(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		dhcp         model.DhcpdInterface
		wantContains []string
		wantLen      int
	}{
		{
			name:         "empty config returns empty slice",
			dhcp:         model.DhcpdInterface{},
			wantContains: nil,
			wantLen:      0,
		},
		{
			name: "alias fields populated",
			dhcp: model.DhcpdInterface{
				AliasAddress:   "192.168.1.254",
				AliasSubnet:    "24",
				DHCPRejectFrom: "192.168.1.100",
			},
			wantContains: []string{
				"Alias Address: 192.168.1.254",
				"Alias Subnet: 24",
				"DHCP Reject From: 192.168.1.100",
			},
			wantLen: 3,
		},
		{
			name: "advanced protocol timing fields",
			dhcp: model.DhcpdInterface{
				AdvDHCPPTTimeout:         "60",
				AdvDHCPPTRetry:           "5",
				AdvDHCPPTSelectTimeout:   "10",
				AdvDHCPPTReboot:          "30",
				AdvDHCPPTBackoffCutoff:   "120",
				AdvDHCPPTInitialInterval: "3",
			},
			wantContains: []string{
				"Protocol Timeout: 60", "Protocol Retry: 5", "Select Timeout: 10",
				"Reboot: 30", "Backoff Cutoff: 120", "Initial Interval: 3",
			},
			wantLen: 6,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			items := buildAdvancedDHCPItems(tt.dhcp)

			if len(items) != tt.wantLen {
				t.Errorf("Item count = %d, want %d", len(items), tt.wantLen)
			}

			for _, want := range tt.wantContains {
				if !slices.Contains(items, want) {
					t.Errorf("Items missing expected content: %q", want)
				}
			}
		})
	}
}

func TestBuildDHCPv6Items(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		dhcp         model.DhcpdInterface
		wantContains []string
		wantLen      int
	}{
		{
			name:         "empty config returns empty slice",
			dhcp:         model.DhcpdInterface{},
			wantContains: nil,
			wantLen:      0,
		},
		{
			name: "track6 fields populated",
			dhcp: model.DhcpdInterface{
				Track6Interface: "wan",
				Track6PrefixID:  "0",
			},
			wantContains: []string{"Track6 Interface: wan", "Track6 Prefix ID: 0"},
			wantLen:      2,
		},
		{
			name: "id assoc and prefix fields",
			dhcp: model.DhcpdInterface{
				AdvDHCP6IDAssocStatementAddressEnable: "1",
				AdvDHCP6IDAssocStatementAddress:       "2001:db8::1",
				AdvDHCP6IDAssocStatementAddressID:     "1",
				AdvDHCP6IDAssocStatementPrefixEnable:  "1",
				AdvDHCP6IDAssocStatementPrefix:        "2001:db8::/48",
			},
			wantContains: []string{
				"ID Assoc Address: Enabled", "Address: 2001:db8::1", "Address ID: 1",
				"ID Assoc Prefix: Enabled", "Prefix: 2001:db8::/48",
			},
			wantLen: 5,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			items := buildDHCPv6Items(tt.dhcp)

			if len(items) != tt.wantLen {
				t.Errorf("Item count = %d, want %d", len(items), tt.wantLen)
			}

			for _, want := range tt.wantContains {
				if !slices.Contains(items, want) {
					t.Errorf("Items missing expected content: %q", want)
				}
			}
		})
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Test Helpers
// ─────────────────────────────────────────────────────────────────────────────

// verifyTableSet validates a TableSet against expected headers, row count, and content.
func verifyTableSet(
	t *testing.T,
	tableSet *markdown.TableSet,
	expectedHeaders []string,
	wantRows int,
	wantContains []string,
) {
	t.Helper()

	// Verify header structure
	if len(tableSet.Header) != len(expectedHeaders) {
		t.Errorf("Header count = %d, want %d", len(tableSet.Header), len(expectedHeaders))
	}
	for i, hdr := range expectedHeaders {
		if i < len(tableSet.Header) && tableSet.Header[i] != hdr {
			t.Errorf("Header[%d] = %q, want %q", i, tableSet.Header[i], hdr)
		}
	}

	// Verify row count
	if len(tableSet.Rows) != wantRows {
		t.Errorf("Row count = %d, want %d", len(tableSet.Rows), wantRows)
	}

	// Verify expected content is present
	tableContent := flattenTableSet(tableSet)
	for _, want := range wantContains {
		if !containsString(tableContent, want) {
			t.Errorf("Table missing expected content: %q", want)
		}
	}
}

// flattenTableSet converts a TableSet into a flat string slice for easier content verification.
func flattenTableSet(ts *markdown.TableSet) []string {
	result := append([]string{}, ts.Header...)
	for _, row := range ts.Rows {
		result = append(result, row...)
	}
	return result
}

// containsString checks if a slice contains a specific string.
func containsString(slice []string, s string) bool {
	return slices.Contains(slice, s)
}
