package builder

import (
	"slices"
	"strings"
	"testing"

	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
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
		dhcp common.DHCPScope
		want bool
	}{
		{
			name: "empty config",
			dhcp: common.DHCPScope{},
			want: false,
		},
		{
			name: "basic config only",
			dhcp: common.DHCPScope{
				Enabled:   true,
				Gateway:   "192.168.1.1",
				DNSServer: "8.8.8.8",
			},
			want: false,
		},
		// Alias fields
		{
			name: "alias address set",
			dhcp: common.DHCPScope{
				AdvancedV4: &common.DHCPAdvancedV4{AliasAddress: "192.168.1.254"},
			},
			want: true,
		},
		{
			name: "alias subnet set",
			dhcp: common.DHCPScope{
				AdvancedV4: &common.DHCPAdvancedV4{AliasSubnet: "24"},
			},
			want: true,
		},
		{
			name: "dhcp reject from set",
			dhcp: common.DHCPScope{
				AdvancedV4: &common.DHCPAdvancedV4{DHCPRejectFrom: "192.168.1.100"},
			},
			want: true,
		},
		// AdvDHCP* fields
		{
			name: "adv dhcp pt timeout set",
			dhcp: common.DHCPScope{
				AdvancedV4: &common.DHCPAdvancedV4{AdvDHCPPTTimeout: "60"},
			},
			want: true,
		},
		{
			name: "adv dhcp pt retry set",
			dhcp: common.DHCPScope{
				AdvancedV4: &common.DHCPAdvancedV4{AdvDHCPPTRetry: "5"},
			},
			want: true,
		},
		{
			name: "adv dhcp send options set",
			dhcp: common.DHCPScope{
				AdvancedV4: &common.DHCPAdvancedV4{AdvDHCPSendOptions: "option1"},
			},
			want: true,
		},
		{
			name: "adv dhcp request options set",
			dhcp: common.DHCPScope{
				AdvancedV4: &common.DHCPAdvancedV4{AdvDHCPRequestOptions: "option2"},
			},
			want: true,
		},
		{
			name: "adv dhcp required options set",
			dhcp: common.DHCPScope{
				AdvancedV4: &common.DHCPAdvancedV4{AdvDHCPRequiredOptions: "option3"},
			},
			want: true,
		},
		{
			name: "adv dhcp option modifiers set",
			dhcp: common.DHCPScope{
				AdvancedV4: &common.DHCPAdvancedV4{AdvDHCPOptionModifiers: "modifier1"},
			},
			want: true,
		},
		{
			name: "adv dhcp config advanced set",
			dhcp: common.DHCPScope{
				AdvancedV4: &common.DHCPAdvancedV4{AdvDHCPConfigAdvanced: "advanced"},
			},
			want: true,
		},
		{
			name: "adv dhcp config file override set",
			dhcp: common.DHCPScope{
				AdvancedV4: &common.DHCPAdvancedV4{AdvDHCPConfigFileOverride: "1"},
			},
			want: true,
		},
		{
			name: "adv dhcp config file override path set",
			dhcp: common.DHCPScope{
				AdvancedV4: &common.DHCPAdvancedV4{AdvDHCPConfigFileOverridePath: "/path/to/file"},
			},
			want: true,
		},
		{
			name: "multiple advanced fields set",
			dhcp: common.DHCPScope{
				AdvancedV4: &common.DHCPAdvancedV4{
					AliasAddress:          "192.168.1.254",
					AdvDHCPSendOptions:    "option1",
					AdvDHCPConfigAdvanced: "advanced",
				},
			},
			want: true,
		},
		// Protocol timing fields
		{
			name: "adv dhcp pt timeout set",
			dhcp: common.DHCPScope{
				AdvancedV4: &common.DHCPAdvancedV4{AdvDHCPPTTimeout: "60"},
			},
			want: true,
		},
		{
			name: "adv dhcp config file override path set via remaining field",
			dhcp: common.DHCPScope{
				AdvancedV4: &common.DHCPAdvancedV4{AdvDHCPConfigFileOverridePath: "/etc/dhcp.conf"},
			},
			want: true,
		},
		{
			name: "non-nil but empty advanced v4",
			dhcp: common.DHCPScope{
				AdvancedV4: &common.DHCPAdvancedV4{},
			},
			want: false,
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
		dhcp common.DHCPScope
		want bool
	}{
		{
			name: "empty config",
			dhcp: common.DHCPScope{},
			want: false,
		},
		{
			name: "basic ipv4 config only",
			dhcp: common.DHCPScope{
				Enabled:   true,
				Gateway:   "192.168.1.1",
				DNSServer: "8.8.8.8",
			},
			want: false,
		},
		{
			name: "advanced ipv4 config only",
			dhcp: common.DHCPScope{
				AdvancedV4: &common.DHCPAdvancedV4{AdvDHCPSendOptions: "option1"},
			},
			want: false,
		},
		// Track6 fields
		{
			name: "track6 interface set",
			dhcp: common.DHCPScope{
				AdvancedV6: &common.DHCPAdvancedV6{Track6Interface: "wan"},
			},
			want: true,
		},
		{
			name: "track6 prefix id set",
			dhcp: common.DHCPScope{
				AdvancedV6: &common.DHCPAdvancedV6{Track6PrefixID: "0"},
			},
			want: true,
		},
		// AdvDHCP6* fields
		{
			name: "adv dhcp6 interface statement send options set",
			dhcp: common.DHCPScope{
				AdvancedV6: &common.DHCPAdvancedV6{AdvDHCP6InterfaceStatementSendOptions: "option1"},
			},
			want: true,
		},
		{
			name: "adv dhcp6 interface statement request options set",
			dhcp: common.DHCPScope{
				AdvancedV6: &common.DHCPAdvancedV6{AdvDHCP6InterfaceStatementRequestOptions: "option2"},
			},
			want: true,
		},
		{
			name: "adv dhcp6 information only enable set",
			dhcp: common.DHCPScope{
				AdvancedV6: &common.DHCPAdvancedV6{AdvDHCP6InterfaceStatementInformationOnlyEnable: "1"},
			},
			want: true,
		},
		{
			name: "adv dhcp6 interface statement script set",
			dhcp: common.DHCPScope{
				AdvancedV6: &common.DHCPAdvancedV6{AdvDHCP6InterfaceStatementScript: "/path/to/script"},
			},
			want: true,
		},
		{
			name: "adv dhcp6 id assoc address enable set",
			dhcp: common.DHCPScope{
				AdvancedV6: &common.DHCPAdvancedV6{AdvDHCP6IDAssocStatementAddressEnable: "1"},
			},
			want: true,
		},
		{
			name: "adv dhcp6 id assoc address set",
			dhcp: common.DHCPScope{
				AdvancedV6: &common.DHCPAdvancedV6{AdvDHCP6IDAssocStatementAddress: "2001:db8::1"},
			},
			want: true,
		},
		{
			name: "adv dhcp6 id assoc prefix enable set",
			dhcp: common.DHCPScope{
				AdvancedV6: &common.DHCPAdvancedV6{AdvDHCP6IDAssocStatementPrefixEnable: "1"},
			},
			want: true,
		},
		{
			name: "adv dhcp6 prefix interface sla len set",
			dhcp: common.DHCPScope{
				AdvancedV6: &common.DHCPAdvancedV6{AdvDHCP6PrefixInterfaceStatementSLALen: "64"},
			},
			want: true,
		},
		{
			name: "adv dhcp6 authentication auth name set",
			dhcp: common.DHCPScope{
				AdvancedV6: &common.DHCPAdvancedV6{AdvDHCP6AuthenticationStatementAuthName: "authname"},
			},
			want: true,
		},
		{
			name: "adv dhcp6 authentication protocol set",
			dhcp: common.DHCPScope{
				AdvancedV6: &common.DHCPAdvancedV6{AdvDHCP6AuthenticationStatementProtocol: "delayed"},
			},
			want: true,
		},
		{
			name: "adv dhcp6 key info key name set",
			dhcp: common.DHCPScope{
				AdvancedV6: &common.DHCPAdvancedV6{AdvDHCP6KeyInfoStatementKeyName: "keyname"},
			},
			want: true,
		},
		{
			name: "adv dhcp6 key info realm set",
			dhcp: common.DHCPScope{
				AdvancedV6: &common.DHCPAdvancedV6{AdvDHCP6KeyInfoStatementRealm: "realm"},
			},
			want: true,
		},
		{
			name: "adv dhcp6 config advanced set",
			dhcp: common.DHCPScope{
				AdvancedV6: &common.DHCPAdvancedV6{AdvDHCP6ConfigAdvanced: "advanced"},
			},
			want: true,
		},
		{
			name: "adv dhcp6 config file override set",
			dhcp: common.DHCPScope{
				AdvancedV6: &common.DHCPAdvancedV6{AdvDHCP6ConfigFileOverride: "1"},
			},
			want: true,
		},
		{
			name: "adv dhcp6 config file override path set",
			dhcp: common.DHCPScope{
				AdvancedV6: &common.DHCPAdvancedV6{AdvDHCP6ConfigFileOverridePath: "/path/to/file"},
			},
			want: true,
		},
		{
			name: "multiple dhcpv6 fields set",
			dhcp: common.DHCPScope{
				AdvancedV6: &common.DHCPAdvancedV6{
					Track6Interface:                       "wan",
					AdvDHCP6IDAssocStatementAddressEnable: "1",
					AdvDHCP6ConfigAdvanced:                "advanced",
				},
			},
			want: true,
		},
		// Empty non-nil AdvancedV6
		{
			name: "non-nil but empty advanced v6",
			dhcp: common.DHCPScope{
				AdvancedV6: &common.DHCPAdvancedV6{},
			},
			want: false,
		},
		// Lifetime fields
		{
			name: "address preferred lifetime only",
			dhcp: common.DHCPScope{
				AdvancedV6: &common.DHCPAdvancedV6{AdvDHCP6IDAssocStatementAddressPLTime: "3600"},
			},
			want: true,
		},
		{
			name: "address valid lifetime only",
			dhcp: common.DHCPScope{
				AdvancedV6: &common.DHCPAdvancedV6{AdvDHCP6IDAssocStatementAddressVLTime: "7200"},
			},
			want: true,
		},
		{
			name: "prefix preferred lifetime only",
			dhcp: common.DHCPScope{
				AdvancedV6: &common.DHCPAdvancedV6{AdvDHCP6IDAssocStatementPrefixPLTime: "1800"},
			},
			want: true,
		},
		{
			name: "prefix valid lifetime only",
			dhcp: common.DHCPScope{
				AdvancedV6: &common.DHCPAdvancedV6{AdvDHCP6IDAssocStatementPrefixVLTime: "3600"},
			},
			want: true,
		},
		// Auth RDM
		{
			name: "auth rdm only",
			dhcp: common.DHCPScope{
				AdvancedV6: &common.DHCPAdvancedV6{AdvDHCP6AuthenticationStatementRDM: "monotonic-clock"},
			},
			want: true,
		},
		// Key metadata
		{
			name: "key id only",
			dhcp: common.DHCPScope{
				AdvancedV6: &common.DHCPAdvancedV6{AdvDHCP6KeyInfoStatementKeyID: "42"},
			},
			want: true,
		},
		{
			name: "key secret only",
			dhcp: common.DHCPScope{
				AdvancedV6: &common.DHCPAdvancedV6{AdvDHCP6KeyInfoStatementSecret: "secret123"},
			},
			want: true,
		},
		{
			name: "key expire only",
			dhcp: common.DHCPScope{
				AdvancedV6: &common.DHCPAdvancedV6{AdvDHCP6KeyInfoStatementExpire: "2026-12-31"},
			},
			want: true,
		},
		// Basic DHCPv6 tracking fields
		{
			name: "dhcpv6 track6 interface set",
			dhcp: common.DHCPScope{
				AdvancedV6: &common.DHCPAdvancedV6{Track6Interface: "wan"},
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
		scopes       []common.DHCPScope
		wantContains []string
		wantRows     int
	}{
		{
			name:         "empty scopes returns placeholder",
			scopes:       nil,
			wantContains: []string{"No DHCP scopes configured"},
			wantRows:     1,
		},
		{
			name:         "empty slice returns placeholder",
			scopes:       []common.DHCPScope{},
			wantContains: []string{"No DHCP scopes configured"},
			wantRows:     1,
		},
		{
			name: "single interface with basic config",
			scopes: []common.DHCPScope{
				{
					Interface: "lan",
					Enabled:   true,
					Gateway:   "192.168.1.1",
					Range:     common.DHCPRange{From: "192.168.1.100", To: "192.168.1.200"},
					DNSServer: "8.8.8.8",
				},
			},
			wantContains: []string{"lan", "192.168.1.1", "192.168.1.100", "192.168.1.200", "8.8.8.8"},
			wantRows:     1,
		},
		{
			name: "multiple interfaces",
			scopes: []common.DHCPScope{
				{
					Interface: "wan",
					Enabled:   false,
				},
				{
					Interface: "lan",
					Enabled:   true,
					Gateway:   "192.168.1.1",
					Range:     common.DHCPRange{From: "192.168.1.100", To: "192.168.1.200"},
				},
				{
					Interface: "opt0",
					Enabled:   true,
					Gateway:   "10.0.0.1",
					Range:     common.DHCPRange{From: "10.0.0.50", To: "10.0.0.100"},
				},
			},
			wantContains: []string{"lan", "wan", "opt0", "192.168.1.1", "10.0.0.1"},
			wantRows:     3,
		},
		{
			name: "interface with all fields populated",
			scopes: []common.DHCPScope{
				{
					Interface:  "lan",
					Enabled:    true,
					Gateway:    "192.168.1.1",
					Range:      common.DHCPRange{From: "192.168.1.100", To: "192.168.1.200"},
					DNSServer:  "8.8.8.8",
					WINSServer: "192.168.1.5",
					NTPServer:  "pool.ntp.org",
				},
			},
			wantContains: []string{"lan", "192.168.1.1", "8.8.8.8", "192.168.1.5", "pool.ntp.org"},
			wantRows:     1,
		},
	}

	dhcpSummaryHeaders := []string{
		"Interface", "Enabled", "Gateway", "Range Start", "Range End",
		"DNS", "WINS", "NTP",
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			tableSet := BuildDHCPSummaryTableSet(tt.scopes)
			verifyTableSet(t, tableSet, dhcpSummaryHeaders, tt.wantRows, tt.wantContains)
		})
	}
}

func TestBuildDHCPStaticLeasesTableSet(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		leases       []common.DHCPStaticLease
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
			leases:       []common.DHCPStaticLease{},
			wantContains: []string{"No static leases configured"},
			wantRows:     1,
		},
		{
			name: "basic lease with MAC IP and Hostname",
			leases: []common.DHCPStaticLease{
				{
					MAC:       "00:11:22:33:44:55",
					IPAddress: "192.168.1.50",
					Hostname:  "server1",
				},
			},
			wantContains: []string{"00:11:22:33:44:55", "192.168.1.50", "server1"},
			wantRows:     1,
		},
		{
			name: "multiple leases",
			leases: []common.DHCPStaticLease{
				{MAC: "00:11:22:33:44:55", IPAddress: "192.168.1.50", Hostname: "server1"},
				{MAC: "AA:BB:CC:DD:EE:FF", IPAddress: "192.168.1.51", Hostname: "server2"},
				{MAC: "11:22:33:44:55:66", IPAddress: "192.168.1.52", Hostname: "printer"},
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
			leases: []common.DHCPStaticLease{
				{
					MAC:              "00:11:22:33:44:55",
					IPAddress:        "192.168.1.50",
					Hostname:         "pxe-server",
					CID:              "client-id-123",
					Filename:         "pxelinux.0",
					Rootpath:         "/tftpboot",
					DefaultLeaseTime: "3600",
					MaxLeaseTime:     "7200",
					Description:      "PXE boot server",
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
		dhcp         common.DHCPScope
		wantContains []string
		wantLen      int
	}{
		{
			name:         "empty config returns empty slice",
			dhcp:         common.DHCPScope{},
			wantContains: nil,
			wantLen:      0,
		},
		{
			name: "alias fields populated",
			dhcp: common.DHCPScope{
				AdvancedV4: &common.DHCPAdvancedV4{
					AliasAddress:   "192.168.1.254",
					AliasSubnet:    "24",
					DHCPRejectFrom: "192.168.1.100",
				},
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
			dhcp: common.DHCPScope{
				AdvancedV4: &common.DHCPAdvancedV4{
					AdvDHCPPTTimeout:         "60",
					AdvDHCPPTRetry:           "5",
					AdvDHCPPTSelectTimeout:   "10",
					AdvDHCPPTReboot:          "30",
					AdvDHCPPTBackoffCutoff:   "120",
					AdvDHCPPTInitialInterval: "3",
				},
			},
			wantContains: []string{
				"Protocol Timeout: 60", "Protocol Retry: 5", "Select Timeout: 10",
				"Reboot: 30", "Backoff Cutoff: 120", "Initial Interval: 3",
			},
			wantLen: 6,
		},
		{
			name: "option and config override fields",
			dhcp: common.DHCPScope{
				AdvancedV4: &common.DHCPAdvancedV4{
					AdvDHCPSendOptions:            "option1",
					AdvDHCPRequestOptions:         "option2",
					AdvDHCPRequiredOptions:        "option3",
					AdvDHCPOptionModifiers:        "modifier1",
					AdvDHCPConfigAdvanced:         "advanced",
					AdvDHCPConfigFileOverride:     "1",
					AdvDHCPConfigFileOverridePath: "/path/to/file",
				},
			},
			wantContains: []string{
				"Send Options: option1",
				"Request Options: option2",
				"Required Options: option3",
				"Option Modifiers: modifier1",
				"Advanced Config: Enabled",
				"Config File Override: Enabled",
				"Override Path: /path/to/file",
			},
			wantLen: 7,
		},
		{
			name: "non-nil but empty advanced v4",
			dhcp: common.DHCPScope{
				AdvancedV4: &common.DHCPAdvancedV4{},
			},
			wantContains: nil,
			wantLen:      0,
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
		dhcp         common.DHCPScope
		wantContains []string
		wantLen      int
	}{
		{
			name:         "empty config returns empty slice",
			dhcp:         common.DHCPScope{},
			wantContains: nil,
			wantLen:      0,
		},
		{
			name: "track6 fields populated",
			dhcp: common.DHCPScope{
				AdvancedV6: &common.DHCPAdvancedV6{
					Track6Interface: "wan",
					Track6PrefixID:  "0",
				},
			},
			wantContains: []string{"Track6 Interface: wan", "Track6 Prefix ID: 0"},
			wantLen:      2,
		},
		{
			name: "id assoc and prefix fields",
			dhcp: common.DHCPScope{
				AdvancedV6: &common.DHCPAdvancedV6{
					AdvDHCP6IDAssocStatementAddressEnable: "1",
					AdvDHCP6IDAssocStatementAddress:       "2001:db8::1",
					AdvDHCP6IDAssocStatementAddressID:     "1",
					AdvDHCP6IDAssocStatementPrefixEnable:  "1",
					AdvDHCP6IDAssocStatementPrefix:        "2001:db8::/48",
				},
			},
			wantContains: []string{
				"ID Assoc Address: Enabled", "Address: 2001:db8::1", "Address ID: 1",
				"ID Assoc Prefix: Enabled", "Prefix: 2001:db8::/48",
			},
			wantLen: 5,
		},
		{
			name: "lifetime fields only",
			dhcp: common.DHCPScope{
				AdvancedV6: &common.DHCPAdvancedV6{
					AdvDHCP6IDAssocStatementAddressPLTime: "3600",
					AdvDHCP6IDAssocStatementAddressVLTime: "7200",
					AdvDHCP6IDAssocStatementPrefixPLTime:  "1800",
					AdvDHCP6IDAssocStatementPrefixVLTime:  "3600",
				},
			},
			wantContains: []string{
				"Address Preferred Lifetime: 3600",
				"Address Valid Lifetime: 7200",
				"Prefix Preferred Lifetime: 1800",
				"Prefix Valid Lifetime: 3600",
			},
			wantLen: 4,
		},
		{
			name: "auth rdm only",
			dhcp: common.DHCPScope{
				AdvancedV6: &common.DHCPAdvancedV6{
					AdvDHCP6AuthenticationStatementRDM: "monotonic-clock",
				},
			},
			wantContains: []string{"Auth RDM: monotonic-clock"},
			wantLen:      1,
		},
		{
			name: "key metadata fields",
			dhcp: common.DHCPScope{
				AdvancedV6: &common.DHCPAdvancedV6{
					AdvDHCP6KeyInfoStatementKeyID:  "42",
					AdvDHCP6KeyInfoStatementSecret: "secret123",
					AdvDHCP6KeyInfoStatementExpire: "2026-12-31",
				},
			},
			wantContains: []string{
				"Key ID: 42",
				"Key Secret: secret123",
				"Key Expire: 2026-12-31",
			},
			wantLen: 3,
		},
		{
			name: "basic dhcpv6 tracking fields",
			dhcp: common.DHCPScope{
				AdvancedV6: &common.DHCPAdvancedV6{
					Track6Interface: "wan",
					Track6PrefixID:  "0",
				},
			},
			wantContains: []string{
				"Track6 Interface: wan",
				"Track6 Prefix ID: 0",
			},
			wantLen: 2,
		},
		{
			name: "non-nil but empty advanced v6",
			dhcp: common.DHCPScope{
				AdvancedV6: &common.DHCPAdvancedV6{},
			},
			wantContains: nil,
			wantLen:      0,
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

// ─────────────────────────────────────────────────────────────────────────────
// EscapePipeForMarkdown Tests
// ─────────────────────────────────────────────────────────────────────────────

func TestEscapePipeForMarkdown(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"no pipes", "hello world", "hello world"},
		{"single pipe", "a|b", "a\\|b"},
		{"multiple pipes", "a|b|c", "a\\|b\\|c"},
		{"empty string", "", ""},
		{"pipe at start", "|hello", "\\|hello"},
		{"pipe at end", "hello|", "hello\\|"},
		{"only pipe", "|", "\\|"},
		{"adjacent pipes", "a||b", "a\\|\\|b"},
		{"pipes with spaces", "a | b | c", "a \\| b \\| c"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := EscapePipeForMarkdown(tt.input)
			if result != tt.expected {
				t.Errorf("EscapePipeForMarkdown(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// TruncateString Tests
// ─────────────────────────────────────────────────────────────────────────────

func TestTruncateString(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    string
		maxLen   int
		expected string
	}{
		{"short string", "hello", 10, "hello"},
		{"exact length", "hello", 5, "hello"},
		{"needs truncation", "hello world", 8, "hello..."},
		{"empty string", "", 10, ""},
		{"very short max", "hello world", 4, "h..."},
		{"four char max", "hello", 4, "h..."},
		{"five char max", "hello world", 5, "he..."},
		{"long string", strings.Repeat("a", 100), 20, strings.Repeat("a", 17) + "..."},
		// Rune-aware truncation: multi-byte characters are not split
		{"unicode emoji", "Hello \U0001f30d\U0001f30e\U0001f30f World", 10, "Hello \U0001f30d..."},
		{"japanese text", "\u3053\u3093\u306b\u3061\u306f\u4e16\u754c", 5, "\u3053\u3093..."},
		{"mixed unicode", "Test\u65e5\u672c\u8a9eText", 8, "Test\u65e5..."},
		{"zero maxLen", "hello", 0, ""},
		{"negative maxLen", "hello", -1, ""},
		{"maxLen equals ellipsis len", "hello", 3, "hel"},
		{"maxLen less than ellipsis len", "hello world", 2, "he"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := TruncateString(tt.input, tt.maxLen)
			if result != tt.expected {
				t.Errorf("TruncateString(%q, %d) = %q, want %q", tt.input, tt.maxLen, result, tt.expected)
			}
		})
	}
}

func TestTruncateString_MaxDescriptionLength(t *testing.T) {
	t.Parallel()

	longDescription := strings.Repeat("a", 100)
	result := TruncateString(longDescription, MaxDescriptionLength)

	if len([]rune(result)) > MaxDescriptionLength {
		t.Errorf(
			"TruncateString result rune length %d exceeds MaxDescriptionLength %d",
			len([]rune(result)),
			MaxDescriptionLength,
		)
	}
	if !strings.HasSuffix(result, "...") {
		t.Error("Truncated string should end with '...'")
	}
}
