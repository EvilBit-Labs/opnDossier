package builder

import (
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/model"
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
