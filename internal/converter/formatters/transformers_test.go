package formatters

import (
	"reflect"
	"testing"

	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
)

//nolint:funlen // test table or data declaration; length is in data not logic
func TestFilterSystemTunables(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name            string
		tunables        []common.SysctlItem
		includeTunables bool
		want            []common.SysctlItem
	}{
		{
			name:            "nil tunables",
			tunables:        nil,
			includeTunables: false,
			want:            nil,
		},
		{
			name:            "empty tunables",
			tunables:        []common.SysctlItem{},
			includeTunables: false,
			want:            []common.SysctlItem{},
		},
		{
			name: "include all tunables",
			tunables: []common.SysctlItem{
				{Tunable: "net.inet.ip.forwarding", Value: "0"},
				{Tunable: "vm.swapusage", Value: "1024"},
			},
			includeTunables: true,
			want: []common.SysctlItem{
				{Tunable: "net.inet.ip.forwarding", Value: "0"},
				{Tunable: "vm.swapusage", Value: "1024"},
			},
		},
		{
			name: "filter security tunables only",
			tunables: []common.SysctlItem{
				{Tunable: "net.inet.ip.forwarding", Value: "0"},
				{Tunable: "vm.swapusage", Value: "1024"},
				{Tunable: "net.inet6.ip6.forwarding", Value: "0"},
				{Tunable: "kern.securelevel", Value: "1"},
				{Tunable: "security.bsd.hardlink_check_uid", Value: "1"},
				{Tunable: "net.inet.tcp.blackhole", Value: "2"},
				{Tunable: "net.inet.udp.blackhole", Value: "1"},
			},
			includeTunables: false,
			want: []common.SysctlItem{
				{Tunable: "net.inet.ip.forwarding", Value: "0"},
				{Tunable: "net.inet6.ip6.forwarding", Value: "0"},
				{Tunable: "kern.securelevel", Value: "1"},
				{Tunable: "security.bsd.hardlink_check_uid", Value: "1"},
				{Tunable: "net.inet.tcp.blackhole", Value: "2"},
				{Tunable: "net.inet.udp.blackhole", Value: "1"},
			},
		},
		{
			name: "filter ICMP and redirect tunables",
			tunables: []common.SysctlItem{
				{Tunable: "net.inet.icmp.drop_redirect", Value: "1"},
				{Tunable: "net.inet.ip.redirect", Value: "0"},
				{Tunable: "net.inet6.icmp6.rediraccept", Value: "0"},
				{Tunable: "hw.memsize", Value: "8589934592"},
			},
			includeTunables: false,
			want: []common.SysctlItem{
				{Tunable: "net.inet.icmp.drop_redirect", Value: "1"},
				{Tunable: "net.inet.ip.redirect", Value: "0"},
				{Tunable: "net.inet6.icmp6.rediraccept", Value: "0"},
			},
		},
		{
			name: "filter source routing tunables",
			tunables: []common.SysctlItem{
				{Tunable: "net.inet.ip.sourceroute", Value: "0"},
				{Tunable: "net.inet.ip.accept_sourceroute", Value: "0"},
				{Tunable: "vm.swapusage", Value: "1024"},
			},
			includeTunables: false,
			want: []common.SysctlItem{
				{Tunable: "net.inet.ip.sourceroute", Value: "0"},
				{Tunable: "net.inet.ip.accept_sourceroute", Value: "0"},
			},
		},
		{
			name: "filter TCP and UDP attack mitigation tunables",
			tunables: []common.SysctlItem{
				{Tunable: "net.inet.tcp.drop_synfin", Value: "1"},
				{Tunable: "net.inet.tcp.syncookies", Value: "1"},
				{Tunable: "net.inet.tcp.log_in_vain", Value: "1"},
				{Tunable: "net.inet.udp.log_in_vain", Value: "1"},
				{Tunable: "hw.memsize", Value: "8589934592"},
			},
			includeTunables: false,
			want: []common.SysctlItem{
				{Tunable: "net.inet.tcp.drop_synfin", Value: "1"},
				{Tunable: "net.inet.tcp.syncookies", Value: "1"},
				{Tunable: "net.inet.tcp.log_in_vain", Value: "1"},
				{Tunable: "net.inet.udp.log_in_vain", Value: "1"},
			},
		},
		{
			name: "filter kernel security tunables",
			tunables: []common.SysctlItem{
				{Tunable: "kern.randompid", Value: "1"},
				{Tunable: "kern.coredump", Value: "0"},
				{Tunable: "kern.maxfiles", Value: "65536"},
			},
			includeTunables: false,
			want: []common.SysctlItem{
				{Tunable: "kern.randompid", Value: "1"},
				{Tunable: "kern.coredump", Value: "0"},
			},
		},
		{
			name: "skip empty tunable names",
			tunables: []common.SysctlItem{
				{Tunable: "", Value: "0"},
				{Tunable: "net.inet.ip.forwarding", Value: "0"},
			},
			includeTunables: false,
			want: []common.SysctlItem{
				{Tunable: "net.inet.ip.forwarding", Value: "0"},
			},
		},
		{
			name: "no security tunables found",
			tunables: []common.SysctlItem{
				{Tunable: "vm.swapusage", Value: "1024"},
				{Tunable: "hw.memsize", Value: "8589934592"},
			},
			includeTunables: false,
			want:            []common.SysctlItem{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := FilterSystemTunables(tt.tunables, tt.includeTunables)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("FilterSystemTunables() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAggregatePackageStats(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		packages []common.Package
		want     map[string]int
	}{
		{
			name:     "nil packages",
			packages: nil,
			want:     nil,
		},
		{
			name:     "empty packages",
			packages: []common.Package{},
			want: map[string]int{
				"total":     0,
				"installed": 0,
				"locked":    0,
				"automatic": 0,
			},
		},
		{
			name: "mixed packages",
			packages: []common.Package{
				{Name: "pkg1", Installed: true, Locked: false, Automatic: false},
				{Name: "pkg2", Installed: false, Locked: true, Automatic: false},
				{Name: "pkg3", Installed: true, Locked: true, Automatic: true},
				{Name: "pkg4", Installed: false, Locked: false, Automatic: true},
			},
			want: map[string]int{
				"total":     4,
				"installed": 2,
				"locked":    2,
				"automatic": 2,
			},
		},
		{
			name: "all features enabled",
			packages: []common.Package{
				{Name: "pkg1", Installed: true, Locked: true, Automatic: true},
				{Name: "pkg2", Installed: true, Locked: true, Automatic: true},
			},
			want: map[string]int{
				"total":     2,
				"installed": 2,
				"locked":    2,
				"automatic": 2,
			},
		},
		{
			name: "no features enabled",
			packages: []common.Package{
				{Name: "pkg1", Installed: false, Locked: false, Automatic: false},
				{Name: "pkg2", Installed: false, Locked: false, Automatic: false},
			},
			want: map[string]int{
				"total":     2,
				"installed": 0,
				"locked":    0,
				"automatic": 0,
			},
		},
		{
			name: "packages with empty names are skipped for flags but counted in total",
			packages: []common.Package{
				{Name: "", Installed: true, Locked: true, Automatic: true},
				{Name: "pkg1", Installed: true, Locked: false, Automatic: false},
			},
			want: map[string]int{
				"total":     2,
				"installed": 1,
				"locked":    0,
				"automatic": 0,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := AggregatePackageStats(tt.packages)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("AggregatePackageStats() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFilterRulesByType(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		rules    []common.FirewallRule
		ruleType common.FirewallRuleType
		want     []common.FirewallRule
	}{
		{
			name:     "nil rules",
			rules:    nil,
			ruleType: common.RuleTypePass,
			want:     nil,
		},
		{
			name:     "empty rules",
			rules:    []common.FirewallRule{},
			ruleType: common.RuleTypePass,
			want:     []common.FirewallRule{},
		},
		{
			name: "empty rule type returns all rules",
			rules: []common.FirewallRule{
				{Type: common.RuleTypePass},
				{Type: common.RuleTypeBlock},
			},
			ruleType: "",
			want: []common.FirewallRule{
				{Type: common.RuleTypePass},
				{Type: common.RuleTypeBlock},
			},
		},
		{
			name: "filter by pass rules",
			rules: []common.FirewallRule{
				{Type: common.RuleTypePass},
				{Type: common.RuleTypeBlock},
				{Type: common.RuleTypePass},
				{Type: common.RuleTypeReject},
			},
			ruleType: common.RuleTypePass,
			want: []common.FirewallRule{
				{Type: common.RuleTypePass},
				{Type: common.RuleTypePass},
			},
		},
		{
			name: "filter by block rules",
			rules: []common.FirewallRule{
				{Type: common.RuleTypePass},
				{Type: common.RuleTypeBlock},
				{Type: common.RuleTypePass},
				{Type: common.RuleTypeBlock},
			},
			ruleType: common.RuleTypeBlock,
			want: []common.FirewallRule{
				{Type: common.RuleTypeBlock},
				{Type: common.RuleTypeBlock},
			},
		},
		{
			name: "no matching rules",
			rules: []common.FirewallRule{
				{Type: common.RuleTypePass},
				{Type: common.RuleTypeBlock},
			},
			ruleType: common.RuleTypeReject,
			want:     []common.FirewallRule{},
		},
		{
			name: "rules with empty type are skipped",
			rules: []common.FirewallRule{
				{Type: ""},
				{Type: common.RuleTypePass},
				{Type: ""},
			},
			ruleType: common.RuleTypePass,
			want: []common.FirewallRule{
				{Type: common.RuleTypePass},
			},
		},
		{
			name: "case sensitive matching",
			rules: []common.FirewallRule{
				{Type: common.RuleTypePass},
				{Type: common.FirewallRuleType("PASS")},
			},
			ruleType: common.RuleTypePass,
			want: []common.FirewallRule{
				{Type: common.RuleTypePass},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := FilterRulesByType(tt.rules, tt.ruleType)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("FilterRulesByType() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestExtractUniqueValues(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		items []string
		want  []string
	}{
		{
			name:  "nil items",
			items: nil,
			want:  nil,
		},
		{
			name:  "empty items",
			items: []string{},
			want:  []string{},
		},
		{
			name:  "single item",
			items: []string{"apple"},
			want:  []string{"apple"},
		},
		{
			name:  "single empty item",
			items: []string{""},
			want:  []string{},
		},
		{
			name:  "unique items",
			items: []string{"apple", "banana", "cherry"},
			want:  []string{"apple", "banana", "cherry"},
		},
		{
			name:  "duplicate items",
			items: []string{"apple", "banana", "apple", "cherry", "banana"},
			want:  []string{"apple", "banana", "cherry"},
		},
		{
			name:  "items with empty strings",
			items: []string{"apple", "", "banana", "", "cherry"},
			want:  []string{"apple", "banana", "cherry"},
		},
		{
			name:  "all empty strings",
			items: []string{"", "", ""},
			want:  []string{},
		},
		{
			name:  "unsorted input gets sorted output",
			items: []string{"zebra", "apple", "banana"},
			want:  []string{"apple", "banana", "zebra"},
		},
		{
			name:  "case sensitive sorting",
			items: []string{"Apple", "apple", "Banana", "banana"},
			want:  []string{"Apple", "Banana", "apple", "banana"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := ExtractUniqueValues(tt.items)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ExtractUniqueValues() = %v, want %v", got, tt.want)
			}
		})
	}
}
