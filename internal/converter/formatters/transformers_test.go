package formatters

import (
	"reflect"
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/model"
)

func TestFilterSystemTunables(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name            string
		tunables        []model.SysctlItem
		includeTunables bool
		want            []model.SysctlItem
	}{
		{
			name:            "nil tunables",
			tunables:        nil,
			includeTunables: false,
			want:            nil,
		},
		{
			name:            "empty tunables",
			tunables:        []model.SysctlItem{},
			includeTunables: false,
			want:            []model.SysctlItem{},
		},
		{
			name: "include all tunables",
			tunables: []model.SysctlItem{
				{Tunable: "net.inet.ip.forwarding", Value: "0"},
				{Tunable: "vm.swapusage", Value: "1024"},
			},
			includeTunables: true,
			want: []model.SysctlItem{
				{Tunable: "net.inet.ip.forwarding", Value: "0"},
				{Tunable: "vm.swapusage", Value: "1024"},
			},
		},
		{
			name: "filter security tunables only",
			tunables: []model.SysctlItem{
				{Tunable: "net.inet.ip.forwarding", Value: "0"},
				{Tunable: "vm.swapusage", Value: "1024"},
				{Tunable: "net.inet6.ip6.forwarding", Value: "0"},
				{Tunable: "kern.securelevel", Value: "1"},
				{Tunable: "security.bsd.hardlink_check_uid", Value: "1"},
				{Tunable: "net.inet.tcp.blackhole", Value: "2"},
				{Tunable: "net.inet.udp.blackhole", Value: "1"},
			},
			includeTunables: false,
			want: []model.SysctlItem{
				{Tunable: "net.inet.ip.forwarding", Value: "0"},
				{Tunable: "net.inet6.ip6.forwarding", Value: "0"},
				{Tunable: "kern.securelevel", Value: "1"},
				{Tunable: "security.bsd.hardlink_check_uid", Value: "1"},
				{Tunable: "net.inet.tcp.blackhole", Value: "2"},
				{Tunable: "net.inet.udp.blackhole", Value: "1"},
			},
		},
		{
			name: "skip empty tunable names",
			tunables: []model.SysctlItem{
				{Tunable: "", Value: "0"},
				{Tunable: "net.inet.ip.forwarding", Value: "0"},
			},
			includeTunables: false,
			want: []model.SysctlItem{
				{Tunable: "net.inet.ip.forwarding", Value: "0"},
			},
		},
		{
			name: "no security tunables found",
			tunables: []model.SysctlItem{
				{Tunable: "vm.swapusage", Value: "1024"},
				{Tunable: "hw.memsize", Value: "8589934592"},
			},
			includeTunables: false,
			want:            []model.SysctlItem{},
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

func TestGroupServicesByStatus(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		services []model.Service
		want     map[string][]model.Service
	}{
		{
			name:     "nil services",
			services: nil,
			want:     nil,
		},
		{
			name:     "empty services",
			services: []model.Service{},
			want: map[string][]model.Service{
				"running": {},
				"stopped": {},
			},
		},
		{
			name: "mixed services",
			services: []model.Service{
				{Name: "ssh", Status: "running"},
				{Name: "apache", Status: "stopped"},
				{Name: "nginx", Status: "running"},
				{Name: "mysql", Status: "stopped"},
			},
			want: map[string][]model.Service{
				"running": {
					{Name: "nginx", Status: "running"},
					{Name: "ssh", Status: "running"},
				},
				"stopped": {
					{Name: "apache", Status: "stopped"},
					{Name: "mysql", Status: "stopped"},
				},
			},
		},
		{
			name: "all running services",
			services: []model.Service{
				{Name: "ssh", Status: "running"},
				{Name: "nginx", Status: "running"},
			},
			want: map[string][]model.Service{
				"running": {
					{Name: "nginx", Status: "running"},
					{Name: "ssh", Status: "running"},
				},
				"stopped": {},
			},
		},
		{
			name: "all stopped services",
			services: []model.Service{
				{Name: "apache", Status: "stopped"},
				{Name: "mysql", Status: "stopped"},
			},
			want: map[string][]model.Service{
				"running": {},
				"stopped": {
					{Name: "apache", Status: "stopped"},
					{Name: "mysql", Status: "stopped"},
				},
			},
		},
		{
			name: "services with empty names are skipped",
			services: []model.Service{
				{Name: "", Status: "running"},
				{Name: "ssh", Status: "running"},
			},
			want: map[string][]model.Service{
				"running": {
					{Name: "ssh", Status: "running"},
				},
				"stopped": {},
			},
		},
		{
			name: "services with unknown status default to stopped",
			services: []model.Service{
				{Name: "unknown", Status: "unknown"},
				{Name: "ssh", Status: "running"},
			},
			want: map[string][]model.Service{
				"running": {
					{Name: "ssh", Status: "running"},
				},
				"stopped": {
					{Name: "unknown", Status: "unknown"},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := GroupServicesByStatus(tt.services)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GroupServicesByStatus() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAggregatePackageStats(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		packages []model.Package
		want     map[string]int
	}{
		{
			name:     "nil packages",
			packages: nil,
			want:     nil,
		},
		{
			name:     "empty packages",
			packages: []model.Package{},
			want: map[string]int{
				"total":     0,
				"installed": 0,
				"locked":    0,
				"automatic": 0,
			},
		},
		{
			name: "mixed packages",
			packages: []model.Package{
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
			packages: []model.Package{
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
			packages: []model.Package{
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
			packages: []model.Package{
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
		rules    []model.Rule
		ruleType string
		want     []model.Rule
	}{
		{
			name:     "nil rules",
			rules:    nil,
			ruleType: "pass",
			want:     nil,
		},
		{
			name:     "empty rules",
			rules:    []model.Rule{},
			ruleType: "pass",
			want:     []model.Rule{},
		},
		{
			name: "empty rule type returns all rules",
			rules: []model.Rule{
				{Type: "pass"},
				{Type: "block"},
			},
			ruleType: "",
			want: []model.Rule{
				{Type: "pass"},
				{Type: "block"},
			},
		},
		{
			name: "filter by pass rules",
			rules: []model.Rule{
				{Type: "pass"},
				{Type: "block"},
				{Type: "pass"},
				{Type: "reject"},
			},
			ruleType: "pass",
			want: []model.Rule{
				{Type: "pass"},
				{Type: "pass"},
			},
		},
		{
			name: "filter by block rules",
			rules: []model.Rule{
				{Type: "pass"},
				{Type: "block"},
				{Type: "pass"},
				{Type: "block"},
			},
			ruleType: "block",
			want: []model.Rule{
				{Type: "block"},
				{Type: "block"},
			},
		},
		{
			name: "no matching rules",
			rules: []model.Rule{
				{Type: "pass"},
				{Type: "block"},
			},
			ruleType: "reject",
			want:     []model.Rule{},
		},
		{
			name: "rules with empty type are skipped",
			rules: []model.Rule{
				{Type: ""},
				{Type: "pass"},
				{Type: ""},
			},
			ruleType: "pass",
			want: []model.Rule{
				{Type: "pass"},
			},
		},
		{
			name: "case sensitive matching",
			rules: []model.Rule{
				{Type: "pass"},
				{Type: "PASS"},
			},
			ruleType: "pass",
			want: []model.Rule{
				{Type: "pass"},
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

func TestMaxInt(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		a    int
		b    int
		want int
	}{
		{"a greater than b", 10, 5, 10},
		{"b greater than a", 5, 10, 10},
		{"equal values", 5, 5, 5},
		{"negative values", -10, -5, -5},
		{"mixed signs", -5, 10, 10},
		{"zero and positive", 0, 5, 5},
		{"zero and negative", 0, -5, 0},
		{"both zero", 0, 0, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := maxInt(tt.a, tt.b)
			if got != tt.want {
				t.Errorf("maxInt(%d, %d) = %d, want %d", tt.a, tt.b, got, tt.want)
			}
		})
	}
}
