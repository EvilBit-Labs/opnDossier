package converter

import (
	"fmt"
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMarkdownBuilder_FilterSystemTunables(t *testing.T) {
	builder := NewMarkdownBuilder()

	tunables := []model.SysctlItem{
		{Tunable: "net.inet.ip.forwarding", Value: "0", Descr: "IP forwarding"},
		{Tunable: "kern.hostname", Value: "firewall", Descr: "System hostname"},
		{Tunable: "security.bsd.see_other_uids", Value: "0", Descr: "See other UIDs"},
		{Tunable: "net.inet.tcp.blackhole", Value: "2", Descr: "TCP blackhole"},
		{Tunable: "user.custom_setting", Value: "1", Descr: "Custom setting"},
		{Tunable: "net.inet6.ip6.forwarding", Value: "0", Descr: "IPv6 forwarding"},
		{Tunable: "kern.securelevel", Value: "1", Descr: "Security level"},
		{Tunable: "net.inet.udp.blackhole", Value: "1", Descr: "UDP blackhole"},
	}

	tests := []struct {
		name             string
		includeTunables  bool
		expectedCount    int
		expectedTunables []string
	}{
		{
			name:            "Include all tunables",
			includeTunables: true,
			expectedCount:   8,
			expectedTunables: []string{
				"net.inet.ip.forwarding",
				"kern.hostname",
				"security.bsd.see_other_uids",
				"net.inet.tcp.blackhole",
				"user.custom_setting",
				"net.inet6.ip6.forwarding",
				"kern.securelevel",
				"net.inet.udp.blackhole",
			},
		},
		{
			name:            "Security tunables only",
			includeTunables: false,
			expectedCount:   6,
			expectedTunables: []string{
				"net.inet.ip.forwarding",
				"security.bsd.see_other_uids",
				"net.inet.tcp.blackhole",
				"net.inet6.ip6.forwarding",
				"kern.securelevel",
				"net.inet.udp.blackhole",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := builder.FilterSystemTunables(tunables, tt.includeTunables)

			assert.Len(t, result, tt.expectedCount)

			// Check that all expected tunables are present
			resultTunables := make([]string, len(result))
			for i, item := range result {
				resultTunables[i] = item.Tunable
			}

			for _, expected := range tt.expectedTunables {
				assert.Contains(t, resultTunables, expected)
			}
		})
	}
}

func TestMarkdownBuilder_FilterSystemTunables_EmptyInput(t *testing.T) {
	builder := NewMarkdownBuilder()

	result := builder.FilterSystemTunables([]model.SysctlItem{}, false)
	assert.Empty(t, result)

	result = builder.FilterSystemTunables([]model.SysctlItem{}, true)
	assert.Empty(t, result)
}

func TestMarkdownBuilder_GroupServicesByStatus(t *testing.T) {
	builder := NewMarkdownBuilder()

	services := []model.Service{
		{Name: "apache", Status: "running", Description: "Web server"},
		{Name: "nginx", Status: "stopped", Description: "Another web server"},
		{Name: "mysql", Status: "running", Description: "Database server"},
		{Name: "redis", Status: "stopped", Description: "Cache server"},
		{Name: "sshd", Status: "running", Description: "SSH daemon"},
		{Name: "ftp", Status: "disabled", Description: "FTP server"},
	}

	result := builder.GroupServicesByStatus(services)

	require.Contains(t, result, "running")
	require.Contains(t, result, "stopped")

	// Check running services
	runningServices := result["running"]
	assert.Len(t, runningServices, 3)

	// Verify services are sorted by name
	runningNames := make([]string, len(runningServices))
	for i, svc := range runningServices {
		runningNames[i] = svc.Name
	}
	assert.Equal(t, []string{"apache", "mysql", "sshd"}, runningNames)

	// Check stopped services (includes disabled services)
	stoppedServices := result["stopped"]
	assert.Len(t, stoppedServices, 3)

	// Verify services are sorted by name
	stoppedNames := make([]string, len(stoppedServices))
	for i, svc := range stoppedServices {
		stoppedNames[i] = svc.Name
	}
	assert.Equal(t, []string{"ftp", "nginx", "redis"}, stoppedNames)
}

func TestMarkdownBuilder_GroupServicesByStatus_EmptyInput(t *testing.T) {
	builder := NewMarkdownBuilder()

	result := builder.GroupServicesByStatus([]model.Service{})
	assert.Empty(t, result)
}

func TestMarkdownBuilder_AggregatePackageStats(t *testing.T) {
	builder := NewMarkdownBuilder()

	packages := []model.Package{
		{Name: "vim", Installed: true, Locked: false, Automatic: false},
		{Name: "git", Installed: true, Locked: true, Automatic: false},
		{Name: "curl", Installed: true, Locked: false, Automatic: true},
		{Name: "wget", Installed: false, Locked: false, Automatic: false},
		{Name: "nano", Installed: true, Locked: true, Automatic: true},
	}

	result := builder.AggregatePackageStats(packages)

	assert.Equal(t, 5, result["total"])
	assert.Equal(t, 4, result["installed"])
	assert.Equal(t, 2, result["locked"])
	assert.Equal(t, 2, result["automatic"])
}

func TestMarkdownBuilder_AggregatePackageStats_EmptyInput(t *testing.T) {
	builder := NewMarkdownBuilder()

	result := builder.AggregatePackageStats([]model.Package{})
	expected := map[string]int{
		"total":     0,
		"installed": 0,
		"locked":    0,
		"automatic": 0,
	}
	assert.Equal(t, expected, result)
}

func TestMarkdownBuilder_AggregatePackageStats_AllFalse(t *testing.T) {
	builder := NewMarkdownBuilder()

	packages := []model.Package{
		{Name: "pkg1", Installed: false, Locked: false, Automatic: false},
		{Name: "pkg2", Installed: false, Locked: false, Automatic: false},
	}

	result := builder.AggregatePackageStats(packages)
	assert.Equal(t, 2, result["total"])
	assert.Equal(t, 0, result["installed"])
	assert.Equal(t, 0, result["locked"])
	assert.Equal(t, 0, result["automatic"])
}

func TestMarkdownBuilder_FilterRulesByType(t *testing.T) {
	builder := NewMarkdownBuilder()

	rules := []model.Rule{
		{Type: "pass", Descr: "Allow HTTP"},
		{Type: "block", Descr: "Block malicious IPs"},
		{Type: "pass", Descr: "Allow HTTPS"},
		{Type: "reject", Descr: "Reject with notice"},
		{Type: "pass", Descr: "Allow SSH"},
	}

	tests := []struct {
		name          string
		ruleType      string
		expectedCount int
		expectedDescs []string
	}{
		{
			name:          "Filter pass rules",
			ruleType:      "pass",
			expectedCount: 3,
			expectedDescs: []string{"Allow HTTP", "Allow HTTPS", "Allow SSH"},
		},
		{
			name:          "Filter block rules",
			ruleType:      "block",
			expectedCount: 1,
			expectedDescs: []string{"Block malicious IPs"},
		},
		{
			name:          "Filter reject rules",
			ruleType:      "reject",
			expectedCount: 1,
			expectedDescs: []string{"Reject with notice"},
		},
		{
			name:          "Filter nonexistent type",
			ruleType:      "nonexistent",
			expectedCount: 0,
			expectedDescs: []string{},
		},
		{
			name:          "Empty rule type returns all",
			ruleType:      "",
			expectedCount: 5,
			expectedDescs: []string{
				"Allow HTTP",
				"Block malicious IPs",
				"Allow HTTPS",
				"Reject with notice",
				"Allow SSH",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := builder.FilterRulesByType(rules, tt.ruleType)

			assert.Len(t, result, tt.expectedCount)

			if tt.expectedCount > 0 {
				resultDescs := make([]string, len(result))
				for i, rule := range result {
					resultDescs[i] = rule.Descr
				}

				for _, expectedDesc := range tt.expectedDescs {
					assert.Contains(t, resultDescs, expectedDesc)
				}
			}
		})
	}
}

func TestMarkdownBuilder_FilterRulesByType_EmptyInput(t *testing.T) {
	builder := NewMarkdownBuilder()

	result := builder.FilterRulesByType([]model.Rule{}, "pass")
	assert.Empty(t, result)

	result = builder.FilterRulesByType([]model.Rule{}, "")
	assert.Empty(t, result)
}

func TestMarkdownBuilder_ExtractUniqueValues(t *testing.T) {
	builder := NewMarkdownBuilder()

	tests := []struct {
		name     string
		input    []string
		expected []string
	}{
		{
			name:     "With duplicates",
			input:    []string{"apple", "banana", "apple", "cherry", "banana", "date"},
			expected: []string{"apple", "banana", "cherry", "date"},
		},
		{
			name:     "No duplicates",
			input:    []string{"apple", "banana", "cherry"},
			expected: []string{"apple", "banana", "cherry"},
		},
		{
			name:     "Empty input",
			input:    []string{},
			expected: []string{},
		},
		{
			name:     "Single item",
			input:    []string{"apple"},
			expected: []string{"apple"},
		},
		{
			name:     "All same items",
			input:    []string{"apple", "apple", "apple"},
			expected: []string{"apple"},
		},
		{
			name:     "Unsorted input",
			input:    []string{"zebra", "apple", "monkey", "banana"},
			expected: []string{"apple", "banana", "monkey", "zebra"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := builder.ExtractUniqueValues(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestMarkdownBuilder_ExtractUniqueValues_PreservesOrder(t *testing.T) {
	builder := NewMarkdownBuilder()

	// Test that the result is always sorted regardless of input order
	inputs := [][]string{
		{"c", "a", "b"},
		{"a", "c", "b"},
		{"b", "a", "c"},
	}

	expected := []string{"a", "b", "c"}

	for i, input := range inputs {
		t.Run(fmt.Sprintf("Order test %d", i+1), func(t *testing.T) {
			result := builder.ExtractUniqueValues(input)
			assert.Equal(t, expected, result)
		})
	}
}
