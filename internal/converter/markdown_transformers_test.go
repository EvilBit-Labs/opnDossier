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

func TestMarkdownBuilder_FilterSystemTunables_EdgeCases(t *testing.T) {
	builder := NewMarkdownBuilder()

	tests := []struct {
		name            string
		input           []model.SysctlItem
		includeTunables bool
		expected        []model.SysctlItem
	}{
		{
			name:            "Nil input",
			input:           nil,
			includeTunables: false,
			expected:        nil,
		},
		{
			name:            "Nil input with include all",
			input:           nil,
			includeTunables: true,
			expected:        nil,
		},
		{
			name: "Empty tunable names",
			input: []model.SysctlItem{
				{Tunable: "", Value: "0", Descr: "Empty tunable"},
				{Tunable: "net.inet.ip.forwarding", Value: "1", Descr: "Valid tunable"},
			},
			includeTunables: false,
			expected: []model.SysctlItem{
				{Tunable: "net.inet.ip.forwarding", Value: "1", Descr: "Valid tunable"},
			},
		},
		{
			name: "Include all returns copy",
			input: []model.SysctlItem{
				{Tunable: "test", Value: "1", Descr: "Test"},
			},
			includeTunables: true,
			expected: []model.SysctlItem{
				{Tunable: "test", Value: "1", Descr: "Test"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := builder.FilterSystemTunables(tt.input, tt.includeTunables)
			assert.Equal(t, tt.expected, result)

			// Verify it's a copy when include all is true
			if tt.includeTunables && tt.input != nil && len(tt.input) > 0 {
				// Modify original to ensure it's a copy
				originalValue := tt.input[0].Value
				tt.input[0].Value = "modified"
				assert.NotEqual(t, "modified", result[0].Value, "Should be a copy, not reference")
				tt.input[0].Value = originalValue // restore
			}
		})
	}
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
	require.NotNil(t, result)
	assert.Contains(t, result, "running")
	assert.Contains(t, result, "stopped")
	assert.Empty(t, result["running"])
	assert.Empty(t, result["stopped"])
}

func TestMarkdownBuilder_GroupServicesByStatus_EdgeCases(t *testing.T) {
	builder := NewMarkdownBuilder()

	tests := []struct {
		name            string
		input           []model.Service
		expectedRunning int
		expectedStopped int
		shouldBeNil     bool
	}{
		{
			name:        "Nil input",
			input:       nil,
			shouldBeNil: true,
		},
		{
			name: "Services with empty names",
			input: []model.Service{
				{Name: "", Status: "running", Description: "Empty name"},
				{Name: "valid", Status: "running", Description: "Valid service"},
			},
			expectedRunning: 1,
			expectedStopped: 0,
		},
		{
			name: "Services with invalid status",
			input: []model.Service{
				{Name: "service1", Status: "unknown", Description: "Unknown status"},
				{Name: "service2", Status: "disabled", Description: "Disabled status"},
				{Name: "service3", Status: "running", Description: "Running status"},
			},
			expectedRunning: 1,
			expectedStopped: 2,
		},
		{
			name: "All running services",
			input: []model.Service{
				{Name: "service1", Status: "running"},
				{Name: "service2", Status: "running"},
			},
			expectedRunning: 2,
			expectedStopped: 0,
		},
		{
			name: "All stopped services",
			input: []model.Service{
				{Name: "service1", Status: "stopped"},
				{Name: "service2", Status: "disabled"},
			},
			expectedRunning: 0,
			expectedStopped: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := builder.GroupServicesByStatus(tt.input)

			if tt.shouldBeNil {
				assert.Nil(t, result)
				return
			}

			require.NotNil(t, result)
			assert.Contains(t, result, "running")
			assert.Contains(t, result, "stopped")
			assert.Len(t, result["running"], tt.expectedRunning)
			assert.Len(t, result["stopped"], tt.expectedStopped)

			// Verify sorting
			for _, services := range result {
				for i := 1; i < len(services); i++ {
					assert.LessOrEqual(t, services[i-1].Name, services[i].Name, "Services should be sorted by name")
				}
			}
		})
	}
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

func TestMarkdownBuilder_AggregatePackageStats_EdgeCases(t *testing.T) {
	builder := NewMarkdownBuilder()

	tests := []struct {
		name     string
		input    []model.Package
		expected map[string]int
		isNil    bool
	}{
		{
			name:  "Nil input",
			input: nil,
			isNil: true,
		},
		{
			name:  "Empty input",
			input: []model.Package{},
			expected: map[string]int{
				"total":     0,
				"installed": 0,
				"locked":    0,
				"automatic": 0,
			},
		},
		{
			name: "Packages with empty names",
			input: []model.Package{
				{Name: "", Installed: true, Locked: true, Automatic: true},
				{Name: "valid", Installed: true, Locked: false, Automatic: false},
			},
			expected: map[string]int{
				"total":     2,
				"installed": 1,
				"locked":    0,
				"automatic": 0,
			},
		},
		{
			name: "All flags true",
			input: []model.Package{
				{Name: "pkg1", Installed: true, Locked: true, Automatic: true},
				{Name: "pkg2", Installed: true, Locked: true, Automatic: true},
			},
			expected: map[string]int{
				"total":     2,
				"installed": 2,
				"locked":    2,
				"automatic": 2,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := builder.AggregatePackageStats(tt.input)

			if tt.isNil {
				assert.Nil(t, result)
				return
			}

			assert.Equal(t, tt.expected, result)
		})
	}
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

func TestMarkdownBuilder_FilterRulesByType_EdgeCases(t *testing.T) {
	builder := NewMarkdownBuilder()

	tests := []struct {
		name         string
		input        []model.Rule
		ruleType     string
		expected     []model.Rule
		shouldBeNil  bool
		shouldBeCopy bool
	}{
		{
			name:        "Nil input",
			input:       nil,
			ruleType:    "pass",
			shouldBeNil: true,
		},
		{
			name:     "Empty input",
			input:    []model.Rule{},
			ruleType: "pass",
			expected: []model.Rule{},
		},
		{
			name: "Rules with empty types",
			input: []model.Rule{
				{Type: "", Descr: "Rule with empty type"},
				{Type: "pass", Descr: "Valid rule"},
			},
			ruleType: "pass",
			expected: []model.Rule{
				{Type: "pass", Descr: "Valid rule"},
			},
		},
		{
			name: "Empty rule type returns copy",
			input: []model.Rule{
				{Type: "pass", Descr: "Test rule"},
			},
			ruleType:     "",
			shouldBeCopy: true,
			expected: []model.Rule{
				{Type: "pass", Descr: "Test rule"},
			},
		},
		{
			name: "No matching rules",
			input: []model.Rule{
				{Type: "block", Descr: "Block rule"},
				{Type: "reject", Descr: "Reject rule"},
			},
			ruleType: "allow",
			expected: []model.Rule{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := builder.FilterRulesByType(tt.input, tt.ruleType)

			if tt.shouldBeNil {
				assert.Nil(t, result)
				return
			}

			assert.Equal(t, tt.expected, result)

			// Verify it's a copy when returning all rules
			if tt.shouldBeCopy && tt.input != nil && len(tt.input) > 0 {
				// Modify original to ensure it's a copy
				originalDescr := tt.input[0].Descr
				tt.input[0].Descr = "modified"
				assert.NotEqual(t, "modified", result[0].Descr, "Should be a copy, not reference")
				tt.input[0].Descr = originalDescr // restore
			}
		})
	}
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

func TestMarkdownBuilder_ExtractUniqueValues_EdgeCases(t *testing.T) {
	builder := NewMarkdownBuilder()

	tests := []struct {
		name        string
		input       []string
		expected    []string
		shouldBeNil bool
	}{
		{
			name:        "Nil input",
			input:       nil,
			shouldBeNil: true,
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
			name:     "Single empty string",
			input:    []string{""},
			expected: []string{},
		},
		{
			name:     "Multiple empty strings",
			input:    []string{"", "", ""},
			expected: []string{},
		},
		{
			name:     "Mixed empty and valid strings",
			input:    []string{"", "apple", "", "banana", ""},
			expected: []string{"apple", "banana"},
		},
		{
			name:     "Empty strings with duplicates",
			input:    []string{"apple", "", "apple", "", "banana"},
			expected: []string{"apple", "banana"},
		},
		{
			name:     "Whitespace strings",
			input:    []string{" ", "  ", "\t", "\n"},
			expected: []string{"\t", "\n", " ", "  "},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := builder.ExtractUniqueValues(tt.input)

			if tt.shouldBeNil {
				assert.Nil(t, result)
				return
			}

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

// Performance tests for large datasets

func BenchmarkFilterSystemTunables(b *testing.B) {
	builder := NewMarkdownBuilder()

	// Generate large dataset
	tunables := make([]model.SysctlItem, 10000)
	for i := range 10000 {
		if i%3 == 0 {
			tunables[i] = model.SysctlItem{Tunable: fmt.Sprintf("security.test.%d", i), Value: "1"}
		} else {
			tunables[i] = model.SysctlItem{Tunable: fmt.Sprintf("other.test.%d", i), Value: "1"}
		}
	}

	b.ResetTimer()
	for b.Loop() {
		builder.FilterSystemTunables(tunables, false)
	}
}

func BenchmarkGroupServicesByStatus(b *testing.B) {
	builder := NewMarkdownBuilder()

	// Generate large dataset
	services := make([]model.Service, 5000)
	for i := range 5000 {
		status := "running"
		if i%2 == 0 {
			status = "stopped"
		}
		services[i] = model.Service{
			Name:   fmt.Sprintf("service-%d", i),
			Status: status,
		}
	}

	b.ResetTimer()
	for b.Loop() {
		builder.GroupServicesByStatus(services)
	}
}

func BenchmarkAggregatePackageStats(b *testing.B) {
	builder := NewMarkdownBuilder()

	// Generate large dataset
	packages := make([]model.Package, 20000)
	for i := range 20000 {
		packages[i] = model.Package{
			Name:      fmt.Sprintf("package-%d", i),
			Installed: i%2 == 0,
			Locked:    i%3 == 0,
			Automatic: i%4 == 0,
		}
	}

	b.ResetTimer()
	for b.Loop() {
		builder.AggregatePackageStats(packages)
	}
}

func BenchmarkFilterRulesByType(b *testing.B) {
	builder := NewMarkdownBuilder()

	// Generate large dataset
	rules := make([]model.Rule, 10000)
	types := []string{"pass", "block", "reject", "match"}
	for i := range 10000 {
		rules[i] = model.Rule{
			Type:  types[i%len(types)],
			Descr: fmt.Sprintf("Rule %d", i),
		}
	}

	b.ResetTimer()
	for b.Loop() {
		builder.FilterRulesByType(rules, "pass")
	}
}

func BenchmarkExtractUniqueValues(b *testing.B) {
	builder := NewMarkdownBuilder()

	// Generate large dataset with duplicates
	items := make([]string, 50000)
	for i := range 50000 {
		// Create duplicates by using modulo
		items[i] = fmt.Sprintf("item-%d", i%1000)
	}

	b.ResetTimer()
	for b.Loop() {
		builder.ExtractUniqueValues(items)
	}
}
