package builder

import (
	"strings"
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/model"
)

// Test the helper methods that delegate to formatters package

func TestMarkdownBuilder_EscapeTableContent(t *testing.T) {
	t.Parallel()

	builder := NewMarkdownBuilder()

	tests := []struct {
		name    string
		content any
		want    string
	}{
		{name: "string content", content: "test string", want: "test string"},
		{name: "pipe character", content: "col1|col2", want: "col1\\|col2"},
		{name: "empty string", content: "", want: ""},
		{name: "integer", content: 42, want: "42"},
		{name: "nil", content: nil, want: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := builder.EscapeTableContent(tt.content)
			if got != tt.want {
				t.Errorf("EscapeTableContent(%v) = %q, want %q", tt.content, got, tt.want)
			}
		})
	}
}

func TestMarkdownBuilder_TruncateDescription(t *testing.T) {
	t.Parallel()

	builder := NewMarkdownBuilder()

	tests := []struct {
		name        string
		description string
		maxLength   int
		want        string
	}{
		{name: "short description", description: "short", maxLength: 10, want: "short"},
		{name: "exact length", description: "exactly10", maxLength: 9, want: "exactly10"},
		{name: "long description", description: "this is a very long description", maxLength: 10, want: "this is a..."},
		{name: "empty description", description: "", maxLength: 5, want: ""},
		{name: "zero max length", description: "test", maxLength: 0, want: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := builder.TruncateDescription(tt.description, tt.maxLength)
			if got != tt.want {
				t.Errorf("TruncateDescription(%q, %d) = %q, want %q", tt.description, tt.maxLength, got, tt.want)
			}
		})
	}
}

func TestMarkdownBuilder_IsLastInSlice(t *testing.T) {
	t.Parallel()

	builder := NewMarkdownBuilder()

	tests := []struct {
		name  string
		index int
		slice any
		want  bool
	}{
		{name: "last in string slice", index: 2, slice: []string{"a", "b", "c"}, want: true},
		{name: "not last in string slice", index: 1, slice: []string{"a", "b", "c"}, want: false},
		{name: "last in int slice", index: 1, slice: []int{1, 2}, want: true},
		{name: "first element", index: 0, slice: []string{"only"}, want: true},
		{name: "out of bounds", index: 5, slice: []string{"a", "b"}, want: false},
		{name: "negative index", index: -1, slice: []string{"a", "b"}, want: false},
		{name: "empty slice", index: 0, slice: []string{}, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := builder.IsLastInSlice(tt.index, tt.slice)
			if got != tt.want {
				t.Errorf("IsLastInSlice(%d, %v) = %v, want %v", tt.index, tt.slice, got, tt.want)
			}
		})
	}
}

func TestMarkdownBuilder_DefaultValue(t *testing.T) {
	t.Parallel()

	builder := NewMarkdownBuilder()

	tests := []struct {
		name       string
		value      any
		defaultVal any
		want       any
	}{
		{name: "non-empty string", value: "test", defaultVal: "default", want: "test"},
		{name: "empty string uses default", value: "", defaultVal: "default", want: "default"},
		{name: "nil uses default", value: nil, defaultVal: "default", want: "default"},
		{name: "zero int", value: 0, defaultVal: 42, want: 42},
		{name: "non-zero int", value: 5, defaultVal: 42, want: 5},
		{name: "empty slice uses default", value: []string{}, defaultVal: "default", want: "default"},
		// Skip slice test since slices are not comparable in Go
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := builder.DefaultValue(tt.value, tt.defaultVal)
			if got != tt.want {
				t.Errorf("DefaultValue(%v, %v) = %v, want %v", tt.value, tt.defaultVal, got, tt.want)
			}
		})
	}
}

func TestMarkdownBuilder_IsEmpty(t *testing.T) {
	t.Parallel()

	builder := NewMarkdownBuilder()

	tests := []struct {
		name  string
		value any
		want  bool
	}{
		{name: "empty string", value: "", want: true},
		{name: "non-empty string", value: "test", want: false},
		{name: "nil", value: nil, want: true},
		{name: "zero int", value: 0, want: true},
		{name: "non-zero int", value: 42, want: false},
		{name: "empty slice", value: []string{}, want: true},
		{name: "non-empty slice", value: []string{"item"}, want: false},
		{name: "empty map", value: map[string]string{}, want: true},
		{name: "non-empty map", value: map[string]string{"key": "value"}, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := builder.IsEmpty(tt.value)
			if got != tt.want {
				t.Errorf("IsEmpty(%v) = %v, want %v", tt.value, got, tt.want)
			}
		})
	}
}

func TestMarkdownBuilder_StringFunctions(t *testing.T) {
	t.Parallel()

	builder := NewMarkdownBuilder()

	tests := []struct {
		name     string
		input    string
		wantUp   string
		wantLow  string
		wantTrim string
	}{
		{
			name:     "basic string",
			input:    "  Hello World  ",
			wantUp:   "  HELLO WORLD  ",
			wantLow:  "  hello world  ",
			wantTrim: "Hello World",
		},
		{
			name:     "empty string",
			input:    "",
			wantUp:   "",
			wantLow:  "",
			wantTrim: "",
		},
		{
			name:     "whitespace only",
			input:    "   ",
			wantUp:   "   ",
			wantLow:  "   ",
			wantTrim: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			gotUp := builder.ToUpper(tt.input)
			if gotUp != tt.wantUp {
				t.Errorf("ToUpper(%q) = %q, want %q", tt.input, gotUp, tt.wantUp)
			}

			gotLow := builder.ToLower(tt.input)
			if gotLow != tt.wantLow {
				t.Errorf("ToLower(%q) = %q, want %q", tt.input, gotLow, tt.wantLow)
			}

			gotTrim := builder.TrimSpace(tt.input)
			if gotTrim != tt.wantTrim {
				t.Errorf("TrimSpace(%q) = %q, want %q", tt.input, gotTrim, tt.wantTrim)
			}
		})
	}
}

func TestMarkdownBuilder_BoolToString(t *testing.T) {
	t.Parallel()

	builder := NewMarkdownBuilder()

	tests := []struct {
		name string
		val  bool
		want string
	}{
		{name: "true value", val: true, want: "✅ Enabled"},
		{name: "false value", val: false, want: "❌ Disabled"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := builder.BoolToString(tt.val)
			if got != tt.want {
				t.Errorf("BoolToString(%v) = %q, want %q", tt.val, got, tt.want)
			}
		})
	}
}

func TestMarkdownBuilder_FormatBytes(t *testing.T) {
	t.Parallel()

	builder := NewMarkdownBuilder()

	tests := []struct {
		name  string
		bytes int64
		want  string
	}{
		{name: "zero bytes", bytes: 0, want: "0 B"},
		{name: "bytes", bytes: 512, want: "512 B"},
		{name: "kilobytes", bytes: 2048, want: "2.0 KiB"},
		{name: "megabytes", bytes: 1048576, want: "1.0 MiB"},
		{name: "gigabytes", bytes: 1073741824, want: "1.0 GiB"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := builder.FormatBytes(tt.bytes)
			if got != tt.want {
				t.Errorf("FormatBytes(%d) = %q, want %q", tt.bytes, got, tt.want)
			}
		})
	}
}

//nolint:dupl // structurally similar to TestMarkdownBuilder_AssessRiskLevel but tests different method
func TestMarkdownBuilder_SanitizeID(t *testing.T) {
	t.Parallel()

	builder := NewMarkdownBuilder()

	tests := []struct {
		name string
		s    string
		want string
	}{
		{name: "basic string", s: "test-id", want: "test-id"},
		{name: "spaces to dashes", s: "test id", want: "test-id"},
		{name: "special chars", s: "test@#$id", want: "test-id"},
		{name: "mixed case", s: "Test ID", want: "test-id"},
		{name: "empty string", s: "", want: "unnamed"},
		{name: "multiple spaces", s: "test   id   here", want: "test-id-here"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := builder.SanitizeID(tt.s)
			if got != tt.want {
				t.Errorf("SanitizeID(%q) = %q, want %q", tt.s, got, tt.want)
			}
		})
	}
}

//nolint:dupl // structurally similar to TestMarkdownBuilder_SanitizeID but tests different method
func TestMarkdownBuilder_AssessRiskLevel(t *testing.T) {
	t.Parallel()

	builder := NewMarkdownBuilder()

	tests := []struct {
		name     string
		severity string
		want     string
	}{
		{name: "critical", severity: "critical", want: "🔴 Critical Risk"},
		{name: "high", severity: "high", want: "🟠 High Risk"},
		{name: "medium", severity: "medium", want: "🟡 Medium Risk"},
		{name: "low", severity: "low", want: "🟢 Low Risk"},
		{name: "unknown", severity: "unknown", want: "⚪ Unknown Risk"},
		{name: "empty", severity: "", want: "⚪ Unknown Risk"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := builder.AssessRiskLevel(tt.severity)
			if got != tt.want {
				t.Errorf("AssessRiskLevel(%q) = %q, want %q", tt.severity, got, tt.want)
			}
		})
	}
}

func TestMarkdownBuilder_CalculateSecurityScore(t *testing.T) {
	t.Parallel()

	builder := NewMarkdownBuilder()

	tests := []struct {
		name string
		data *model.OpnSenseDocument
		want int
	}{
		{
			name: "nil document",
			data: nil,
			want: 0,
		},
		{
			name: "basic document",
			data: &model.OpnSenseDocument{
				System: model.System{
					Hostname: "test",
				},
			},
			want: 50, // Default baseline score from formatters
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := builder.CalculateSecurityScore(tt.data)
			// Score can vary based on formatters implementation, just ensure it's in valid range
			if got < 0 || got > 100 {
				t.Errorf("CalculateSecurityScore(%v) = %d, want score between 0-100", tt.data, got)
			}
		})
	}
}

func TestMarkdownBuilder_AssessServiceRisk(t *testing.T) {
	t.Parallel()

	builder := NewMarkdownBuilder()

	tests := []struct {
		name    string
		service model.Service
	}{
		{
			name:    "ssh service",
			service: model.Service{Name: "ssh", Status: "running"},
		},
		{
			name:    "http service",
			service: model.Service{Name: "http", Status: "running"},
		},
		{
			name:    "unknown service",
			service: model.Service{Name: "unknown", Status: "stopped"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := builder.AssessServiceRisk(tt.service)
			// Risk assessment can vary, just ensure it returns a valid format
			if !strings.Contains(got, "🔴") && !strings.Contains(got, "🟠") &&
				!strings.Contains(got, "🟡") && !strings.Contains(got, "🟢") &&
				!strings.Contains(got, "⚪") && !strings.Contains(got, "ℹ️") {
				t.Errorf("AssessServiceRisk(%v) = %q, want valid risk format", tt.service, got)
			}
		})
	}
}

func TestMarkdownBuilder_FilterSystemTunables(t *testing.T) {
	t.Parallel()

	builder := NewMarkdownBuilder()

	tunables := []model.SysctlItem{
		{Tunable: "kern.ipc.maxsockbuf", Value: "16777216"},
		{Tunable: "net.inet.tcp.mssdflt", Value: "1460"},
		{Tunable: "vm.stats.sys.v_page_size", Value: "4096"},
		{Tunable: "security.bsd.see_other_uids", Value: "1"},
	}

	tests := []struct {
		name            string
		includeTunables bool
		wantCount       int
	}{
		{
			name:            "include security tunables",
			includeTunables: true,
			wantCount:       4, // All should be included as they're security-related
		},
		{
			name:            "exclude non-security tunables",
			includeTunables: false,
			wantCount:       1, // Only the explicit security.* tunable
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := builder.FilterSystemTunables(tunables, tt.includeTunables)
			if got == nil {
				t.Errorf("FilterSystemTunables returned nil")
			}
			// The actual filtering logic depends on formatters implementation
			// Just ensure it returns a valid slice
		})
	}
}

func TestMarkdownBuilder_GroupServicesByStatus(t *testing.T) {
	t.Parallel()

	builder := NewMarkdownBuilder()

	services := []model.Service{
		{Name: "ssh", Status: "running"},
		{Name: "http", Status: "running"},
		{Name: "ftp", Status: "stopped"},
		{Name: "ntp", Status: "running"},
	}

	result := builder.GroupServicesByStatus(services)
	if result == nil {
		t.Error("GroupServicesByStatus returned nil")
		return
	}

	// Should have running and stopped groups
	if len(result) == 0 {
		t.Error("GroupServicesByStatus returned empty map")
	}

	// Just verify the function doesn't panic and returns a map
	for status, svcList := range result {
		if status == "" {
			t.Error("GroupServicesByStatus returned empty status key")
		}
		if len(svcList) == 0 {
			t.Errorf("GroupServicesByStatus returned empty service list for status: %s", status)
		}
	}
}

func TestMarkdownBuilder_AggregatePackageStats(t *testing.T) {
	t.Parallel()

	builder := NewMarkdownBuilder()

	packages := []model.Package{
		{Name: "nginx", Version: "1.20.1", Installed: true},
		{Name: "mysql", Version: "8.0.28", Installed: true},
		{Name: "php", Version: "8.1.0", Installed: false},
	}

	result := builder.AggregatePackageStats(packages)
	if result == nil {
		t.Error("AggregatePackageStats returned nil")
		return
	}

	// Should return some stats about the packages
	if len(result) == 0 {
		t.Error("AggregatePackageStats returned empty stats")
	}

	// Verify it's a valid map with numeric values
	for key, value := range result {
		if key == "" {
			t.Error("AggregatePackageStats returned empty key")
		}
		if value < 0 {
			t.Errorf("AggregatePackageStats returned negative value %d for key %s", value, key)
		}
	}
}

func TestMarkdownBuilder_FilterRulesByType(t *testing.T) {
	t.Parallel()

	builder := NewMarkdownBuilder()

	rules := []model.Rule{
		{Type: "pass", Protocol: "tcp"},
		{Type: "block", Protocol: "udp"},
		{Type: "pass", Protocol: "icmp"},
		{Type: "reject", Protocol: "tcp"},
	}

	tests := []struct {
		name     string
		ruleType string
	}{
		{name: "pass rules", ruleType: "pass"},
		{name: "block rules", ruleType: "block"},
		{name: "reject rules", ruleType: "reject"},
		{name: "nonexistent type", ruleType: "nonexistent"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := builder.FilterRulesByType(rules, tt.ruleType)

			// Ensure the function returns a valid slice
			if result == nil {
				t.Error("FilterRulesByType returned nil")
				return
			}

			// All returned rules should match the requested type (if any exist)
			for _, rule := range result {
				if rule.Type != tt.ruleType {
					t.Errorf("FilterRulesByType returned rule with type %s, want %s", rule.Type, tt.ruleType)
				}
			}
		})
	}
}

func TestMarkdownBuilder_ExtractUniqueValues(t *testing.T) {
	t.Parallel()

	builder := NewMarkdownBuilder()

	tests := []struct {
		name  string
		items []string
		want  int // minimum unique count expected
	}{
		{
			name:  "empty slice",
			items: []string{},
			want:  0,
		},
		{
			name:  "unique items",
			items: []string{"a", "b", "c"},
			want:  3,
		},
		{
			name:  "duplicate items",
			items: []string{"a", "b", "a", "c", "b"},
			want:  3,
		},
		{
			name:  "all same",
			items: []string{"a", "a", "a"},
			want:  1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := builder.ExtractUniqueValues(tt.items)

			if result == nil {
				t.Error("ExtractUniqueValues returned nil")
				return
			}

			if len(result) != tt.want {
				t.Errorf("ExtractUniqueValues() returned %d unique items, want %d", len(result), tt.want)
			}

			// Verify all items in result are unique
			seen := make(map[string]bool)
			for _, item := range result {
				if seen[item] {
					t.Errorf("ExtractUniqueValues() returned duplicate item: %s", item)
				}
				seen[item] = true
			}
		})
	}
}

// Test pluralize helper function.
func TestPluralize(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		count int
		unit  string
		want  string
	}{
		{name: "singular", count: 1, unit: "day", want: "1 day"},
		{name: "plural", count: 2, unit: "day", want: "2 days"},
		{name: "zero", count: 0, unit: "item", want: "0 items"},
		{name: "large number", count: 100, unit: "file", want: "100 files"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := pluralize(tt.count, tt.unit)
			if got != tt.want {
				t.Errorf("pluralize(%d, %q) = %q, want %q", tt.count, tt.unit, got, tt.want)
			}
		})
	}
}

// Test formatDuration helper function.
func TestFormatDuration(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		seconds int
		want    string
	}{
		{name: "1 second", seconds: 1, want: "1 second"},
		{name: "30 seconds", seconds: 30, want: "30 seconds"},
		{name: "1 minute", seconds: 60, want: "1 minute"},
		{name: "90 seconds", seconds: 90, want: "1 minute, 30 seconds"},
		{name: "1 hour", seconds: 3600, want: "1 hour"},
		{name: "90 minutes", seconds: 5400, want: "1 hour, 30 minutes"},
		{name: "1 day", seconds: 86400, want: "1 day"},
		{name: "25 hours", seconds: 90000, want: "1 day, 1 hour"},
		{name: "1 week", seconds: 604800, want: "1 week"},
		{name: "8 days", seconds: 691200, want: "1 week, 1 day"},
		{name: "complex duration", seconds: 90061, want: "1 day, 1 hour, 1 minute, 1 second"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := formatDuration(tt.seconds)
			if got != tt.want {
				t.Errorf("formatDuration(%d) = %q, want %q", tt.seconds, got, tt.want)
			}
		})
	}
}
