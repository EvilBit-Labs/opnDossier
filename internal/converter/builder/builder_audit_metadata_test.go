package builder

import (
	"fmt"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/audit"
	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
)

// reconCounts and portalEntry stand in for the unexported red-mode metadata
// types (enumerationData, adminPortal in internal/audit): the renderer must
// label them by reflection, since it cannot name them.
type reconCounts struct {
	Interfaces      int
	WANInterfaces   int
	InboundNATRules int
}

type portalEntry struct {
	Name         string
	Port         int
	Reachability string
}

// unescapedAngle matches an angle bracket that is not preceded by a backslash.
var unescapedAngle = regexp.MustCompile(`(^|[^\\])[<>]`)

// goStructDump matches Go's default %v rendering of a struct or a list of
// structs: an opening brace followed by a digit, or a bracket-brace pair.
var goStructDump = regexp.MustCompile(`\{\d|\\?\[\{`)

// assertNoDefaultStructFormatting fails when any struct or list-of-struct
// metadata value reached the output through fmt's default %v formatting,
// which is how #949 and #990 looked. It is reflective so that a structured
// key added later cannot regress silently.
func assertNoDefaultStructFormatting(t *testing.T, metadata map[string]any, rendered string) {
	t.Helper()

	if loc := goStructDump.FindString(rendered); loc != "" {
		t.Errorf("rendered audit section contains a Go struct dump %q:\n%s", loc, rendered)
	}
	for key, value := range metadata {
		if !isStructuredMetadata(value) {
			continue
		}
		dump := fmt.Sprintf("%v", value)
		if strings.Contains(rendered, dump) || strings.Contains(rendered, escapeForTableInTest(dump)) {
			t.Errorf("metadata %q reached the output as its default formatting %q", key, dump)
		}
	}
}

// escapeForTableInTest mirrors what the old table path did to a %v dump,
// so the assertion also catches an escaped dump.
func escapeForTableInTest(s string) string {
	return NewMarkdownBuilder().EscapeTableContent(s)
}

func TestBuildAuditSection_StructuredMetadataRendersLabeled(t *testing.T) {
	t.Parallel()

	metadata := map[string]any{
		"report_type":           "blue_team",
		"recommendation_count":  3,
		"compliance_frameworks": []string{"FIREWALL", "SANS", "STIG"},
		"configuration_summary": audit.ConfigSummary{Interfaces: 2, FirewallRules: 7, NATRules: 1, Users: 1},
		"recommendations": []audit.Recommendation{
			{
				Component:       "backup-config",
				Recommendations: []string{"Enable AutoConfigBackup in Services > Auto Config Backup"},
			},
			{Component: "dns-config", Recommendations: []string{"Configure DNS servers", "Enable DNSSEC"}},
		},
		"enumeration_data": reconCounts{Interfaces: 54, WANInterfaces: 1, InboundNATRules: 0},
		"admin_portals":    []portalEntry{{Name: "webgui", Port: 443, Reachability: "lan"}},
	}

	result := NewMarkdownBuilder().BuildAuditSection(&common.CommonDevice{
		ComplianceResults: &common.ComplianceResults{Mode: "blue", Metadata: metadata},
	})

	assertNoDefaultStructFormatting(t, metadata, result)

	expected := []string{
		"## Audit Metadata",
		// Scalars and string lists stay in the key/value table.
		"| report\\_type | blue\\_team |",
		"| recommendation\\_count | 3 |",
		"| compliance\\_frameworks | FIREWALL, SANS, STIG |",
		// A struct becomes a labeled Field/Value table under its own heading,
		// in declaration order, with acronym runs kept together.
		"### Configuration Summary",
		"| Interfaces | 2 |",
		"| Firewall Rules | 7 |",
		"| NAT Rules | 1 |",
		"| Users | 1 |",
		"### Enumeration Data",
		"| WAN Interfaces | 1 |",
		"| Inbound NAT Rules | 0 |",
		// A list of structs becomes a table with one column per field.
		"### Admin Portals",
		"| Name | Port | Reachability |",
		"| webgui | 443 | lan |",
		// Recommendations are one bullet per component with a nested list.
		"### Recommendations",
		"- **backup-config**\n  - Enable AutoConfigBackup in Services \\> Auto Config Backup\n",
		"- **dns-config**\n  - Configure DNS servers\n  - Enable DNSSEC\n",
	}
	for _, want := range expected {
		if !strings.Contains(result, want) {
			t.Errorf("expected output to contain %q, got:\n%s", want, result)
		}
	}

	// The structured keys must not also appear as table rows.
	for _, key := range []string{"configuration\\_summary", "recommendations |", "enumeration\\_data", "admin\\_portals |"} {
		if strings.Contains(result, "| "+key) {
			t.Errorf("structured key %q should not be a table row, got:\n%s", key, result)
		}
	}
}

func TestBuildAuditSection_StructuredMetadataEmptyValues(t *testing.T) {
	t.Parallel()

	metadata := map[string]any{
		"admin_portals":   []portalEntry(nil),
		"recommendations": []audit.Recommendation{},
	}

	result := NewMarkdownBuilder().BuildAuditSection(&common.CommonDevice{
		ComplianceResults: &common.ComplianceResults{Mode: "red", Metadata: metadata},
	})

	for _, want := range []string{"### Admin Portals\nNone.\n", "### Recommendations\nNone.\n"} {
		if !strings.Contains(result, want) {
			t.Errorf("expected output to contain %q, got:\n%s", want, result)
		}
	}
	if strings.Contains(result, "| Key |") {
		t.Errorf("no scalar keys, so no key/value table expected, got:\n%s", result)
	}
}

func TestBuildAuditSection_StructuredMetadataEscapesContent(t *testing.T) {
	t.Parallel()

	metadata := map[string]any{
		"admin_portals": []portalEntry{{Name: "a|b<img src=x>", Port: 22, Reachability: "wan"}},
		"recommendations": []audit.Recommendation{
			{Component: "x_y", Recommendations: []string{"use `safe` <b>values</b> | always"}},
		},
		// A structured key is plugin-supplied data too; its heading must not
		// become an image or a link.
		"scan_![probe](https://example.invalid/beacon)": reconCounts{Interfaces: 1},
	}

	result := NewMarkdownBuilder().BuildAuditSection(&common.CommonDevice{
		ComplianceResults: &common.ComplianceResults{Mode: "red", Metadata: metadata},
	})

	for _, want := range []string{
		"| a\\|b\\<img src=x\\> | 22 | wan |",
		"- **x\\_y**",
		"  - use \\`safe\\` \\<b\\>values\\</b\\> \\| always",
		"### Scan !\\[probe\\](https://example.invalid/beacon)\n",
	} {
		if !strings.Contains(result, want) {
			t.Errorf("expected output to contain %q, got:\n%s", want, result)
		}
	}
	if strings.Contains(result, "![probe](") {
		t.Errorf("a structured key reached a heading as live markup:\n%s", result)
	}
	// Every angle bracket must carry its escape, or goldmark would parse the
	// value as a raw HTML node.
	if unescapedAngle.MatchString(result) {
		t.Errorf("an unescaped angle bracket reached the output:\n%s", result)
	}
}

// TestBuildAuditSection_StructuredMetadataPointerChains pins that a value the
// classifier calls structured through several pointer layers is unwrapped the
// same way by the renderers, and that a nil pointer at any depth renders as
// "None." or an omitted row instead of panicking.
func TestBuildAuditSection_StructuredMetadataPointerChains(t *testing.T) {
	t.Parallel()

	summary := &audit.ConfigSummary{Interfaces: 2, FirewallRules: 7, NATRules: 1, Users: 1}
	portal := &portalEntry{Name: "webgui", Port: 443, Reachability: "lan"}
	metadata := map[string]any{
		"configuration_summary": &summary,
		"enumeration_data":      (**reconCounts)(nil),
		"admin_portals":         []**portalEntry{nil, &portal},
	}

	result := NewMarkdownBuilder().BuildAuditSection(&common.CommonDevice{
		ComplianceResults: &common.ComplianceResults{Mode: "red", Metadata: metadata},
	})

	for _, want := range []string{
		"### Configuration Summary\n| Field | Value |",
		"| Firewall Rules | 7 |",
		"### Enumeration Data\nNone.\n",
		"### Admin Portals\n| Name | Port | Reachability |\n|---------|---------|---------|\n| webgui | 443 | lan |\n",
	} {
		if !strings.Contains(result, want) {
			t.Errorf("expected output to contain %q, got:\n%s", want, result)
		}
	}
	if strings.Count(result, "| webgui |") != 1 {
		t.Errorf("expected exactly one portal row, got:\n%s", result)
	}
}

func TestIsStructuredMetadata(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name  string
		value any
		want  bool
	}{
		{"nil", nil, false},
		{"string", "x", false},
		{"int", 3, false},
		{"bool", true, false},
		{"string slice", []string{"a"}, false},
		{"stringer struct", reflect.TypeFor[int](), false},
		{"struct", audit.ConfigSummary{}, true},
		{"struct pointer", &audit.ConfigSummary{}, true},
		{"struct slice", []audit.Recommendation{}, true},
		{"nil struct slice", []portalEntry(nil), true},
		{"struct pointer slice", []*portalEntry{}, true},
		{"double struct pointer", func() any { p := &audit.ConfigSummary{}; return &p }(), true},
		{"nil double struct pointer", (**audit.ConfigSummary)(nil), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := isStructuredMetadata(tc.value); got != tc.want {
				t.Errorf("isStructuredMetadata(%#v) = %v, want %v", tc.value, got, tc.want)
			}
		})
	}
}

func TestFormatMetadataValue(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name  string
		value any
		want  string
	}{
		{"nil", nil, ""},
		{"string escaped", "a_b", "a\\_b"},
		{"int", 42, "42"},
		{"bool", false, "false"},
		{"string slice joined", []string{"FIREWALL", "SANS"}, "FIREWALL, SANS"},
		{"empty slice", []string{}, ""},
		{
			"nested struct labeled",
			reconCounts{Interfaces: 1, WANInterfaces: 2},
			"Interfaces: 1, WAN Interfaces: 2, Inbound NAT Rules: 0",
		},
		{
			"struct slice labeled",
			[]portalEntry{{Name: "ssh", Port: 22, Reachability: "lan"}},
			"Name: ssh, Port: 22, Reachability: lan",
		},
		{"nil pointer", (*portalEntry)(nil), ""},
		{"nil double pointer", (**portalEntry)(nil), ""},
		{
			"double pointer unwrapped",
			func() any { p := &portalEntry{Name: "ssh", Port: 22, Reachability: "lan"}; return &p }(),
			"Name: ssh, Port: 22, Reachability: lan",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := formatMetadataValue(tc.value); got != tc.want {
				t.Errorf("formatMetadataValue(%#v) = %q, want %q", tc.value, got, tc.want)
			}
		})
	}
}

func TestHumanizeMetadataNames(t *testing.T) {
	t.Parallel()

	keys := map[string]string{
		"configuration_summary": "Configuration Summary",
		"recommendations":       "Recommendations",
		"enumeration_data":      "Enumeration Data",
		"admin_portals":         "Admin Portals",
		"":                      "",
	}
	for in, want := range keys {
		if got := humanizeMetadataKey(in); got != want {
			t.Errorf("humanizeMetadataKey(%q) = %q, want %q", in, got, want)
		}
	}

	fields := map[string]string{
		"Interfaces":      "Interfaces",
		"FirewallRules":   "Firewall Rules",
		"NATRules":        "NAT Rules",
		"InboundNATRules": "Inbound NAT Rules",
		"WANInterfaces":   "WAN Interfaces",
		"IPv6Allow":       "IPv6 Allow",
		"Port":            "Port",
		"ID":              "ID",
	}
	for in, want := range fields {
		if got := humanizeFieldName(in); got != want {
			t.Errorf("humanizeFieldName(%q) = %q, want %q", in, got, want)
		}
	}
}
