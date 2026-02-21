package converter

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"

	builderPkg "github.com/EvilBit-Labs/opnDossier/internal/converter/builder"
	"github.com/EvilBit-Labs/opnDossier/internal/model/common"
	"github.com/nao1215/markdown"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestMarkdownBuilder_TemplateParityValidation validates that the new programmatic
// methods produce equivalent output to what would be expected from templates.
func TestMarkdownBuilder_TemplateParityValidation(t *testing.T) {
	tests := []struct {
		name         string
		dataFile     string
		validateFunc func(t *testing.T, output string)
	}{
		{
			name:     "minimal configuration",
			dataFile: "minimal.json",
			validateFunc: func(t *testing.T, output string) {
				t.Helper()
				// Must contain essential sections
				assert.Contains(t, output, "OPNsense Configuration Summary")
				assert.Contains(t, output, "minimal-host")
				assert.Contains(t, output, "minimal.local")
				assert.Contains(t, output, "23.1.1")

				// Should have proper markdown structure
				assert.Contains(t, output, "# OPNsense Configuration Summary")
				assert.Contains(t, output, "## System Information")
				assert.Contains(t, output, "## Table of Contents")
			},
		},
		{
			name:     "complete configuration",
			dataFile: "complete.json",
			validateFunc: func(t *testing.T, output string) {
				t.Helper()
				// Must contain all major sections
				sections := []string{
					"System Configuration",
					"Network Configuration",
					"Security Configuration",
					"Service Configuration",
					"Interfaces",
					"Firewall Rules",
					"DHCP Services",
					"System Users",
					"System Tunables",
				}

				for _, section := range sections {
					assert.Contains(t, output, section, "Missing section: %s", section)
				}

				// Verify specific data points
				assert.Contains(t, output, "comprehensive-firewall")
				assert.Contains(t, output, "security.local")
				assert.Contains(t, output, "24.1.2")
				assert.Contains(t, output, "Primary Data Center")
			},
		},
		{
			name:     "edge cases handling",
			dataFile: "edge_cases.json",
			validateFunc: func(t *testing.T, output string) {
				t.Helper()
				// Should handle special characters properly
				// Note: pipes might be present in non-table contexts
				assert.NotContains(t, output, "\n\n\n", "Multiple newlines should be cleaned")

				// Should still produce valid markdown
				assert.Contains(t, output, "OPNsense Configuration Summary")
				assert.Contains(t, output, "edge-case-test")

				// Test Markdown character escaping in Description fields (which use escapeTableContent)
				// These fields should have proper escaping applied
				assert.Contains(
					t,
					output,
					"Rule with \\*bold\\* and \\_italic\\_ text",
					"Asterisks and underscores should be escaped in description fields",
				)
				assert.Contains(
					t,
					output,
					"Rule with \\`code\\` and \\\\backslash\\\\ characters",
					"Backticks and backslashes should be escaped in description fields",
				)
				assert.Contains(
					t,
					output,
					"Rule with \\| pipes \\| and",
					"Pipes should be escaped in description fields",
				)

				// Test that special characters in all table fields are properly escaped
				// All table content should be escaped for safety
				assert.Contains(t, output, "tunable\\*with\\*asterisks", "Asterisks should be escaped in table content")
				assert.Contains(
					t,
					output,
					"value\\_with\\_underscores",
					"Underscores should be escaped in table content",
				)
				assert.Contains(
					t,
					output,
					"value\\\\with\\\\backslashes",
					"Backslashes should be escaped in table content",
				)
				assert.Contains(t, output, "tunable\\`with\\`backticks", "Backticks should be escaped in table content")
				assert.Contains(
					t,
					output,
					"tunable\\[with\\]brackets",
					"Square brackets should be escaped in table content",
				)
				assert.Contains(t, output, "value\\<with\\>angles", "Angle brackets should be escaped in table content")
				assert.Contains(
					t,
					output,
					"invalid.tunable.with.pipes\\|and\\|newlines",
					"Pipes should be escaped in table content",
				)

				// Verify that table structure is preserved (pipes for table separators should remain unescaped)
				assert.Contains(t, output, "|", "Table structure should be preserved")
				assert.Contains(t, output, "---", "Table headers should be preserved")

				// Verify that escaped characters don't break table structure
				assert.Contains(t, output, "|", "Table structure should be preserved")
				assert.Contains(t, output, "---", "Table headers should be preserved")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Load test data
			testData := loadTestDataFromFile(t, tt.dataFile)

			// Generate standard report
			builder := NewMarkdownBuilder()
			standardOutput, err := builder.BuildStandardReport(testData)
			require.NoError(t, err)
			assert.NotEmpty(t, standardOutput)

			// Generate comprehensive report
			comprehensiveOutput, err := builder.BuildComprehensiveReport(testData)
			require.NoError(t, err)
			assert.NotEmpty(t, comprehensiveOutput)

			// Validate outputs
			tt.validateFunc(t, standardOutput)
			tt.validateFunc(t, comprehensiveOutput)

			// Both reports should have similar basic content, don't enforce length comparison
			// since the comprehensive report may exclude empty sections
		})
	}
}

// TestMarkdownBuilder_CrossMethodInteraction tests that different methods
// work together correctly and share data appropriately.
func TestMarkdownBuilder_CrossMethodInteraction(t *testing.T) {
	testData := loadTestDataFromFile(t, "complete.json")
	builder := NewMarkdownBuilder()

	// Test that section builders can be used independently
	systemSection := builder.BuildSystemSection(testData)
	networkSection := builder.BuildNetworkSection(testData)
	securitySection := builder.BuildSecuritySection(testData)
	servicesSection := builder.BuildServicesSection(testData)

	// Each section should be self-contained and valid
	assert.Contains(t, systemSection, "System Configuration")
	assert.Contains(t, networkSection, "Network Configuration")
	assert.Contains(t, securitySection, "Security Configuration")
	assert.Contains(t, servicesSection, "Service Configuration")

	// Test that tables can be generated independently
	interfaceTable := builderPkg.BuildInterfaceTableSet(testData.Interfaces)
	rulesTable := builderPkg.BuildFirewallRulesTableSet(testData.FirewallRules)
	userTable := builderPkg.BuildUserTableSet(testData.Users)
	groupTable := builderPkg.BuildGroupTableSet(testData.Groups)
	sysctlTable := builderPkg.BuildSysctlTableSet(testData.Sysctl)

	// All tables should have proper structure
	validateTableStructure(t, interfaceTable, "Interfaces")
	validateTableStructure(t, rulesTable, "Firewall Rules")
	validateTableStructure(t, userTable, "Users")
	validateTableStructure(t, groupTable, "Groups")
	validateTableStructure(t, sysctlTable, "Sysctl")

	// Combined report should include all sections
	fullReport, err := builder.BuildComprehensiveReport(testData)
	require.NoError(t, err)

	// Verify sections appear in the correct order
	sysIndex := strings.Index(fullReport, "System Configuration")
	netIndex := strings.Index(fullReport, "Network Configuration")
	secIndex := strings.Index(fullReport, "Security Configuration")
	svcIndex := strings.Index(fullReport, "Service Configuration")

	assert.Greater(t, netIndex, sysIndex, "Network should come after System")
	assert.Greater(t, secIndex, netIndex, "Security should come after Network")
	assert.Greater(t, svcIndex, secIndex, "Services should come after Security")
}

// TestMarkdownBuilder_ErrorHandling tests comprehensive error handling.
func TestMarkdownBuilder_ErrorHandling(t *testing.T) {
	builder := NewMarkdownBuilder()

	tests := []struct {
		name     string
		data     *common.CommonDevice
		wantErr  bool
		errCheck func(t *testing.T, err error)
	}{
		{
			name:    "nil document",
			data:    nil,
			wantErr: true,
			errCheck: func(t *testing.T, err error) {
				t.Helper()
				assert.Equal(t, builderPkg.ErrNilDevice, err)
			},
		},
		{
			name:    "empty document",
			data:    &common.CommonDevice{},
			wantErr: false,
		},
		{
			name: "document with only system",
			data: &common.CommonDevice{
				System: common.System{
					Hostname: "test",
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test standard report
			_, err := builder.BuildStandardReport(tt.data)
			if tt.wantErr {
				require.Error(t, err)
				if tt.errCheck != nil {
					tt.errCheck(t, err)
				}
			} else {
				require.NoError(t, err)
			}

			// Test comprehensive report
			_, err = builder.BuildComprehensiveReport(tt.data)
			if tt.wantErr {
				require.Error(t, err)
				if tt.errCheck != nil {
					tt.errCheck(t, err)
				}
			} else {
				require.NoError(t, err)
			}
		})
	}
}

// TestMarkdownBuilder_LargeDatasetHandling tests performance with large datasets.
func TestMarkdownBuilder_LargeDatasetHandling(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping large dataset test in short mode")
	}

	// Generate large test data
	largeData := generateLargeTestData(t)
	builder := NewMarkdownBuilder()

	// Test that large datasets can be processed
	result, err := builder.BuildStandardReport(largeData)
	require.NoError(t, err)
	assert.NotEmpty(t, result)

	// Verify the report contains expected number of elements
	interfaceCount := strings.Count(result, "Interface")

	// Should have processed multiple interfaces
	assert.Greater(t, interfaceCount, 5, "Should process multiple interfaces")
	// Just check it's not empty and well-formed
	assert.NotEmpty(t, result, "Should have generated some content")
	assert.Contains(t, result, "OPNsense Configuration Summary", "Should have proper header")

	t.Logf("Generated report with %d chars", len(result))
}

// TestMarkdownBuilder_MarkdownValidation tests that generated markdown is valid.
func TestMarkdownBuilder_MarkdownValidation(t *testing.T) {
	testData := loadTestDataFromFile(t, "complete.json")
	builder := NewMarkdownBuilder()

	reports := map[string]string{}

	// Generate both types of reports
	standardReport, err := builder.BuildStandardReport(testData)
	require.NoError(t, err)
	reports["standard"] = standardReport

	comprehensiveReport, err := builder.BuildComprehensiveReport(testData)
	require.NoError(t, err)
	reports["comprehensive"] = comprehensiveReport

	for reportType, content := range reports {
		t.Run(reportType, func(t *testing.T) {
			// Basic markdown structure validation
			validateMarkdownStructure(t, content)

			// Verify no broken markdown elements
			validateMarkdownSyntax(t, content)

			// Check for proper table formatting
			validateTableFormatting(t, content)
		})
	}
}

// Helper functions for tests

func loadTestDataFromFile(t *testing.T, filename string) *common.CommonDevice {
	t.Helper()

	path := filepath.Join("testdata", filename)
	data, err := os.ReadFile(path)
	require.NoError(t, err, "Failed to read test data file: %s", filename)

	var doc common.CommonDevice
	err = json.Unmarshal(data, &doc)
	require.NoError(t, err, "Failed to unmarshal test data: %s", filename)

	return &doc
}

func validateTableStructure(t *testing.T, table any, tableName string) {
	t.Helper()

	// Basic validation that table is not nil
	assert.NotNil(t, table, "%s table should not be nil", tableName)

	// Type assertion to verify concrete TableSet structure
	tableSet, ok := table.(*markdown.TableSet)
	assert.True(t, ok, "%s table should be of type *markdown.TableSet, got %T", tableName, table)

	// Validate headers exist and are non-empty
	assert.NotNil(t, tableSet.Header, "%s table headers should not be nil", tableName)
	assert.NotEmpty(t, tableSet.Header, "%s table should have at least one header column", tableName)

	// Check for empty header entries
	for i, header := range tableSet.Header {
		assert.NotEmpty(t, strings.TrimSpace(header),
			"%s table header at index %d should not be empty or whitespace-only", tableName, i)
	}

	// Validate rows structure
	assert.NotNil(t, tableSet.Rows, "%s table rows should not be nil", tableName)

	// Check each row has the same number of columns as headers
	expectedColumns := len(tableSet.Header)
	for i, row := range tableSet.Rows {
		assert.NotNil(t, row, "%s table row %d should not be nil", tableName, i)
		assert.Len(t, row, expectedColumns,
			"%s table row %d should have %d columns to match headers, got %d",
			tableName, i, expectedColumns, len(row))

		// Check each cell value is not nil (since it's already a string)
		// Note: Empty cells are allowed as they may be legitimate for optional data
		for j, cell := range row {
			// Cell should be a valid string (can be empty, but not nil)
			assert.NotNil(t, cell,
				"%s table cell at row %d, column %d should not be nil",
				tableName, i, j)
		}
	}
}

func validateMarkdownStructure(t *testing.T, content string) {
	t.Helper()

	// Check for proper heading hierarchy
	assert.Contains(t, content, "# ", "Should have H1 headings")
	assert.Contains(t, content, "## ", "Should have H2 headings")

	// Check for table of contents
	assert.Contains(t, content, "Table of Contents", "Should have table of contents")

	// Check for proper markdown list formatting
	lines := strings.Split(content, "\n")
	for i, line := range lines {
		if strings.HasPrefix(line, "- ") || strings.HasPrefix(line, "* ") {
			// Check that list items are properly formatted
			assert.NotEmpty(t, strings.TrimSpace(line),
				"List item at line %d should not be empty", i+1)
		}
	}
}

// splitOnUnescapedPipes splits a string on unescaped pipe characters.
// It handles escaped pipes (\\|) by treating them as literal characters.
func splitOnUnescapedPipes(line string) []string {
	var cells []string
	var current strings.Builder

	for i := 0; i < len(line); i++ {
		char := line[i]

		if char == '\\' && i+1 < len(line) && line[i+1] == '|' {
			// This is an escaped pipe, write both characters and skip the pipe
			current.WriteByte(char)
			current.WriteByte(line[i+1])
			i++ // Skip the next character (the pipe)
			continue
		}

		if char == '|' {
			cells = append(cells, strings.TrimSpace(current.String()))
			current.Reset()
			continue
		}

		current.WriteByte(char)
	}

	// Add the last cell
	cells = append(cells, strings.TrimSpace(current.String()))

	return cells
}

func TestSplitOnUnescapedPipes(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []string
	}{
		{
			name:     "simple table row",
			input:    "cell1|cell2|cell3",
			expected: []string{"cell1", "cell2", "cell3"},
		},
		{
			name:     "table with escaped pipes",
			input:    "cell1\\|with pipe|cell2|cell3",
			expected: []string{"cell1\\|with pipe", "cell2", "cell3"},
		},
		{
			name:     "table with multiple escaped pipes",
			input:    "cell1\\|pipe1\\|pipe2|cell2|cell3",
			expected: []string{"cell1\\|pipe1\\|pipe2", "cell2", "cell3"},
		},
		{
			name:     "table with backslash not followed by pipe",
			input:    "cell1\\n|cell2|cell3",
			expected: []string{"cell1\\n", "cell2", "cell3"},
		},
		{
			name:     "single cell with escaped pipe",
			input:    "cell1\\|with pipe",
			expected: []string{"cell1\\|with pipe"},
		},
		{
			name:     "empty cells",
			input:    "||",
			expected: []string{"", "", ""},
		},
		{
			name:     "cells with spaces",
			input:    " cell1 | cell2 | cell3 ",
			expected: []string{"cell1", "cell2", "cell3"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := splitOnUnescapedPipes(tt.input)
			if !reflect.DeepEqual(result, tt.expected) {
				t.Errorf("splitOnUnescapedPipes(%q) = %v, want %v", tt.input, result, tt.expected)
			}
		})
	}
}

func validateMarkdownSyntax(t *testing.T, content string) {
	t.Helper()

	// Check for unescaped pipes in tables
	lines := strings.Split(content, "\n")
	for i, line := range lines {
		if strings.Contains(line, "|") && !strings.Contains(line, "\\|") {
			// This should be a table line
			if !strings.HasPrefix(strings.TrimSpace(line), "|") &&
				!strings.HasSuffix(strings.TrimSpace(line), "|") {
				// Split on unescaped pipes and validate table structure
				cells := splitOnUnescapedPipes(line)
				if len(cells) < 2 {
					t.Errorf("Line %d has insufficient cells for table structure (found %d, need at least 2): %s",
						i+1, len(cells), line)
				}
			}
		}
	}

	// Check for properly closed code blocks
	codeBlockCount := strings.Count(content, "```")
	assert.Equal(t, 0, codeBlockCount%2, "Code blocks should be properly closed")
}

func validateTableFormatting(t *testing.T, content string) {
	t.Helper()

	lines := strings.Split(content, "\n")
	inTable := false

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)

		// Detect table start
		if strings.HasPrefix(trimmed, "|") && strings.HasSuffix(trimmed, "|") {
			if !inTable {
				inTable = true
				// Next line should be separator
				if i+1 < len(lines) {
					nextLine := strings.TrimSpace(lines[i+1])
					if strings.Contains(nextLine, "|") && strings.Contains(nextLine, "-") {
						// Just check it's a valid table separator - be more lenient
						if !strings.HasPrefix(nextLine, "|") || !strings.HasSuffix(nextLine, "|") {
							t.Errorf("Table separator line should start and end with | at line %d: %s", i+2, nextLine)
						}
					}
				}
			}
		} else if inTable && trimmed == "" {
			inTable = false
		}
	}
}

func generateLargeTestData(t *testing.T) *common.CommonDevice {
	t.Helper()

	// Generate test data with many interfaces, rules, users, etc.
	doc := &common.CommonDevice{
		System: common.System{
			Hostname: "large-test-host",
			Domain:   "large.test.local",
			Firmware: common.Firmware{
				Version: "24.1.2",
			},
		},
	}

	// Generate 20 interfaces
	doc.Interfaces = make([]common.Interface, 0, 20)
	for i := range 20 {
		doc.Interfaces = append(doc.Interfaces, common.Interface{
			Name:       fmt.Sprintf("if%d", i),
			PhysicalIf: fmt.Sprintf("em%d", i),
			Enabled:    true,
			IPAddress:  fmt.Sprintf("10.0.%d.1", i),
			Subnet:     "24",
		})
	}

	// Generate 100 firewall rules
	doc.FirewallRules = make([]common.FirewallRule, 0, 100)
	for i := range 100 {
		rule := common.FirewallRule{
			Type:        []string{"pass", "block"}[i%2],
			Description: fmt.Sprintf("Rule %d", i+1),
			Interfaces:  []string{fmt.Sprintf("if%d", i%20)},
			IPProtocol:  "inet",
			Protocol:    "tcp",
			Source:      common.RuleEndpoint{Address: "any"},
			Destination: common.RuleEndpoint{Address: "any"},
		}
		doc.FirewallRules = append(doc.FirewallRules, rule)
	}

	// Generate 10 users
	for i := range 10 {
		user := common.User{
			Name:        fmt.Sprintf("user%d", i),
			Description: fmt.Sprintf("Test User %d", i),
			GroupName:   "users",
			Scope:       "local",
		}
		doc.Users = append(doc.Users, user)
	}

	// Generate 50 sysctl items
	for i := range 50 {
		sysctl := common.SysctlItem{
			Tunable:     fmt.Sprintf("test.sysctl.item%d", i),
			Value:       strconv.Itoa(i % 2),
			Description: fmt.Sprintf("Test sysctl item %d", i),
		}
		doc.Sysctl = append(doc.Sysctl, sysctl)
	}

	return doc
}
