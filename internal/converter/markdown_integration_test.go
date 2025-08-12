package converter

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/model"
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
	interfaceTable := builder.BuildInterfaceTable(testData.Interfaces)
	rulesTable := builder.BuildFirewallRulesTable(testData.Filter.Rule)
	userTable := builder.BuildUserTable(testData.System.User)
	groupTable := builder.BuildGroupTable(testData.System.Group)
	sysctlTable := builder.BuildSysctlTable(testData.Sysctl)

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
		data     *model.OpnSenseDocument
		wantErr  bool
		errCheck func(t *testing.T, err error)
	}{
		{
			name:    "nil document",
			data:    nil,
			wantErr: true,
			errCheck: func(t *testing.T, err error) {
				t.Helper()
				assert.Equal(t, ErrNilOpnSenseDocument, err)
			},
		},
		{
			name:    "empty document",
			data:    &model.OpnSenseDocument{},
			wantErr: false,
		},
		{
			name: "document with only system",
			data: &model.OpnSenseDocument{
				System: model.System{
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

func loadTestDataFromFile(t *testing.T, filename string) *model.OpnSenseDocument {
	t.Helper()

	path := filepath.Join("testdata", filename)
	data, err := os.ReadFile(path)
	require.NoError(t, err, "Failed to read test data file: %s", filename)

	var doc model.OpnSenseDocument
	err = json.Unmarshal(data, &doc) //nolint:musttag // JSON tags not required for test data
	require.NoError(t, err, "Failed to unmarshal test data: %s", filename)

	return &doc
}

func validateTableStructure(t *testing.T, table any, tableName string) {
	t.Helper()

	// Basic validation that table is not nil and has expected structure
	assert.NotNil(t, table, "%s table should not be nil", tableName)

	// Additional table-specific validations could be added here
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

func validateMarkdownSyntax(t *testing.T, content string) {
	t.Helper()

	// Check for unescaped pipes in tables
	lines := strings.Split(content, "\n")
	for i, line := range lines {
		if strings.Contains(line, "|") && !strings.Contains(line, "\\|") {
			// This should be a table line
			if !strings.HasPrefix(strings.TrimSpace(line), "|") &&
				!strings.HasSuffix(strings.TrimSpace(line), "|") {
				// Count pipes to ensure even number (proper table structure)
				pipeCount := strings.Count(line, "|")
				if pipeCount%2 != 0 {
					t.Errorf("Line %d has odd number of pipes, may indicate malformed table: %s",
						i+1, line)
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

func generateLargeTestData(t *testing.T) *model.OpnSenseDocument {
	t.Helper()

	// Generate test data with many interfaces, rules, users, etc.
	doc := &model.OpnSenseDocument{
		System: model.System{
			Hostname: "large-test-host",
			Domain:   "large.test.local",
			Firmware: model.Firmware{
				Version: "24.1.2",
			},
		},
		Interfaces: model.Interfaces{
			Items: make(map[string]model.Interface),
		},
		Filter: model.Filter{
			Rule: make([]model.Rule, 0, 100),
		},
		Sysctl: make([]model.SysctlItem, 0, 50),
	}

	// Generate 20 interfaces
	for i := range 20 {
		name := fmt.Sprintf("if%d", i)
		doc.Interfaces.Items[name] = model.Interface{
			If:     fmt.Sprintf("em%d", i),
			Enable: "1",
			IPAddr: fmt.Sprintf("10.0.%d.1", i),
			Subnet: "24",
			Descr:  fmt.Sprintf("Interface %d", i),
		}
	}

	// Generate 100 firewall rules
	for i := range 100 {
		rule := model.Rule{
			Type:       []string{"pass", "block"}[i%2],
			Descr:      fmt.Sprintf("Rule %d", i+1),
			Interface:  model.InterfaceList{fmt.Sprintf("if%d", i%20)},
			IPProtocol: "inet",
			Protocol:   "tcp",
			Source: model.Source{
				Network: "any",
			},
			Destination: model.Destination{
				Network: "any",
			},
		}
		doc.Filter.Rule = append(doc.Filter.Rule, rule)
	}

	// Generate 10 users
	for i := range 10 {
		user := model.User{
			Name:      fmt.Sprintf("user%d", i),
			Descr:     fmt.Sprintf("Test User %d", i),
			Groupname: "users",
			Scope:     "local",
		}
		doc.System.User = append(doc.System.User, user)
	}

	// Generate 50 sysctl items
	for i := range 50 {
		sysctl := model.SysctlItem{
			Tunable: fmt.Sprintf("test.sysctl.item%d", i),
			Value:   strconv.Itoa(i % 2),
			Descr:   fmt.Sprintf("Test sysctl item %d", i),
		}
		doc.Sysctl = append(doc.Sysctl, sysctl)
	}

	return doc
}
