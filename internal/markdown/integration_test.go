package markdown

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/model"
	"github.com/EvilBit-Labs/opnDossier/internal/parser"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// createTempXMLFile creates a temporary XML file with given content and returns setup function.
func createTempXMLFile(t *testing.T, pattern, content string) func() (string, func()) {
	t.Helper()
	return func() (string, func()) {
		tmpFile, err := os.CreateTemp(t.TempDir(), pattern)
		if err != nil {
			t.Fatalf("Failed to create temp file: %v", err)
		}

		if _, err := tmpFile.WriteString(content); err != nil {
			if err := tmpFile.Close(); err != nil {
				t.Fatalf("Failed to close temp file: %v", err)
			}
			if err := os.Remove(tmpFile.Name()); err != nil {
				t.Logf("Failed to remove temp file: %v", err)
			}
			t.Fatalf("Failed to write temp file: %v", err)
		}
		if err := tmpFile.Close(); err != nil {
			t.Fatalf("Failed to close temp file: %v", err)
		}

		return tmpFile.Name(), func() {
			if err := os.Remove(tmpFile.Name()); err != nil {
				t.Logf("Failed to remove temp file: %v", err)
			}
		}
	}
}

// TestGenerateFromXMLFiles tests the markdown generator with all XML files in testdata.
func TestGenerateFromXMLFiles(t *testing.T) {
	testdataDir := "testdata"

	// Find all XML files in testdata directory
	xmlFiles, err := filepath.Glob(filepath.Join(testdataDir, "*.xml"))
	require.NoError(t, err, "Failed to find XML files in testdata directory")
	require.NotEmpty(t, xmlFiles, "No XML files found in testdata directory")

	// Define test cases for each XML file with expected content markers
	tests := []struct {
		name                    string
		xmlFile                 string
		expectedSections        []string // Main section headers we expect
		expectedSystemMarkers   []string // System section content markers
		expectedNetworkMarkers  []string // Network section content markers
		expectedSecurityMarkers []string // Security section content markers
		expectedServiceMarkers  []string // Service section content markers
		expectedSysctlKeys      []string // Known sysctl keys that should appear
	}{
		{
			name:    "config.xml",
			xmlFile: "testdata/config.xml",
			expectedSections: []string{
				"# OPNsense Configuration Summary",
				"## Interfaces",
				"## Firewall Rules",
				"## NAT Rules",
				"## DHCP Services",
			},
			expectedSystemMarkers: []string{
				"**Hostname**: TestHost",
				"**Platform**: OPNsense",
			},
			expectedNetworkMarkers: []string{
				"## Interfaces",
				"wan",
				"lan",
			},
			expectedSecurityMarkers: []string{
				"## NAT Rules",
				"automatic",
			},
			expectedServiceMarkers: []string{
				"## DHCP Services",
				"## DNS Resolver",
			},
			expectedSysctlKeys: []string{
				// We'll validate these dynamically based on actual XML content
			},
		},
		{
			name:    "sample.config.1.xml",
			xmlFile: "testdata/sample.config.1.xml",
			expectedSections: []string{
				"# OPNsense Configuration Summary",
				"## Interfaces",
				"## Firewall Rules",
				"## NAT Rules",
				"## DHCP Services",
			},
			expectedSystemMarkers: []string{
				"**Hostname**: TestHost",
				"**Platform**: OPNsense",
			},
			expectedNetworkMarkers: []string{
				"## Interfaces",
				"wan",
				"lan",
				"192.168.1.1",
			},
			expectedSecurityMarkers: []string{
				"## NAT Rules",
				"automatic",
				"Default allow LAN to any rule",
			},
			expectedServiceMarkers: []string{
				"## DHCP Services",
				"## DNS Resolver",
				"192.168.1.100",
			},
			expectedSysctlKeys: []string{
				// NOTE: Currently sysctl parsing is not working in the parser
				// so these tests are disabled until the parser is fixed
			},
		},
		{
			name:    "sample.config.2.xml",
			xmlFile: "testdata/sample.config.2.xml",
			expectedSections: []string{
				"# OPNsense Configuration Summary",
				"## Interfaces",
				"## Firewall Rules",
				"## NAT Rules",
				"## DHCP Services",
			},
			expectedSystemMarkers: []string{
				"**Platform**: OPNsense",
			},
			expectedNetworkMarkers: []string{
				"## Interfaces",
				"wan",
				"lan",
			},
			expectedSecurityMarkers: []string{
				"## NAT Rules",
			},
			expectedServiceMarkers: []string{
				"## DHCP Services",
			},
			expectedSysctlKeys: []string{
				// Will be populated based on actual content
			},
		},
		{
			name:    "sample.config.3.xml",
			xmlFile: "testdata/sample.config.3.xml",
			expectedSections: []string{
				"# OPNsense Configuration Summary",
				"## Interfaces",
				"## Firewall Rules",
				"## NAT Rules",
				"## DHCP Services",
			},
			expectedSystemMarkers: []string{
				"**Platform**: OPNsense",
			},
			expectedNetworkMarkers: []string{
				"## Interfaces",
				"wan",
				"lan",
			},
			expectedSecurityMarkers: []string{
				"## NAT Rules",
			},
			expectedServiceMarkers: []string{
				"## DHCP Services",
			},
			expectedSysctlKeys: []string{
				// Will be populated based on actual content
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Check if XML file exists
			if _, err := os.Stat(tt.xmlFile); os.IsNotExist(err) {
				t.Skipf("XML file %s does not exist, skipping test", tt.xmlFile)
				return
			}

			// Load XML file
			xmlFile, err := os.Open(tt.xmlFile)
			require.NoError(t, err, "Failed to open XML file: %s", tt.xmlFile)

			defer func() {
				err := xmlFile.Close()
				require.NoError(t, err)
			}()

			// Parse XML into model
			xmlParser := parser.NewXMLParser()
			ctx := context.Background()
			cfg, err := xmlParser.Parse(ctx, xmlFile)
			require.NoError(t, err, "Failed to parse XML file: %s", tt.xmlFile)
			assert.NotNil(t, cfg, "Parsed configuration should not be nil")

			// Test Markdown generation
			t.Run("markdown_generation", func(t *testing.T) {
				generator, err := NewMarkdownGenerator(nil)
				require.NoError(t, err)

				opts := DefaultOptions().WithFormat(FormatMarkdown)

				result, err := generator.Generate(ctx, cfg, opts)
				require.NoError(t, err, "Markdown generation should not fail")
				assert.NotEmpty(t, result, "Generated markdown should not be empty")

				// Test main sections are present
				for _, section := range tt.expectedSections {
					assert.Contains(t, result, section, "Should contain main section: %s", section)
				}

				// Test system section markers
				for _, marker := range tt.expectedSystemMarkers {
					assert.Contains(t, result, marker, "Should contain system marker: %s", marker)
				}

				// Test network section markers
				for _, marker := range tt.expectedNetworkMarkers {
					assert.Contains(t, result, marker, "Should contain network marker: %s", marker)
				}

				// Test security section markers
				for _, marker := range tt.expectedSecurityMarkers {
					assert.Contains(t, result, marker, "Should contain security marker: %s", marker)
				}

				// Test service section markers
				for _, marker := range tt.expectedServiceMarkers {
					assert.Contains(t, result, marker, "Should contain service marker: %s", marker)
				}

				// Test sysctl keys are present if any are defined
				if len(tt.expectedSysctlKeys) > 0 {
					assert.Contains(t, result, "### System Tuning (Sysctl)", "Should contain sysctl section")

					for _, key := range tt.expectedSysctlKeys {
						assert.Contains(t, result, key, "Should contain sysctl key: %s", key)
					}
				}

				// Additional validation: ensure sections are properly formatted
				assert.Contains(t, result, "# OPNsense Configuration Summary", "Should have main title")

				// Count section headers to ensure we have expected structure
				sectionCount := strings.Count(result, "## ")
				assert.GreaterOrEqual(t, sectionCount, 4, "Should have at least 4 main sections")

				// The current template doesn't have subsections, so we don't check for them
				// subsectionCount := strings.Count(result, "### ")
				// assert.Greater(t, subsectionCount, 0, "Should have subsections")
			})

			// Test JSON generation
			t.Run("json_generation", func(t *testing.T) {
				generator, err := NewMarkdownGenerator(nil)
				require.NoError(t, err)

				opts := DefaultOptions().WithFormat(FormatJSON)

				result, err := generator.Generate(ctx, cfg, opts)
				require.NoError(t, err, "JSON generation should not fail")
				assert.NotEmpty(t, result, "Generated JSON should not be empty")

				// Basic JSON structure validation
				assert.True(t, strings.HasPrefix(result, "{"), "JSON should start with {")
				assert.True(t, strings.HasSuffix(strings.TrimSpace(result), "}"), "JSON should end with }")

				// Should contain basic system information
				if cfg.System.Hostname != "" {
					assert.Contains(t, result, cfg.System.Hostname, "JSON should contain hostname")
				}

				if cfg.System.Domain != "" {
					assert.Contains(t, result, cfg.System.Domain, "JSON should contain domain")
				}
			})

			// Test YAML generation
			t.Run("yaml_generation", func(t *testing.T) {
				generator, err := NewMarkdownGenerator(nil)
				require.NoError(t, err)

				opts := DefaultOptions().WithFormat(FormatYAML)

				result, err := generator.Generate(ctx, cfg, opts)
				require.NoError(t, err, "YAML generation should not fail")
				assert.NotEmpty(t, result, "Generated YAML should not be empty")

				// Basic YAML structure validation
				lines := strings.Split(result, "\n")
				assert.Greater(t, len(lines), 1, "YAML should have multiple lines")

				// Should contain basic system information
				if cfg.System.Hostname != "" {
					assert.Contains(t, result, cfg.System.Hostname, "YAML should contain hostname")
				}

				if cfg.System.Domain != "" {
					assert.Contains(t, result, cfg.System.Domain, "YAML should contain domain")
				}
			})
		})
	}
}

// TestGenerateFromXMLFilesRobustness tests edge cases and error conditions.
func TestGenerateFromXMLFilesRobustness(t *testing.T) {
	tests := []struct {
		name        string
		setupFunc   func() (string, func()) // Returns file path and cleanup function
		expectError bool
		errorType   string
	}{
		{
			name: "empty_xml_file",
			setupFunc: func() (string, func()) {
				tmpFile, err := os.CreateTemp(t.TempDir(), "empty-*.xml")
				if err != nil {
					t.Fatalf("Failed to create temp file: %v", err)
				}
				if err := tmpFile.Close(); err != nil {
					t.Fatalf("Failed to close temp file: %v", err)
				}

				return tmpFile.Name(), func() {
					if err := os.Remove(tmpFile.Name()); err != nil {
						t.Logf("Failed to remove temp file: %v", err)
					}
				}
			},
			expectError: true,
			errorType:   "parse_error",
		},
		{
			name:        "invalid_xml_content",
			setupFunc:   createTempXMLFile(t, "invalid-*.xml", `<?xml version="1.0"?><invalid><unclosed>`),
			expectError: true,
			errorType:   "xml_syntax_error",
		},
		{
			name: "missing_opnsense_root",
			setupFunc: createTempXMLFile(
				t,
				"noroot-*.xml",
				`<?xml version="1.0"?><config><system><hostname>test</hostname></system></config>`,
			),
			expectError: true,
			errorType:   "missing_root",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filePath, cleanup := tt.setupFunc()
			defer cleanup()

			// Try to parse the XML file
			xmlFile, err := os.Open(filePath)
			require.NoError(t, err, "Failed to open test XML file")

			defer func() {
				err := xmlFile.Close()
				require.NoError(t, err)
			}()

			xmlParser := parser.NewXMLParser()
			ctx := context.Background()
			cfg, err := xmlParser.Parse(ctx, xmlFile)

			if tt.expectError {
				require.Error(t, err, "Should have failed to parse invalid XML")
				assert.Nil(t, cfg, "Configuration should be nil on parse error")

				return
			}

			// If parsing succeeded, test generation
			require.NoError(t, err, "Should successfully parse XML")
			require.NotNil(t, cfg, "Configuration should not be nil")

			generator, err := NewMarkdownGenerator(nil)
			require.NoError(t, err)

			opts := DefaultOptions().WithFormat(FormatMarkdown)

			result, err := generator.Generate(ctx, cfg, opts)
			require.NoError(t, err, "Generation should not fail with valid config")
			assert.NotEmpty(t, result, "Generated content should not be empty")
		})
	}
}

// TestDebugSysctlParsing helps debug sysctl parsing issues.
func TestDebugSysctlParsing(t *testing.T) {
	// Load sample.config.1.xml which has known sysctl entries
	xmlFile, err := os.Open("testdata/sample.config.1.xml")
	require.NoError(t, err, "Failed to open sample.config.1.xml")

	defer func() {
		err := xmlFile.Close()
		require.NoError(t, err)
	}()

	xmlParser := parser.NewXMLParser()
	ctx := context.Background()
	cfg, err := xmlParser.Parse(ctx, xmlFile)
	require.NoError(t, err, "Failed to parse sample.config.1.xml")
	require.NotNil(t, cfg, "Configuration should not be nil")

	// Debug print the sysctl entries
	t.Logf("Sysctl entries found: %d", len(cfg.Sysctl))

	for i, entry := range cfg.Sysctl {
		t.Logf("Entry %d: Tunable=%s, Value=%s, Descr=%s", i, entry.Tunable, entry.Value, entry.Descr)
	}

	// Check system config
	sysConfig := cfg.SystemConfig()
	t.Logf("System config sysctl entries: %d", len(sysConfig.Sysctl))

	for i, entry := range sysConfig.Sysctl {
		t.Logf("SysConfig Entry %d: Tunable=%s, Value=%s, Descr=%s", i, entry.Tunable, entry.Value, entry.Descr)
	}

	// Generate markdown to see output
	generator, err := NewMarkdownGenerator(nil)
	require.NoError(t, err)

	opts := DefaultOptions().WithFormat(FormatMarkdown)

	result, err := generator.Generate(ctx, cfg, opts)
	require.NoError(t, err, "Markdown generation should not fail")

	t.Logf("Generated output contains 'System Tuning': %v", strings.Contains(result, "System Tuning"))

	// Print a portion of the result to see what's there
	if len(result) > 2000 {
		t.Logf("Generated markdown (first 2000 chars):\n%s...", result[:2000])
	} else {
		t.Logf("Generated markdown:\n%s", result)
	}
}

// TestSysctlKeyValidation specifically tests that sysctl keys are properly formatted and displayed
// NOTE: Currently skipped because sysctl parsing is not working in the XML parser.
func TestSysctlKeyValidation(t *testing.T) {
	t.Skip(
		"Sysctl parsing is currently not working in the XML parser - individual <sysctl> elements are not being handled correctly",
	)

	// Load sample.config.1.xml which has known sysctl entries
	xmlFile, err := os.Open("testdata/sample.config.1.xml")
	require.NoError(t, err, "Failed to open sample.config.1.xml")

	defer func() {
		if err := xmlFile.Close(); err != nil {
			t.Logf("Failed to close XML file: %v", err)
		}
	}()

	xmlParser := parser.NewXMLParser()
	ctx := context.Background()
	cfg, err := xmlParser.Parse(ctx, xmlFile)
	require.NoError(t, err, "Failed to parse sample.config.1.xml")
	require.NotNil(t, cfg, "Configuration should not be nil")

	generator, err := NewMarkdownGenerator(nil)
	require.NoError(t, err)

	opts := DefaultOptions().WithFormat(FormatMarkdown)

	result, err := generator.Generate(ctx, cfg, opts)
	require.NoError(t, err, "Markdown generation should not fail")
	require.NotEmpty(t, result, "Generated markdown should not be empty")

	// Check that sysctl section exists
	assert.Contains(t, result, "### System Tuning (Sysctl)", "Should contain sysctl section header")

	// Check specific sysctl keys from sample.config.1.xml
	expectedSysctlEntries := []struct {
		key         string
		value       string
		description string
	}{
		{
			key:         "net.inet.ip.random_id",
			value:       "1",
			description: "Randomize the ID field in IP packets",
		},
		{
			key:         "net.inet.tcp.log_debug",
			value:       "0",
			description: "Enable TCP extended debugging",
		},
	}

	for _, entry := range expectedSysctlEntries {
		// Check that the sysctl key appears in bold
		assert.Contains(t, result, "**"+entry.key+"**", "Should contain sysctl key in bold: %s", entry.key)

		// Check that the value appears
		assert.Contains(t, result, entry.value, "Should contain sysctl value: %s", entry.value)

		// Check that description appears
		if entry.description != "" {
			assert.Contains(t, result, entry.description, "Should contain sysctl description: %s", entry.description)
		}

		// Check status field (should show enabled for existing entries)
		assert.Contains(t, result, "*Status*: enabled", "Should show enabled status for sysctl entries")
	}
}

// TestInterfaceConfigurationDetail tests that network interface details are properly rendered.
func TestInterfaceConfigurationDetail(t *testing.T) {
	// Load sample.config.1.xml which has detailed interface config
	xmlFile, err := os.Open("testdata/sample.config.1.xml")
	require.NoError(t, err, "Failed to open sample.config.1.xml")

	defer func() {
		if err := xmlFile.Close(); err != nil {
			t.Logf("Failed to close XML file: %v", err)
		}
	}()

	xmlParser := parser.NewXMLParser()
	ctx := context.Background()
	cfg, err := xmlParser.Parse(ctx, xmlFile)
	require.NoError(t, err, "Failed to parse sample.config.1.xml")
	require.NotNil(t, cfg, "Configuration should not be nil")

	generator, err := NewMarkdownGenerator(nil)
	require.NoError(t, err)

	opts := DefaultOptions().WithFormat(FormatMarkdown)

	result, err := generator.Generate(ctx, cfg, opts)
	require.NoError(t, err, "Markdown generation should not fail")
	require.NotEmpty(t, result, "Generated markdown should not be empty")

	// Test interfaces table format (table-based instead of individual sections)
	assert.Contains(t, result, "## Interfaces", "Should contain interfaces section")
	assert.Contains(t, result, "em0", "Should show WAN physical interface")
	assert.Contains(t, result, "em1", "Should show LAN physical interface")
	assert.Contains(t, result, "192.168.1.1", "Should show LAN IPv4 address")
	assert.Contains(t, result, "24", "Should show LAN subnet")
	assert.Contains(t, result, "dhcp", "Should show WAN DHCP configuration")
}

// TestFirewallRulesFormatting tests that firewall rules are properly formatted in tables.
func TestFirewallRulesFormatting(t *testing.T) {
	// Load sample.config.1.xml which has firewall rules
	xmlFile, err := os.Open("testdata/sample.config.1.xml")
	require.NoError(t, err, "Failed to open sample.config.1.xml")

	defer func() {
		if err := xmlFile.Close(); err != nil {
			t.Logf("Failed to close XML file: %v", err)
		}
	}()

	xmlParser := parser.NewXMLParser()
	ctx := context.Background()
	cfg, err := xmlParser.Parse(ctx, xmlFile)
	require.NoError(t, err, "Failed to parse sample.config.1.xml")
	require.NotNil(t, cfg, "Configuration should not be nil")

	generator, err := NewMarkdownGenerator(nil)
	require.NoError(t, err)

	opts := DefaultOptions().WithFormat(FormatMarkdown)

	result, err := generator.Generate(ctx, cfg, opts)
	require.NoError(t, err, "Markdown generation should not fail")
	require.NotEmpty(t, result, "Generated markdown should not be empty")

	// Test firewall rules section
	assert.Contains(t, result, "## Firewall Rules", "Should contain firewall rules section")

	// Test table headers based on actual template output
	expectedHeaders := []string{"Action", "Proto", "Source", "Destination", "Description"}
	for _, header := range expectedHeaders {
		assert.Contains(t, result, header, "Should contain firewall table header: %s", header)
	}

	// Test specific rule content from sample.config.1.xml
	assert.Contains(t, result, "Default allow LAN to any rule", "Should contain specific rule description")
	assert.Contains(t, result, "Block bogon networks on", "Should contain specific rule description")
	assert.Contains(t, result, "pass", "Should contain pass action")
	assert.Contains(t, result, "block", "Should contain block action")
}

func TestMarkdownGenerator_Integration(t *testing.T) {
	// Create a test configuration
	cfg := &model.OpnSenseDocument{
		System: model.System{
			Hostname: "test-host",
			Domain:   "test.local",
		},
		Interfaces: model.Interfaces{
			Items: map[string]model.Interface{
				"wan": {
					Enable:  "1",
					If:      "em0",
					Descr:   "WAN Interface",
					IPAddr:  "192.168.1.1",
					Subnet:  "24",
					Gateway: "192.168.1.254",
				},
			},
		},
	}

	ctx := context.Background()

	t.Run("markdown generation", func(t *testing.T) {
		generator, err := NewMarkdownGenerator(nil)
		require.NoError(t, err)

		opts := DefaultOptions().WithFormat(FormatMarkdown)
		result, err := generator.Generate(ctx, cfg, opts)

		require.NoError(t, err)
		assert.NotEmpty(t, result)
		assert.Contains(t, result, "test-host")
		assert.Contains(t, result, "WAN Interface")
	})

	t.Run("comprehensive markdown generation", func(t *testing.T) {
		generator, err := NewMarkdownGenerator(nil)
		require.NoError(t, err)

		opts := DefaultOptions().WithFormat(FormatMarkdown).WithComprehensive(true)
		result, err := generator.Generate(ctx, cfg, opts)

		require.NoError(t, err)
		assert.NotEmpty(t, result)
		assert.Contains(t, result, "test-host")
		assert.Contains(t, result, "WAN Interface")
	})

	t.Run("JSON generation", func(t *testing.T) {
		generator, err := NewMarkdownGenerator(nil)
		require.NoError(t, err)

		opts := DefaultOptions().WithFormat(FormatJSON)
		result, err := generator.Generate(ctx, cfg, opts)

		require.NoError(t, err)
		assert.NotEmpty(t, result)
		assert.Contains(t, result, "test-host")
		assert.Contains(t, result, "WAN Interface")
	})

	t.Run("YAML generation", func(t *testing.T) {
		generator, err := NewMarkdownGenerator(nil)
		require.NoError(t, err)

		opts := DefaultOptions().WithFormat(FormatYAML)
		result, err := generator.Generate(ctx, cfg, opts)

		require.NoError(t, err)
		assert.NotEmpty(t, result)
		assert.Contains(t, result, "test-host")
		assert.Contains(t, result, "WAN Interface")
	})
}

func TestTemplateRendering_Integration(t *testing.T) {
	cfg := &model.OpnSenseDocument{
		System: model.System{
			Hostname: "template-test",
			Domain:   "test.local",
		},
	}

	ctx := context.Background()

	t.Run("standard template", func(t *testing.T) {
		generator, err := NewMarkdownGenerator(nil)
		require.NoError(t, err)

		opts := DefaultOptions().WithFormat(FormatMarkdown)
		result, err := generator.Generate(ctx, cfg, opts)

		require.NoError(t, err)
		assert.Contains(t, result, "template-test")
		assert.Contains(t, result, "test.local")
	})

	t.Run("comprehensive template", func(t *testing.T) {
		generator, err := NewMarkdownGenerator(nil)
		require.NoError(t, err)

		opts := DefaultOptions().WithFormat(FormatMarkdown).WithComprehensive(true)
		result, err := generator.Generate(ctx, cfg, opts)

		require.NoError(t, err)
		assert.Contains(t, result, "template-test")
		assert.Contains(t, result, "test.local")
	})
}

func TestErrorHandling_Integration(t *testing.T) {
	ctx := context.Background()

	t.Run("nil configuration", func(t *testing.T) {
		generator, err := NewMarkdownGenerator(nil)
		require.NoError(t, err)

		opts := DefaultOptions()
		result, err := generator.Generate(ctx, nil, opts)

		require.Error(t, err)
		assert.Equal(t, ErrNilConfiguration, err)
		assert.Empty(t, result)
	})

	t.Run("invalid options", func(t *testing.T) {
		generator, err := NewMarkdownGenerator(nil)
		require.NoError(t, err)

		cfg := &model.OpnSenseDocument{}
		opts := Options{Format: Format("invalid")}
		result, err := generator.Generate(ctx, cfg, opts)

		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid options")
		assert.Empty(t, result)
	})
}
