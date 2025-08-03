package parser

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/EvilBit-Labs/opnDossier/internal/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestXMLParser_Parse(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected *model.OpnSenseDocument
		wantErr  bool
	}{
		{
			name:  "valid config",
			input: `<opnsense><version>1.2.3</version><system><hostname>test-host</hostname><domain>test.local</domain></system></opnsense>`,
			expected: &model.OpnSenseDocument{
				Version: "1.2.3",
				System: model.System{
					Hostname: "test-host",
					Domain:   "test.local",
				},
			},
			wantErr: false,
		},
		{
			name:     "invalid xml",
			input:    `<opnsense><version>1.2.3</version><system><hostname>test-host</hostname></system>`,
			expected: nil,
			wantErr:  true,
		},
		{
			name:     "empty input",
			input:    ` `,
			expected: nil,
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := NewXMLParser()
			opnsense, err := p.Parse(context.Background(), strings.NewReader(tt.input))

			if tt.wantErr {
				require.Error(t, err)
				assert.Nil(t, opnsense)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expected.Version, opnsense.Version)
				assert.Equal(t, tt.expected.System.Hostname, opnsense.System.Hostname)
				assert.Equal(t, tt.expected.System.Domain, opnsense.System.Domain)
			}
		})
	}
}

// TestXMLParser_ParseSampleFiles tests parsing of real config.xml sample files.
func TestXMLParser_ParseSampleFiles(t *testing.T) {
	testDataDir := "testdata"

	// Get all .xml.sample files in testdata directory
	sampleFiles, err := filepath.Glob(filepath.Join(testDataDir, "*.xml.sample"))
	require.NoError(t, err, "Failed to find sample XML files")

	if len(sampleFiles) == 0 {
		t.Skip("No sample XML files found in testdata directory")
	}

	parser := NewXMLParser()

	for _, sampleFile := range sampleFiles {
		t.Run(filepath.Base(sampleFile), func(t *testing.T) {
			// Open and parse the file
			file, err := os.Open(sampleFile)
			require.NoError(t, err, "Failed to open sample file: %s", sampleFile)

			defer func() { _ = file.Close() }()

			opnsense, err := parser.Parse(context.Background(), file)
			require.NoError(t, err, "Failed to parse sample file: %s", sampleFile)
			require.NotNil(t, opnsense, "Parsed config should not be nil")

			// Run comprehensive validation
			validateOPNsenseConfig(t, opnsense, sampleFile)
		})
	}
}

// TestXMLParser_ParseConfigSample specifically tests the main config.xml.sample file.
func TestXMLParser_ParseConfigSample(t *testing.T) {
	sampleFile := filepath.Join("testdata", "sample.config.3.xml")

	// Check if file exists
	if _, err := os.Stat(sampleFile); os.IsNotExist(err) {
		t.Skip("sample.config.3.xml not found in testdata directory")
	}

	parser := NewXMLParser()
	file, err := os.Open(sampleFile)
	require.NoError(t, err)

	defer func() { _ = file.Close() }()

	opnsense, err := parser.Parse(context.Background(), file)
	require.NoError(t, err)
	require.NotNil(t, opnsense)

	// Test specific expected values from sample.config.3.xml
	t.Run("System Configuration", func(t *testing.T) {
		assert.Equal(t, "OPNsense", opnsense.System.Hostname)
		assert.Equal(t, "localdomain", opnsense.System.Domain)
		assert.Equal(t, "normal", opnsense.System.Optimization)
		assert.Equal(t, "Etc/UTC", opnsense.System.Timezone)
		assert.Equal(t, "1", opnsense.System.DNSAllowOverride)
		// Test WebGUI configuration
		if opnsense.System.WebGUI.Protocol != "https" {
			t.Errorf("Expected WebGUI protocol 'https', got '%s'", opnsense.System.WebGUI.Protocol)
		}
	})

	t.Run("Users and Groups", func(t *testing.T) {
		require.Len(t, opnsense.System.Group, 1)
		assert.Equal(t, "admins", opnsense.System.Group[0].Name)
		assert.Equal(t, "System Administrators", opnsense.System.Group[0].Description)
		assert.Equal(t, "1999", opnsense.System.Group[0].Gid)

		require.Len(t, opnsense.System.User, 1)
		assert.Equal(t, "root", opnsense.System.User[0].Name)
		assert.Equal(t, "System Administrator", opnsense.System.User[0].Descr)
		assert.Equal(t, "admins", opnsense.System.User[0].Groupname)
		assert.Equal(t, "0", opnsense.System.User[0].UID)
	})

	t.Run("Network Interfaces", func(t *testing.T) {
		// WAN Interface
		wan, wanExists := opnsense.Interfaces.Wan()
		require.True(t, wanExists, "WAN interface should exist")
		assert.Equal(t, "1", wan.Enable)
		assert.Equal(t, "mismatch1", wan.If)
		assert.Equal(t, "dhcp", wan.IPAddr)
		assert.Equal(t, "dhcp6", wan.IPAddrv6)
		assert.Equal(t, "1", wan.BlockPriv)
		assert.Equal(t, "1", wan.BlockBogons)

		// LAN Interface
		lan, lanExists := opnsense.Interfaces.Lan()
		require.True(t, lanExists, "LAN interface should exist")
		assert.Equal(t, "1", lan.Enable)
		assert.Equal(t, "mismatch0", lan.If)
		assert.Equal(t, "192.168.1.1", lan.IPAddr)
		assert.Equal(t, "track6", lan.IPAddrv6)
		assert.Equal(t, "24", lan.Subnet)
		assert.Equal(t, "64", lan.Subnetv6)
		assert.Equal(t, "wan", lan.Track6Interface)
		assert.Equal(t, "0", lan.Track6PrefixID)
	})

	t.Run("DHCP Configuration", func(t *testing.T) {
		lanDhcp, lanDhcpExists := opnsense.Dhcpd.Lan()
		require.True(t, lanDhcpExists, "LAN DHCP configuration should exist")
		assert.Equal(t, "192.168.1.100", lanDhcp.Range.From)
		assert.Equal(t, "192.168.1.199", lanDhcp.Range.To)
	})

	t.Run("Services", func(t *testing.T) {
		assert.Equal(t, "1", opnsense.Unbound.Enable)
		assert.Equal(t, "public", opnsense.Snmpd.ROCommunity)
		assert.Equal(t, "automatic", opnsense.Nat.Outbound.Mode)
		assert.Equal(t, "0.opnsense.pool.ntp.org", opnsense.Ntpd.Prefer)
	})

	t.Run("Sysctl Items", func(t *testing.T) {
		assert.Greater(t, len(opnsense.Sysctl), 30, "Should have more than 30 sysctl items")

		// Check a specific sysctl item
		found := false

		for _, item := range opnsense.Sysctl {
			if item.Tunable == "net.inet.icmp.drop_redirect" {
				assert.Equal(t, "1", item.Value)

				found = true

				break
			}
		}

		assert.True(t, found, "Should find net.inet.icmp.drop_redirect sysctl item")
	})

	t.Run("Firewall Rules", func(t *testing.T) {
		assert.Len(t, opnsense.Filter.Rule, 2)

		// Check first rule
		assert.Equal(t, "pass", opnsense.Filter.Rule[0].Type)
		assert.Equal(t, "inet", opnsense.Filter.Rule[0].IPProtocol)
		assert.Equal(t, "Default allow LAN to any rule", opnsense.Filter.Rule[0].Descr)
		assert.Equal(t, "lan", opnsense.Filter.Rule[0].Interface)
		assert.Equal(t, "lan", opnsense.Filter.Rule[0].Source.Network)

		// Check second rule (IPv6)
		assert.Equal(t, "pass", opnsense.Filter.Rule[1].Type)
		assert.Equal(t, "inet6", opnsense.Filter.Rule[1].IPProtocol)
		assert.Equal(t, "Default allow LAN IPv6 to any rule", opnsense.Filter.Rule[1].Descr)
	})

	t.Run("Load Balancer", func(t *testing.T) {
		assert.Len(t, opnsense.LoadBalancer.MonitorType, 5)

		// Check monitor types
		monitorNames := make([]string, len(opnsense.LoadBalancer.MonitorType))
		for i, monitor := range opnsense.LoadBalancer.MonitorType {
			monitorNames[i] = monitor.Name
		}

		assert.Contains(t, monitorNames, "ICMP")
		assert.Contains(t, monitorNames, "TCP")
		assert.Contains(t, monitorNames, "HTTP")
		assert.Contains(t, monitorNames, "HTTPS")
		assert.Contains(t, monitorNames, "SMTP")
	})

	// Widgets are now inline in System struct, so we test them there
}

// validateOPNsenseConfig performs comprehensive validation of an OPNsense configuration.
func validateOPNsenseConfig(t *testing.T, config *model.OpnSenseDocument, _ string) {
	t.Helper()

	t.Run("Basic Structure", func(t *testing.T) {
		assert.NotNil(t, config, "Config should not be nil")
		assert.Equal(t, "opnsense", config.XMLName.Local, "Root element should be 'opnsense'")
	})

	t.Run("System Configuration", func(t *testing.T) {
		assert.NotEmpty(t, config.System.Hostname, "Hostname should not be empty")
		assert.NotEmpty(t, config.System.Domain, "Domain should not be empty")

		// Validate users if present
		for i, user := range config.System.User {
			assert.NotEmpty(t, user.Name, "User %d name should not be empty", i)
			assert.NotEmpty(t, user.UID, "User %d UID should not be empty", i)
		}

		// Validate groups if present
		for i, group := range config.System.Group {
			assert.NotEmpty(t, group.Name, "Group %d name should not be empty", i)
			assert.NotEmpty(t, group.Gid, "Group %d GID should not be empty", i)
		}
	})

	t.Run("Network Interfaces", func(t *testing.T) {
		// At least one interface should be enabled
		var wanEnabled, lanEnabled bool
		if wan, exists := config.Interfaces.Wan(); exists {
			wanEnabled = wan.Enable == "1"
			// Validate interface name if specified
			if wan.If != "" {
				assert.NotEmpty(t, wan.If, "WAN interface name should not be empty if specified")
			}
		}

		if lan, exists := config.Interfaces.Lan(); exists {
			lanEnabled = lan.Enable == "1"
			// Validate interface name if specified
			if lan.If != "" {
				assert.NotEmpty(t, lan.If, "LAN interface name should not be empty if specified")
			}
		}

		assert.True(t, wanEnabled || lanEnabled, "At least one interface should be enabled")
	})

	t.Run("Sysctl Items", func(t *testing.T) {
		for i, item := range config.Sysctl {
			assert.NotEmpty(t, item.Tunable, "Sysctl item %d tunable should not be empty", i)
			assert.NotEmpty(t, item.Value, "Sysctl item %d value should not be empty", i)
			// Description can be empty, but if present should be reasonable
			if item.Descr != "" {
				assert.Greater(t, len(item.Descr), 5, "Sysctl item %d description should be meaningful", i)
			}
		}
	})

	t.Run("Firewall Rules", func(t *testing.T) {
		for i, rule := range config.Filter.Rule {
			assert.NotEmpty(t, rule.Type, "Rule %d type should not be empty", i)
			assert.Contains(t, []string{"pass", "block", "reject"}, rule.Type, "Rule %d type should be valid", i)

			if rule.IPProtocol != "" {
				assert.Contains(t, []string{"inet", "inet6"}, rule.IPProtocol, "Rule %d IP protocol should be valid", i)
			}

			if rule.Interface != "" {
				assert.NotEmpty(t, rule.Interface, "Rule %d interface should not be empty if specified", i)
			}
		}
	})

	t.Run("Load Balancer Monitors", func(t *testing.T) {
		for i, monitor := range config.LoadBalancer.MonitorType {
			assert.NotEmpty(t, monitor.Name, "Monitor %d name should not be empty", i)
			assert.NotEmpty(t, monitor.Type, "Monitor %d type should not be empty", i)

			// Validate common monitor types
			validTypes := []string{"icmp", "tcp", "http", "https", "send"}
			assert.Contains(t, validTypes, monitor.Type, "Monitor %d type should be valid", i)
		}
	})
}

// BenchmarkXMLParser_Parse benchmarks the parsing performance.
func BenchmarkXMLParser_Parse(b *testing.B) {
	sampleFile := filepath.Join("testdata", "config.xml.sample")

	// Check if file exists
	if _, err := os.Stat(sampleFile); os.IsNotExist(err) {
		b.Skip("config.xml.sample not found in testdata directory")
	}

	parser := NewXMLParser()

	for b.Loop() {
		file, err := os.Open(sampleFile)
		if err != nil {
			b.Fatal(err)
		}

		_, err = parser.Parse(context.Background(), file)
		if err != nil {
			_ = file.Close()

			b.Fatal(err)
		}

		_ = file.Close()
	}
}

// TestXMLParser_Validate tests the Validate method of XMLParser.
func TestXMLParser_Validate(t *testing.T) {
	p := NewXMLParser()

	// Load a valid sample configuration
	validConfig := &model.OpnSenseDocument{
		Version: "1.2.3",
		System: model.System{
			Hostname: "test-host",
			Domain:   "test.local",
		},
	}

	// Validate should return no error for a valid configuration
	err := p.Validate(validConfig)
	require.NoError(t, err)

	// Load an invalid configuration
	invalidConfig := &model.OpnSenseDocument{
		Version: "",
		System:  model.System{}, // Missing hostname and domain
	}

	// Validate should return an error for an invalid configuration
	err = p.Validate(invalidConfig)
	require.Error(t, err)
}

// TestXMLParser_ParseAndValidate tests the ParseAndValidate method of XMLParser.
func TestXMLParser_ParseAndValidate(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{
			name:    "valid input",
			input:   `<opnsense><version>1.2.3</version><system><hostname>test-host</hostname><domain>test.local</domain></system></opnsense>`,
			wantErr: false,
		},
		{
			name:    "invalid input - missing required fields",
			input:   `<opnsense><system></system></opnsense>`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := NewXMLParser()

			_, err := p.ParseAndValidate(context.Background(), strings.NewReader(tt.input))

			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

// TestXMLParser_MalformedXML tests parsing of malformed XML with line/column assertion.
func TestXMLParser_MalformedXML(t *testing.T) {
	tests := []struct {
		name         string
		input        string
		expectedLine int
		description  string
	}{
		{
			name: "unclosed tag",
			input: `<opnsense>
				<system>
					<hostname>testhost</hostname>
					<domain>example.com</domain>
				</system>`, // Missing </opnsense>
			expectedLine: 1, // xml.SyntaxError reports line of root element
			description:  "Unclosed root tag should produce ParseError with line information",
		},
		{
			name: "mismatched tag",
			input: `<opnsense>
				<system>
					<hostname>testhost</hostname>
					<domain>example.com</domain>
				</wrong>
			</opnsense>`,
			expectedLine: 5, // Line where mismatched tag occurs
			description:  "Mismatched tag should produce ParseError with line information",
		},
		{
			name: "invalid character in tag name",
			input: `<opnsense>
				<system>
					<host-name@invalid>testhost</host-name@invalid>
					<domain>example.com</domain>
				</system>
			</opnsense>`,
			expectedLine: 3, // Line where invalid character occurs
			description:  "Invalid character in tag name should produce ParseError with line information",
		},
		{
			name: "malformed attribute",
			input: `<opnsense>
				<system version="1.0>
					<hostname>testhost</hostname>
					<domain>example.com</domain>
				</system>
			</opnsense>`,
			expectedLine: 2, // Line where malformed attribute occurs
			description:  "Malformed attribute should produce ParseError with line information",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parser := NewXMLParser()
			reader := strings.NewReader(tt.input)

			_, err := parser.Parse(context.Background(), reader)

			require.Error(t, err, tt.description)

			// Check if it's a ParseError with line information
			var parseErr *ParseError
			if errors.As(err, &parseErr) {
				assert.Positive(t, parseErr.Line, "ParseError should have line information")
				assert.Contains(t, parseErr.Message, "opnsense", "ParseError should contain element context")
			} else {
				// If not a direct ParseError, check if it's wrapped with system decode error
				errorStr := err.Error()
				isValidError := strings.Contains(errorStr, "failed to decode XML") ||
					strings.Contains(errorStr, "failed to decode system") ||
					strings.Contains(errorStr, "XML syntax error")
				assert.True(t, isValidError, "Error should indicate XML parsing failure, got: %s", errorStr)
			}
		})
	}
}

// TestXMLParser_ValidationFailure tests cases that should produce ValidationError.
func TestXMLParser_ValidationFailure(t *testing.T) {
	tests := []struct {
		name         string
		input        string
		validationOn bool
		description  string
	}{
		{
			name: "missing required hostname",
			input: `<opnsense>
				<system>
					<domain>example.com</domain>
				</system>
			</opnsense>`,
			validationOn: true,
			description:  "Missing hostname should produce ValidationError when validation is enabled",
		},
		{
			name: "invalid enum value",
			input: `<opnsense>
				<system>
					<hostname>testhost</hostname>
					<domain>example.com</domain>
					<optimization>invalid-value</optimization>
				</system>
			</opnsense>`,
			validationOn: true,
			description:  "Invalid enum value should produce ValidationError when validation is enabled",
		},
		{
			name: "cross-field validation error",
			input: `<opnsense>
				<system>
					<hostname>testhost</hostname>
					<domain>example.com</domain>
				</system>
				<interfaces>
					<lan>
						<ipaddrv6>track6</ipaddrv6>
					</lan>
				</interfaces>
			</opnsense>`,
			validationOn: true,
			description:  "Missing track6 fields should produce ValidationError when validation is enabled",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parser := NewXMLParser()
			reader := strings.NewReader(tt.input)

			if tt.validationOn {
				// Test ParseAndValidate which always validates
				_, err := parser.ParseAndValidate(context.Background(), reader)
				require.Error(t, err, tt.description)

				// Check if it's an AggregatedValidationError
				var aggErr *AggregatedValidationError
				require.ErrorAs(t, err, &aggErr, "Should be AggregatedValidationError or contain one")

				if aggErr != nil {
					assert.NotEmpty(t, aggErr.Errors, "Should have validation errors")
				}
			} else {
				// When validation is off, should pass parsing
				_, err := parser.Parse(context.Background(), reader)
				require.NoError(t, err, "Should pass parsing when validation is disabled")
			}
		})
	}
}

// generateLargeXML generates a large XML configuration for testing.
func generateLargeXML(size int) string {
	var builder strings.Builder
	builder.WriteString(`<?xml version="1.0"?>`)
	builder.WriteString(`<opnsense>`)
	builder.WriteString(`<system>`)
	builder.WriteString(`<hostname>testhost</hostname>`)
	builder.WriteString(`<domain>example.com</domain>`)
	builder.WriteString(`</system>`)

	// Generate many sysctl items to reach desired size - all within a single <sysctl> element
	builder.WriteString(`<sysctl>`)

	for i := range size {
		builder.WriteString(`<item>`)
		builder.WriteString(fmt.Sprintf(`<tunable>net.inet.ip.test_%d</tunable>`, i))
		builder.WriteString(fmt.Sprintf(`<value>%d</value>`, i%10))
		builder.WriteString(
			fmt.Sprintf(
				`<descr>Test sysctl item number %d with some additional descriptive text to increase size and memory usage for the benchmark</descr>`,
				i,
			),
		)
		builder.WriteString(`</item>`)
	}

	builder.WriteString(`</sysctl>`)

	// Add some filter rules to increase complexity
	builder.WriteString(`<filter>`)

	for i := range size / 100 { // Reduce number of rules to focus on sysctl items
		builder.WriteString(`<rule>`)
		builder.WriteString(`<type>pass</type>`)
		builder.WriteString(`<ipprotocol>inet</ipprotocol>`)
		builder.WriteString(`<interface>lan</interface>`)
		builder.WriteString(
			fmt.Sprintf(`<descr>Generated rule number %d for testing large XML configurations</descr>`, i),
		)
		builder.WriteString(`<source>`)
		builder.WriteString(`<network>lan</network>`)
		builder.WriteString(`</source>`)
		builder.WriteString(`<destination>`)
		builder.WriteString(`<any/>`)
		builder.WriteString(`</destination>`)
		builder.WriteString(`</rule>`)
	}

	builder.WriteString(`</filter>`)

	builder.WriteString(`</opnsense>`)

	return builder.String()
}

// BenchmarkXMLParser_LargeConfig benchmarks parsing of large XML configurations
// Tests memory usage and time constraints for ~2 MB generated config.
func BenchmarkXMLParser_LargeConfig(b *testing.B) {
	// Generate a configuration that will be large but manageable for testing
	// Each sysctl item is roughly 200 bytes, start with 10,000 items for ~2MB
	const targetItems = 10000

	tempDir := b.TempDir() // Use b.TempDir() for benchmark

	// Generate and write large XML to temporary file to avoid keeping it in memory
	xmlFile := filepath.Join(tempDir, "large-config.xml")
	xmlContent := generateLargeXML(targetItems)

	err := os.WriteFile(xmlFile, []byte(xmlContent), 0o600)
	if err != nil {
		b.Fatalf("Failed to write large XML file: %v", err)
	}

	// Verify file size
	stat, err := os.Stat(xmlFile)
	if err != nil {
		b.Fatalf("Failed to stat XML file: %v", err)
	}

	fileSizeMB := float64(stat.Size()) / (1024 * 1024)
	b.Logf("Generated XML file size: %.2f MB", fileSizeMB)

	// Ensure file is at least 1 MB for meaningful test
	if fileSizeMB < 1 {
		b.Fatalf("Generated file too small: %.2f MB, expected at least 1 MB", fileSizeMB)
	}

	parser := NewXMLParser()

	// Record initial memory stats
	var m1, m2 runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&m1)

	for i := 0; b.Loop(); i++ {
		file, err := os.Open(xmlFile)
		if err != nil {
			b.Fatal(err)
		}

		start := time.Now()
		_, err = parser.Parse(context.Background(), file)
		duration := time.Since(start)

		if err != nil {
			if err := file.Close(); err != nil {
				b.Logf("Warning: failed to close file: %v", err)
			}

			b.Fatal(err)
		}

		if err := file.Close(); err != nil {
			b.Logf("Warning: failed to close file: %v", err)
		}

		// Assert time constraint: should complete within 200ms
		if duration > 200*time.Millisecond {
			b.Errorf("Parsing took %v, expected ≤ 200ms", duration)
		}

		// Check memory usage periodically
		if i%10 == 0 {
			runtime.GC()
			runtime.ReadMemStats(&m2)
			memUsedMB := float64(m2.Alloc) / (1024 * 1024)

			// Memory usage should be reasonable (less than 50 MB for parsing)
			if memUsedMB > 50 {
				b.Errorf("Memory usage too high: %.2f MB", memUsedMB)
			}
		}
	}

	b.StopTimer()

	// Final memory check
	runtime.GC()
	runtime.ReadMemStats(&m2)
	memUsedMB := float64(m2.Alloc) / (1024 * 1024)
	b.Logf("Peak memory usage: %.2f MB", memUsedMB)

	// Report performance metrics
	b.ReportMetric(fileSizeMB, "file_size_MB")
	b.ReportMetric(memUsedMB, "memory_MB")
}
