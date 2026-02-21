package audit

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/compliance"
	"github.com/EvilBit-Labs/opnDossier/internal/model/common"
)

// TestGlobalPluginRegistry tests all global registry functions.
//

func TestGlobalPluginRegistry(t *testing.T) {
	// Reset global registry for clean testing
	globalRegistryOnce = sync.Once{}
	globalRegistry = nil

	t.Run("GetGlobalRegistry", func(t *testing.T) {
		registry1 := GetGlobalRegistry()
		if registry1 == nil {
			t.Error("GetGlobalRegistry() returned nil")
		}

		registry2 := GetGlobalRegistry()
		if registry1 != registry2 {
			t.Error("GetGlobalRegistry() should return same instance (singleton)")
		}
	})

	t.Run("RegisterGlobalPlugin", func(t *testing.T) {
		// Reset for this test
		globalRegistryOnce = sync.Once{}
		globalRegistry = nil

		mockPlugin := &mockCompliancePlugin{
			name:        "global-test-plugin",
			description: "Test plugin for global registry",
			version:     "1.0.0",
		}

		err := RegisterGlobalPlugin(mockPlugin)
		if err != nil {
			t.Errorf("RegisterGlobalPlugin() error = %v", err)
		}

		// Try to register the same plugin again (should fail)
		err = RegisterGlobalPlugin(mockPlugin)
		if err == nil {
			t.Error("RegisterGlobalPlugin() should fail when registering duplicate plugin")
		}
	})

	t.Run("GetGlobalPlugin", func(t *testing.T) {
		// Reset for this test
		globalRegistryOnce = sync.Once{}
		globalRegistry = nil

		mockPlugin := &mockCompliancePlugin{
			name:        "global-get-plugin",
			description: "Test plugin for global get",
			version:     "1.0.0",
		}

		// Register plugin first
		err := RegisterGlobalPlugin(mockPlugin)
		if err != nil {
			t.Fatalf("Failed to register global plugin: %v", err)
		}

		// Get the plugin
		retrievedPlugin, err := GetGlobalPlugin("global-get-plugin")
		if err != nil {
			t.Errorf("GetGlobalPlugin() error = %v", err)
		}

		if retrievedPlugin == nil {
			t.Error("GetGlobalPlugin() returned nil plugin")
		}

		if retrievedPlugin != nil && retrievedPlugin.Name() != mockPlugin.name {
			t.Errorf("GetGlobalPlugin() name = %v, want %v", retrievedPlugin.Name(), mockPlugin.name)
		}

		// Try to get nonexistent plugin
		_, err = GetGlobalPlugin("nonexistent")
		if err == nil {
			t.Error("GetGlobalPlugin() should return error for nonexistent plugin")
		}
	})

	t.Run("ListGlobalPlugins", func(t *testing.T) {
		// Reset for this test
		globalRegistryOnce = sync.Once{}
		globalRegistry = nil

		// Test with empty registry
		plugins := ListGlobalPlugins()
		if plugins == nil {
			t.Error("ListGlobalPlugins() returned nil")
		}
		if len(plugins) != 0 {
			t.Errorf("ListGlobalPlugins() returned %d plugins, expected 0 for empty registry", len(plugins))
		}

		// Register some plugins
		plugins1 := &mockCompliancePlugin{
			name:        "global-list-plugin-1",
			description: "First plugin for global list",
			version:     "1.0.0",
		}
		plugins2 := &mockCompliancePlugin{
			name:        "global-list-plugin-2",
			description: "Second plugin for global list",
			version:     "1.0.0",
		}

		err := RegisterGlobalPlugin(plugins1)
		if err != nil {
			t.Fatalf("Failed to register first global plugin: %v", err)
		}

		err = RegisterGlobalPlugin(plugins2)
		if err != nil {
			t.Fatalf("Failed to register second global plugin: %v", err)
		}

		// List plugins
		pluginList := ListGlobalPlugins()
		if pluginList == nil {
			t.Error("ListGlobalPlugins() returned nil")
		}

		if len(pluginList) != 2 {
			t.Errorf("ListGlobalPlugins() returned %d plugins, expected 2", len(pluginList))
		}

		// Verify both plugins are in the list
		pluginMap := make(map[string]bool)
		for _, name := range pluginList {
			pluginMap[name] = true
		}

		if !pluginMap["global-list-plugin-1"] {
			t.Error("ListGlobalPlugins() missing first plugin")
		}
		if !pluginMap["global-list-plugin-2"] {
			t.Error("ListGlobalPlugins() missing second plugin")
		}
	})
}

// TestLoadDynamicPlugins tests the LoadDynamicPlugins functionality.
func TestLoadDynamicPlugins(t *testing.T) {
	t.Parallel()

	registry := NewPluginRegistry()
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	ctx := context.Background()

	tests := []struct {
		name    string
		dir     string
		wantErr bool
	}{
		{
			name:    "nonexistent directory",
			dir:     "/nonexistent/path/to/plugins",
			wantErr: false, // Should not error, just log and continue
		},
		{
			name:    "empty directory",
			dir:     t.TempDir(),
			wantErr: false,
		},
		{
			name:    "directory with non-.so files",
			dir:     createTestDirWithNonSOFiles(t),
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := registry.LoadDynamicPlugins(ctx, tt.dir, logger)
			if (err != nil) != tt.wantErr {
				t.Errorf("LoadDynamicPlugins() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestPluginRegistry_CalculateSummary tests the calculateSummary method with various scenarios.
func TestPluginRegistry_CalculateSummary(t *testing.T) {
	t.Parallel()

	registry := NewPluginRegistry()

	tests := []struct {
		name                  string
		result                *ComplianceResult
		expectedTotalCount    int
		expectedCriticalCount int
		expectedHighCount     int
		expectedMediumCount   int
		expectedLowCount      int
	}{
		{
			name: "empty result",
			result: &ComplianceResult{
				Findings:   []compliance.Finding{},
				Compliance: make(map[string]map[string]bool),
				PluginInfo: make(map[string]PluginInfo),
			},
			expectedTotalCount:    0,
			expectedCriticalCount: 0,
			expectedHighCount:     0,
			expectedMediumCount:   0,
			expectedLowCount:      0,
		},
		{
			name: "mixed severity findings",
			result: &ComplianceResult{
				Findings: []compliance.Finding{
					{Type: "critical", Title: "Critical Issue", Description: "Critical security issue"},
					{Type: "high", Title: "High Issue", Description: "High severity issue"},
					{Type: "medium", Title: "Medium Issue", Description: "Medium severity issue"},
					{Type: "low", Title: "Low Issue", Description: "Low severity issue"},
					{Type: "critical", Title: "Another Critical", Description: "Another critical issue"},
				},
				Compliance: map[string]map[string]bool{
					"test-plugin": {
						"CONTROL-001": true,
						"CONTROL-002": false,
					},
				},
				PluginInfo: map[string]PluginInfo{
					"test-plugin": {
						Name:        "Test Plugin",
						Version:     "1.0.0",
						Description: "Test plugin",
						Controls:    []compliance.Control{},
					},
				},
			},
			expectedTotalCount:    5,
			expectedCriticalCount: 2,
			expectedHighCount:     1,
			expectedMediumCount:   1,
			expectedLowCount:      1,
		},
		{
			name: "unknown severity types",
			result: &ComplianceResult{
				Findings: []compliance.Finding{
					{Type: "unknown", Title: "Unknown Issue", Description: "Unknown severity"},
					{Type: "info", Title: "Info Issue", Description: "Info level"},
					{Type: "", Title: "Empty Type", Description: "Empty severity type"},
				},
				Compliance: make(map[string]map[string]bool),
				PluginInfo: make(map[string]PluginInfo),
			},
			expectedTotalCount:    3,
			expectedCriticalCount: 0,
			expectedHighCount:     0,
			expectedMediumCount:   0,
			expectedLowCount:      0,
		},
		{
			name: "compliance calculations",
			result: &ComplianceResult{
				Findings: []compliance.Finding{},
				Compliance: map[string]map[string]bool{
					"plugin1": {
						"CONTROL-001": true,
						"CONTROL-002": true,
						"CONTROL-003": false,
					},
					"plugin2": {
						"CONTROL-001": false,
						"CONTROL-002": false,
					},
				},
				PluginInfo: map[string]PluginInfo{
					"plugin1": {
						Name:        "Plugin 1",
						Version:     "1.0.0",
						Description: "First plugin",
						Controls:    []compliance.Control{},
					},
					"plugin2": {
						Name:        "Plugin 2",
						Version:     "1.0.0",
						Description: "Second plugin",
						Controls:    []compliance.Control{},
					},
				},
			},
			expectedTotalCount:    0,
			expectedCriticalCount: 0,
			expectedHighCount:     0,
			expectedMediumCount:   0,
			expectedLowCount:      0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			summary := registry.calculateSummary(tt.result)
			if summary == nil {
				t.Error("calculateSummary() returned nil")
				return
			}

			if summary.TotalFindings != tt.expectedTotalCount {
				t.Errorf("calculateSummary() TotalFindings = %v, want %v", summary.TotalFindings, tt.expectedTotalCount)
			}

			if summary.CriticalFindings != tt.expectedCriticalCount {
				t.Errorf(
					"calculateSummary() CriticalFindings = %v, want %v",
					summary.CriticalFindings,
					tt.expectedCriticalCount,
				)
			}

			if summary.HighFindings != tt.expectedHighCount {
				t.Errorf("calculateSummary() HighFindings = %v, want %v", summary.HighFindings, tt.expectedHighCount)
			}

			if summary.MediumFindings != tt.expectedMediumCount {
				t.Errorf(
					"calculateSummary() MediumFindings = %v, want %v",
					summary.MediumFindings,
					tt.expectedMediumCount,
				)
			}

			if summary.LowFindings != tt.expectedLowCount {
				t.Errorf("calculateSummary() LowFindings = %v, want %v", summary.LowFindings, tt.expectedLowCount)
			}

			if summary.PluginCount != len(tt.result.PluginInfo) {
				t.Errorf("calculateSummary() PluginCount = %v, want %v", summary.PluginCount, len(tt.result.PluginInfo))
			}

			// Test compliance calculations
			if tt.name == "compliance calculations" {
				plugin1Compliance, exists := summary.Compliance["plugin1"]
				if !exists {
					t.Error("calculateSummary() missing compliance for plugin1")
				} else {
					if plugin1Compliance.Compliant != 2 {
						t.Errorf("calculateSummary() plugin1 compliant = %v, want 2", plugin1Compliance.Compliant)
					}
					if plugin1Compliance.NonCompliant != 1 {
						t.Errorf(
							"calculateSummary() plugin1 non-compliant = %v, want 1",
							plugin1Compliance.NonCompliant,
						)
					}
					if plugin1Compliance.Total != 3 {
						t.Errorf("calculateSummary() plugin1 total = %v, want 3", plugin1Compliance.Total)
					}
				}

				plugin2Compliance, exists := summary.Compliance["plugin2"]
				if !exists {
					t.Error("calculateSummary() missing compliance for plugin2")
				} else {
					if plugin2Compliance.Compliant != 0 {
						t.Errorf("calculateSummary() plugin2 compliant = %v, want 0", plugin2Compliance.Compliant)
					}
					if plugin2Compliance.NonCompliant != 2 {
						t.Errorf(
							"calculateSummary() plugin2 non-compliant = %v, want 2",
							plugin2Compliance.NonCompliant,
						)
					}
					if plugin2Compliance.Total != 2 {
						t.Errorf("calculateSummary() plugin2 total = %v, want 2", plugin2Compliance.Total)
					}
				}
			}
		})
	}
}

// TestPluginRegistry_RegisterPlugin_ValidationFailure tests plugin registration with validation failure.
func TestPluginRegistry_RegisterPlugin_ValidationFailure(t *testing.T) {
	t.Parallel()

	registry := NewPluginRegistry()

	failingPlugin := &mockFailingPlugin{
		mockCompliancePlugin: mockCompliancePlugin{
			name:        "failing-plugin",
			description: "A plugin that fails validation",
			version:     "1.0.0",
		},
		shouldFailValidation: true,
	}

	err := registry.RegisterPlugin(failingPlugin)
	if err == nil {
		t.Error("RegisterPlugin() should fail when plugin validation fails")
	}

	// Verify plugin was not registered
	_, err = registry.GetPlugin("failing-plugin")
	if err == nil {
		t.Error("Plugin should not be registered after validation failure")
	}
}

// TestRunComplianceChecks_WithFindingsAndReferences tests compliance checks with complex findings.
func TestRunComplianceChecks_WithFindingsAndReferences(t *testing.T) {
	t.Parallel()

	registry := NewPluginRegistry()

	// Create a mock plugin that returns findings with references
	mockPlugin := &mockPluginWithFindings{
		mockCompliancePlugin: mockCompliancePlugin{
			name:        "test-plugin-findings",
			description: "Test plugin with findings",
			version:     "1.0.0",
		},
		findings: []compliance.Finding{
			{
				Type:           "high",
				Title:          "Security Issue",
				Description:    "A security issue was found",
				Recommendation: "Fix the issue",
				References:     []string{"CONTROL-001", "CONTROL-002"},
			},
		},
		controls: []compliance.Control{
			{ID: "CONTROL-001", Title: "Control 1", Severity: "high"},
			{ID: "CONTROL-002", Title: "Control 2", Severity: "medium"},
			{ID: "CONTROL-003", Title: "Control 3", Severity: "low"},
		},
	}

	err := registry.RegisterPlugin(mockPlugin)
	if err != nil {
		t.Fatalf("Failed to register plugin: %v", err)
	}

	testConfig := &common.CommonDevice{
		System: common.System{
			Hostname: "test-host",
		},
	}

	result, err := registry.RunComplianceChecks(testConfig, []string{"test-plugin-findings"})
	if err != nil {
		t.Errorf("RunComplianceChecks() error = %v", err)
	}

	if result == nil {
		t.Error("RunComplianceChecks() returned nil result")
		return
	}

	if len(result.Findings) != 1 {
		t.Errorf("RunComplianceChecks() findings count = %v, want 1", len(result.Findings))
	}

	// Verify compliance status was updated based on findings
	pluginCompliance := result.Compliance["test-plugin-findings"]
	if pluginCompliance == nil {
		t.Error("RunComplianceChecks() missing compliance for plugin")
		return
	}

	// Controls referenced in findings should be marked as non-compliant
	if pluginCompliance["CONTROL-001"] != false {
		t.Error("RunComplianceChecks() CONTROL-001 should be non-compliant")
	}
	if pluginCompliance["CONTROL-002"] != false {
		t.Error("RunComplianceChecks() CONTROL-002 should be non-compliant")
	}
	// Control not referenced should remain compliant
	if pluginCompliance["CONTROL-003"] != true {
		t.Error("RunComplianceChecks() CONTROL-003 should be compliant")
	}
}

// createTestDirWithNonSOFiles creates a temporary directory with non-.so files for testing.
func createTestDirWithNonSOFiles(t *testing.T) string {
	t.Helper()

	dir := t.TempDir()

	// Create some non-.so files
	files := []string{"test.txt", "plugin.dll", "plugin.dylib", "readme.md"}
	for _, file := range files {
		filePath := filepath.Join(dir, file)
		err := os.WriteFile(filePath, []byte("test content"), 0o600)
		if err != nil {
			t.Fatalf("Failed to create test file %s: %v", file, err)
		}
	}

	return dir
}

// mockPluginWithFindings is a mock plugin that returns specific findings and controls.
type mockPluginWithFindings struct {
	mockCompliancePlugin

	findings []compliance.Finding
	controls []compliance.Control
}

func (m *mockPluginWithFindings) RunChecks(_ *common.CommonDevice) []compliance.Finding {
	return m.findings
}

func (m *mockPluginWithFindings) GetControls() []compliance.Control {
	return m.controls
}

func (m *mockPluginWithFindings) GetControlByID(id string) (*compliance.Control, error) {
	for i := range m.controls {
		if m.controls[i].ID == id {
			return &m.controls[i], nil
		}
	}
	return nil, compliance.ErrControlNotFound
}
