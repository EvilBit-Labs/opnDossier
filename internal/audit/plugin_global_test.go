package audit

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/compliance"
	"github.com/EvilBit-Labs/opnDossier/internal/constants"
	"github.com/EvilBit-Labs/opnDossier/internal/logging"
	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
)

// TestGlobalPluginRegistry tests all global registry functions.
func TestGlobalPluginRegistry(t *testing.T) {
	// Save and restore global state. We capture both the registry pointer
	// and whether the singleton was already initialized so cleanup can
	// faithfully restore the original state.
	origRegistry := globalRegistry
	origInitialized := globalRegistry != nil

	t.Cleanup(func() {
		globalRegistry = origRegistry
		if origInitialized {
			// Mark the Once as already executed by running a no-op Do.
			// We reset first, then immediately fire Do so subsequent
			// GetGlobalRegistry() calls return the saved pointer.
			globalRegistryOnce = sync.Once{}
			globalRegistryOnce.Do(func() {})
		} else {
			globalRegistryOnce = sync.Once{}
		}
	})

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
	logger := newTestLogger(t)
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
					{
						Type:        "compliance",
						Severity:    "critical",
						Title:       "Critical Issue",
						Description: "Critical security issue",
					},
					{Type: "compliance", Severity: "high", Title: "High Issue", Description: "High severity issue"},
					{
						Type:        "compliance",
						Severity:    "medium",
						Title:       "Medium Issue",
						Description: "Medium severity issue",
					},
					{Type: "compliance", Severity: "low", Title: "Low Issue", Description: "Low severity issue"},
					{
						Type:        "compliance",
						Severity:    "critical",
						Title:       "Another Critical",
						Description: "Another critical issue",
					},
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
					{Type: "compliance", Severity: "unknown", Title: "Unknown Issue", Description: "Unknown severity"},
					{Type: "compliance", Severity: "info", Title: "Info Issue", Description: "Info level"},
					{Type: "compliance", Severity: "", Title: "Empty Type", Description: "Empty severity type"},
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
				Type:           "compliance",
				Severity:       "high",
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

	result, err := registry.RunComplianceChecks(testConfig, []string{"test-plugin-findings"}, newTestLogger(t))
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

// TestRunComplianceChecks_MissingSeverityDerivation tests that findings without Severity
// are normalized by deriving severity from the plugin's control metadata.
func TestRunComplianceChecks_MissingSeverityDerivation(t *testing.T) {
	t.Parallel()

	registry := NewPluginRegistry()

	// Plugin with controls that have severity, but findings lack Severity
	mockPlugin := &mockPluginWithFindings{
		mockCompliancePlugin: mockCompliancePlugin{
			name:        "test-missing-severity",
			description: "Plugin returning findings without Severity",
			version:     "1.0.0",
		},
		findings: []compliance.Finding{
			{
				Type:           "compliance",
				Title:          "Finding Without Severity",
				Description:    "This finding has no severity set",
				Recommendation: "Fix it",
				Reference:      "CONTROL-001",
				References:     []string{"CONTROL-001"},
			},
			{
				Type:           "compliance",
				Title:          "Finding With Severity Already Set",
				Description:    "This finding already has severity",
				Severity:       "low",
				Recommendation: "Fix it",
				Reference:      "CONTROL-002",
				References:     []string{"CONTROL-002"},
			},
		},
		controls: []compliance.Control{
			{ID: "CONTROL-001", Title: "Control 1", Severity: severityCritical},
			{ID: "CONTROL-002", Title: "Control 2", Severity: "medium"},
		},
	}

	err := registry.RegisterPlugin(mockPlugin)
	if err != nil {
		t.Fatalf("Failed to register plugin: %v", err)
	}

	testConfig := &common.CommonDevice{
		System: common.System{Hostname: "test-host"},
	}

	result, err := registry.RunComplianceChecks(testConfig, []string{"test-missing-severity"}, newTestLogger(t))
	if err != nil {
		t.Fatalf("RunComplianceChecks() error = %v", err)
	}

	if len(result.Findings) != 2 {
		t.Fatalf("Expected 2 findings, got %d", len(result.Findings))
	}

	// Finding without severity should be derived from control metadata
	if result.Findings[0].Severity != severityCritical {
		t.Errorf("Expected derived severity 'critical', got %q", result.Findings[0].Severity)
	}

	// Finding with severity already set should be unchanged
	if result.Findings[1].Severity != "low" {
		t.Errorf("Expected existing severity 'low', got %q", result.Findings[1].Severity)
	}

	// Summary should reflect the derived severity
	if result.Summary.CriticalFindings != 1 {
		t.Errorf("Expected 1 critical finding, got %d", result.Summary.CriticalFindings)
	}
	if result.Summary.LowFindings != 1 {
		t.Errorf("Expected 1 low finding, got %d", result.Summary.LowFindings)
	}
}

// TestRunComplianceChecks_MissingSeverityNoMatchingControl tests that findings without
// Severity and no matching control cause RunComplianceChecks to return an error.
func TestRunComplianceChecks_MissingSeverityNoMatchingControl(t *testing.T) {
	t.Parallel()

	registry := NewPluginRegistry()

	mockPlugin := &mockPluginWithFindings{
		mockCompliancePlugin: mockCompliancePlugin{
			name:        "test-no-control-match",
			description: "Plugin with unresolvable severity",
			version:     "1.0.0",
		},
		findings: []compliance.Finding{
			{
				Type:           "compliance",
				Title:          "Orphan Finding",
				Description:    "No matching control exists",
				Recommendation: "Fix it",
				Reference:      "NONEXISTENT-001",
				References:     []string{"NONEXISTENT-001"},
			},
		},
		controls: []compliance.Control{
			{ID: "CONTROL-001", Title: "Control 1", Severity: "high"},
		},
	}

	err := registry.RegisterPlugin(mockPlugin)
	if err != nil {
		t.Fatalf("Failed to register plugin: %v", err)
	}

	testConfig := &common.CommonDevice{
		System: common.System{Hostname: "test-host"},
	}

	result, err := registry.RunComplianceChecks(testConfig, []string{"test-no-control-match"}, newTestLogger(t))
	if err == nil {
		t.Fatal("RunComplianceChecks() should return error for orphan finding with unresolvable severity")
	}

	if result != nil {
		t.Error("RunComplianceChecks() should return nil result on error")
	}

	// Error should identify the plugin and the unresolved reference
	errMsg := err.Error()
	if !strings.Contains(errMsg, "test-no-control-match") {
		t.Errorf("Error should identify plugin name, got: %s", errMsg)
	}
	if !strings.Contains(errMsg, "NONEXISTENT-001") {
		t.Errorf("Error should identify unresolved control reference, got: %s", errMsg)
	}
}

// TestDeriveSeverityFromControl tests the deriveSeverityFromControl helper directly.
func TestDeriveSeverityFromControl(t *testing.T) {
	t.Parallel()

	mockPlugin := &mockPluginWithFindings{
		mockCompliancePlugin: mockCompliancePlugin{
			name:    "derive-test",
			version: "1.0.0",
		},
		controls: []compliance.Control{
			{ID: "CTRL-001", Severity: severityCritical},
			{ID: "CTRL-002", Severity: "high"},
		},
	}

	t.Run("derives from References", func(t *testing.T) {
		t.Parallel()

		result, err := deriveSeverityFromControl(mockPlugin, compliance.Finding{
			References: []string{"CTRL-001"},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result != severityCritical {
			t.Errorf("deriveSeverityFromControl() = %q, want %q", result, severityCritical)
		}
	})

	t.Run("derives from Reference fallback", func(t *testing.T) {
		t.Parallel()

		result, err := deriveSeverityFromControl(mockPlugin, compliance.Finding{
			Reference: "CTRL-002",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result != "high" {
			t.Errorf("deriveSeverityFromControl() = %q, want %q", result, "high")
		}
	})

	t.Run("References takes priority over Reference", func(t *testing.T) {
		t.Parallel()

		result, err := deriveSeverityFromControl(mockPlugin, compliance.Finding{
			References: []string{"CTRL-001"},
			Reference:  "CTRL-002",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result != severityCritical {
			t.Errorf("deriveSeverityFromControl() = %q, want %q", result, severityCritical)
		}
	})

	t.Run("no matching control returns error", func(t *testing.T) {
		t.Parallel()

		_, err := deriveSeverityFromControl(mockPlugin, compliance.Finding{
			Title:      "Bad Finding",
			References: []string{"NONEXISTENT"},
			Reference:  "ALSO-NONEXISTENT",
		})
		if err == nil {
			t.Fatal("expected error for unresolvable control references")
		}
		if !strings.Contains(err.Error(), "NONEXISTENT") {
			t.Errorf("error should mention unresolved reference, got: %v", err)
		}
	})

	t.Run("empty references returns error", func(t *testing.T) {
		t.Parallel()

		_, err := deriveSeverityFromControl(mockPlugin, compliance.Finding{
			Title: "No Refs Finding",
		})
		if err == nil {
			t.Fatal("expected error for finding with no control references")
		}
	})
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

// mockPanickingPlugin is a mock plugin whose RunChecks method always panics.
type mockPanickingPlugin struct {
	mockCompliancePlugin

	controls []compliance.Control
}

// RunChecks panics unconditionally to simulate a misbehaving plugin.
func (m *mockPanickingPlugin) RunChecks(_ *common.CommonDevice) []compliance.Finding {
	panic("test panic")
}

// GetControls returns the controls configured on the mock.
func (m *mockPanickingPlugin) GetControls() []compliance.Control {
	return m.controls
}

// GetControlByID returns the control matching the given ID.
func (m *mockPanickingPlugin) GetControlByID(id string) (*compliance.Control, error) {
	for i := range m.controls {
		if m.controls[i].ID == id {
			return &m.controls[i], nil
		}
	}
	return nil, compliance.ErrControlNotFound
}

// TestRunComplianceChecks_PanickingPluginIsolation verifies that a panicking
// plugin is caught and retained with zero findings without affecting other plugins.
func TestRunComplianceChecks_PanickingPluginIsolation(t *testing.T) {
	t.Parallel()

	logger := newTestLogger(t)

	panickingPlugin := &mockPanickingPlugin{
		mockCompliancePlugin: mockCompliancePlugin{
			name:        "panicking-plugin",
			version:     "0.0.1",
			description: "Plugin that panics",
		},
		controls: []compliance.Control{
			{ID: "PANIC-001", Title: "Panic Control", Severity: "high"},
		},
	}

	healthyPlugin := &mockPluginWithFindings{
		mockCompliancePlugin: mockCompliancePlugin{
			name:        "healthy-plugin",
			version:     "1.0.0",
			description: "Plugin that works",
		},
		controls: []compliance.Control{
			{ID: "HEALTHY-001", Title: "Healthy Control", Severity: "medium"},
		},
		findings: []compliance.Finding{
			{
				Type:           "compliance",
				Severity:       "medium",
				Title:          "Healthy Finding",
				Description:    "A real finding",
				Recommendation: "Fix it",
				References:     []string{"HEALTHY-001"},
			},
		},
	}

	tests := []struct {
		name                string
		plugins             []compliance.Plugin
		selectedPlugins     []string
		wantFindingsCount   int
		wantPluginInfoCount int
	}{
		{
			name:                "panicking plugin only",
			plugins:             []compliance.Plugin{panickingPlugin},
			selectedPlugins:     []string{"panicking-plugin"},
			wantFindingsCount:   0,
			wantPluginInfoCount: 1,
		},
		{
			name:                "panicking plugin with healthy plugin",
			plugins:             []compliance.Plugin{panickingPlugin, healthyPlugin},
			selectedPlugins:     []string{"panicking-plugin", "healthy-plugin"},
			wantFindingsCount:   1,
			wantPluginInfoCount: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			registry := NewPluginRegistry()
			for _, p := range tt.plugins {
				if err := registry.RegisterPlugin(p); err != nil {
					t.Fatalf("Failed to register plugin %q: %v", p.Name(), err)
				}
			}

			device := &common.CommonDevice{
				System: common.System{Hostname: "test-host"},
			}

			result, err := registry.RunComplianceChecks(device, tt.selectedPlugins, logger)
			if err != nil {
				t.Fatalf("RunComplianceChecks() unexpected error: %v", err)
			}

			if result == nil {
				t.Fatal("RunComplianceChecks() returned nil result")
			}

			if len(result.Findings) != tt.wantFindingsCount {
				t.Errorf("Findings count = %d, want %d", len(result.Findings), tt.wantFindingsCount)
			}

			if len(result.PluginInfo) != tt.wantPluginInfoCount {
				t.Errorf("PluginInfo count = %d, want %d", len(result.PluginInfo), tt.wantPluginInfoCount)
			}

			if result.Summary.TotalFindings != tt.wantFindingsCount {
				t.Errorf("Summary.TotalFindings = %d, want %d", result.Summary.TotalFindings, tt.wantFindingsCount)
			}

			// Panicking plugin must be present in PluginFindings with zero findings
			pf, ok := result.PluginFindings["panicking-plugin"]
			if !ok {
				t.Error("Panicking plugin should be present in PluginFindings")
			} else if len(pf) > 0 {
				t.Errorf("Panicking plugin should have no findings, got %d", len(pf))
			}

			// Panicking plugin must be present in PluginInfo
			if _, ok := result.PluginInfo["panicking-plugin"]; !ok {
				t.Error("Panicking plugin should be present in PluginInfo")
			}

			// Panicking plugin must be present in Compliance map
			if _, ok := result.Compliance["panicking-plugin"]; !ok {
				t.Error("Panicking plugin should be present in Compliance map")
			}
		})
	}

	// Verify healthy plugin findings are preserved when a sibling panics
	t.Run("healthy plugin findings preserved alongside panic", func(t *testing.T) {
		t.Parallel()

		registry := NewPluginRegistry()
		if err := registry.RegisterPlugin(panickingPlugin); err != nil {
			t.Fatalf("Failed to register panicking plugin: %v", err)
		}

		if err := registry.RegisterPlugin(healthyPlugin); err != nil {
			t.Fatalf("Failed to register healthy plugin: %v", err)
		}

		device := &common.CommonDevice{
			System: common.System{Hostname: "test-host"},
		}

		result, err := registry.RunComplianceChecks(
			device,
			[]string{"panicking-plugin", "healthy-plugin"},
			logger,
		)
		if err != nil {
			t.Fatalf("RunComplianceChecks() unexpected error: %v", err)
		}

		hf, ok := result.PluginFindings["healthy-plugin"]
		if !ok {
			t.Fatal("healthy-plugin should be present in PluginFindings")
		}

		if len(hf) != 1 {
			t.Errorf("healthy-plugin findings count = %d, want 1", len(hf))
		}

		if hf[0].Title != "Healthy Finding" {
			t.Errorf("healthy-plugin finding title = %q, want %q", hf[0].Title, "Healthy Finding")
		}
	})
}

// TestRunComplianceChecks_NilLoggerFallback verifies that passing a nil logger
// to RunComplianceChecks creates a fallback logger and completes without error,
// including when a plugin panics.
func TestRunComplianceChecks_NilLoggerFallback(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name              string
		plugins           []compliance.Plugin
		selectedPlugins   []string
		wantFindingsCount int
	}{
		{
			name: "nil logger with healthy plugin",
			plugins: []compliance.Plugin{
				&mockPluginWithFindings{
					mockCompliancePlugin: mockCompliancePlugin{
						name:        "healthy",
						version:     "1.0.0",
						description: "Healthy plugin",
					},
					controls: []compliance.Control{
						{ID: "H-001", Title: "Control", Severity: "low"},
					},
					findings: []compliance.Finding{
						{
							Type:       "compliance",
							Severity:   "low",
							Title:      "A finding",
							References: []string{"H-001"},
						},
					},
				},
			},
			selectedPlugins:   []string{"healthy"},
			wantFindingsCount: 1,
		},
		{
			name: "nil logger with panicking plugin",
			plugins: []compliance.Plugin{
				&mockPanickingPlugin{
					mockCompliancePlugin: mockCompliancePlugin{
						name:        "panicker",
						version:     "0.1.0",
						description: "Panics",
					},
					controls: []compliance.Control{
						{ID: "P-001", Title: "Control", Severity: "high"},
					},
				},
			},
			selectedPlugins:   []string{"panicker"},
			wantFindingsCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			registry := NewPluginRegistry()
			for _, p := range tt.plugins {
				if err := registry.RegisterPlugin(p); err != nil {
					t.Fatalf("Failed to register plugin %q: %v", p.Name(), err)
				}
			}

			device := &common.CommonDevice{
				System: common.System{Hostname: "test-host"},
			}

			// Pass nil logger — should create fallback without error
			result, err := registry.RunComplianceChecks(device, tt.selectedPlugins, nil)
			if err != nil {
				t.Fatalf("RunComplianceChecks() with nil logger unexpected error: %v", err)
			}

			if result == nil {
				t.Fatal("RunComplianceChecks() returned nil result")
			}

			if len(result.Findings) != tt.wantFindingsCount {
				t.Errorf("Findings count = %d, want %d", len(result.Findings), tt.wantFindingsCount)
			}
		})
	}
}

// TestRunComplianceChecks_PerPluginSeverityArithmetic exercises the full RunComplianceChecks
// pipeline with the real STIG plugin and verifies that severity counts sum correctly.
func TestRunComplianceChecks_PerPluginSeverityArithmetic(t *testing.T) {
	t.Parallel()

	logger, err := logging.New(logging.Config{})
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}

	pm := NewPluginManager(logger)
	ctx := context.Background()

	if err := pm.InitializePlugins(ctx); err != nil {
		t.Fatalf("InitializePlugins() error: %v", err)
	}

	registry := pm.GetRegistry()

	// Build a device that triggers all four STIG findings:
	// - V-206694: any/any pass rule without deny -> missing default deny
	// - V-206674: any/any pass rule -> overly permissive
	// - V-206690: SNMP community string -> unnecessary services
	// - V-206682: no syslog -> insufficient logging
	device := &common.CommonDevice{
		FirewallRules: []common.FirewallRule{
			{
				Type:        "pass",
				Source:      common.RuleEndpoint{Address: constants.NetworkAny},
				Destination: common.RuleEndpoint{Address: constants.NetworkAny},
			},
		},
		SNMP: common.SNMPConfig{
			ROCommunity: "public",
		},
	}

	result, err := registry.RunComplianceChecks(device, []string{"stig"}, newTestLogger(t))
	if err != nil {
		t.Fatalf("RunComplianceChecks() error: %v", err)
	}

	if result == nil {
		t.Fatal("RunComplianceChecks() returned nil result")
	}

	if len(result.Findings) == 0 {
		t.Fatal("RunComplianceChecks() returned zero findings; expected STIG findings")
	}

	// Total findings must be consistent
	if result.Summary.TotalFindings != len(result.Findings) {
		t.Errorf("Summary.TotalFindings = %d, want %d (len of Findings)",
			result.Summary.TotalFindings, len(result.Findings))
	}

	// Severity arithmetic invariant: all severity buckets must sum to TotalFindings
	severitySum := result.Summary.CriticalFindings +
		result.Summary.HighFindings +
		result.Summary.MediumFindings +
		result.Summary.LowFindings
	if severitySum != result.Summary.TotalFindings {
		t.Errorf("Severity sum (%d) != TotalFindings (%d): critical=%d high=%d medium=%d low=%d",
			severitySum, result.Summary.TotalFindings,
			result.Summary.CriticalFindings, result.Summary.HighFindings,
			result.Summary.MediumFindings, result.Summary.LowFindings)
	}

	// STIG controls have "high" and "medium" severities; at least one must be non-zero
	if result.Summary.HighFindings == 0 && result.Summary.MediumFindings == 0 {
		t.Error("Expected at least one high or medium finding from STIG plugin")
	}

	// Per-plugin findings map must match aggregate
	stigFindings, ok := result.PluginFindings["stig"]
	if !ok {
		t.Fatal("PluginFindings missing 'stig' entry")
	}

	if len(stigFindings) != len(result.Findings) {
		t.Errorf("PluginFindings[\"stig\"] length = %d, want %d",
			len(stigFindings), len(result.Findings))
	}

	if result.Summary.PluginCount != 1 {
		t.Errorf("Summary.PluginCount = %d, want 1", result.Summary.PluginCount)
	}
}

// TestDeduplicatePluginNames tests the deduplicatePluginNames helper function.
func TestDeduplicatePluginNames(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    []string
		expected []string
	}{
		{
			name:     "no duplicates",
			input:    []string{"stig", "sans", "firewall"},
			expected: []string{"stig", "sans", "firewall"},
		},
		{
			name:     "adjacent duplicates",
			input:    []string{"stig", "stig"},
			expected: []string{"stig"},
		},
		{
			name:     "non-adjacent duplicates",
			input:    []string{"stig", "sans", "stig"},
			expected: []string{"stig", "sans"},
		},
		{
			name:     "all same",
			input:    []string{"stig", "stig", "stig"},
			expected: []string{"stig"},
		},
		{
			name:     "empty input",
			input:    []string{},
			expected: []string{},
		},
		{
			name:     "nil input",
			input:    nil,
			expected: []string{},
		},
		{
			name:     "single element",
			input:    []string{"stig"},
			expected: []string{"stig"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result := deduplicatePluginNames(tt.input)
			if len(result) != len(tt.expected) {
				t.Fatalf("deduplicatePluginNames() returned %d items, want %d", len(result), len(tt.expected))
			}

			for i, name := range result {
				if name != tt.expected[i] {
					t.Errorf("deduplicatePluginNames()[%d] = %q, want %q", i, name, tt.expected[i])
				}
			}
		})
	}
}

// TestRunComplianceChecks_DuplicatePluginNames tests that duplicate plugin names
// are handled gracefully by RunComplianceChecks (defense-in-depth deduplication).
func TestRunComplianceChecks_DuplicatePluginNames(t *testing.T) {
	t.Parallel()

	registry := NewPluginRegistry()

	plugin := &mockPluginWithFindings{
		mockCompliancePlugin: mockCompliancePlugin{
			name:        "test-plugin",
			version:     "1.0.0",
			description: "Test Plugin",
		},
		controls: []compliance.Control{
			{ID: "TEST-001", Title: "Test Control", Severity: "high"},
		},
		findings: []compliance.Finding{
			{
				Title:      "Test Finding",
				Severity:   "high",
				References: []string{"TEST-001"},
			},
		},
	}

	if err := registry.RegisterPlugin(plugin); err != nil {
		t.Fatalf("Failed to register plugin: %v", err)
	}

	device := &common.CommonDevice{
		System: common.System{Hostname: "test"},
	}

	// Pass duplicate names — should be deduplicated internally
	result, err := registry.RunComplianceChecks(device, []string{"test-plugin", "test-plugin"}, newTestLogger(t))
	if err != nil {
		t.Fatalf("RunComplianceChecks() unexpected error: %v", err)
	}

	// Should have findings from only one execution
	if len(result.Findings) != 1 {
		t.Errorf("Expected 1 finding (deduplicated), got %d", len(result.Findings))
	}

	// Per-plugin map should have exactly one entry
	if len(result.PluginFindings) != 1 {
		t.Errorf("Expected 1 plugin in PluginFindings, got %d", len(result.PluginFindings))
	}

	// PluginInfo should have exactly one entry
	if len(result.PluginInfo) != 1 {
		t.Errorf("Expected 1 plugin in PluginInfo, got %d", len(result.PluginInfo))
	}

	// Summary should reflect the deduplicated count
	if result.Summary.TotalFindings != 1 {
		t.Errorf("Expected TotalFindings=1, got %d", result.Summary.TotalFindings)
	}

	if result.Summary.PluginCount != 1 {
		t.Errorf("Expected PluginCount=1, got %d", result.Summary.PluginCount)
	}
}
