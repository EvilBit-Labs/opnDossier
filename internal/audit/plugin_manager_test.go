package audit

import (
	"context"
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/compliance"
	"github.com/EvilBit-Labs/opnDossier/internal/logging"
	"github.com/EvilBit-Labs/opnDossier/internal/model/common"
)

func newTestLogger(t *testing.T) *logging.Logger {
	t.Helper()
	logger, err := logging.New(logging.Config{})
	if err != nil {
		t.Fatal("failed to create test logger:", err)
	}
	return logger
}

func TestNewPluginManager(t *testing.T) {
	t.Parallel()

	logger := newTestLogger(t)
	manager := NewPluginManager(logger)

	if manager == nil {
		t.Fatal("NewPluginManager() returned nil")
	}

	if manager.registry == nil {
		t.Error("NewPluginManager() registry not initialized")
	}

	if manager.logger != logger {
		t.Error("NewPluginManager() logger not set correctly")
	}
}

func TestPluginManager_InitializePlugins(t *testing.T) {
	t.Parallel()

	logger := newTestLogger(t)
	manager := NewPluginManager(logger)

	ctx := context.Background()
	err := manager.InitializePlugins(ctx)
	if err != nil {
		t.Errorf("InitializePlugins() error = %v", err)
	}

	// Verify plugins were registered
	pluginNames := manager.registry.ListPlugins()
	expectedPlugins := []string{"stig", "sans", "firewall"}

	if len(pluginNames) != len(expectedPlugins) {
		t.Errorf("InitializePlugins() registered %d plugins, expected %d", len(pluginNames), len(expectedPlugins))
	}

	// Check that all expected plugins are present
	pluginMap := make(map[string]bool)
	for _, name := range pluginNames {
		pluginMap[name] = true
	}

	for _, expected := range expectedPlugins {
		if !pluginMap[expected] {
			t.Errorf("InitializePlugins() missing expected plugin: %s", expected)
		}
	}
}

func TestPluginManager_GetRegistry(t *testing.T) {
	t.Parallel()

	logger := newTestLogger(t)
	manager := NewPluginManager(logger)

	registry := manager.GetRegistry()
	if registry == nil {
		t.Error("GetRegistry() returned nil")
	}

	if registry != manager.registry {
		t.Error("GetRegistry() returned different registry than internal")
	}
}

func TestPluginManager_ListAvailablePlugins(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name                 string
		initializePlugins    bool
		expectedMinimumCount int
	}{
		{
			name:                 "with plugins initialized",
			initializePlugins:    true,
			expectedMinimumCount: 3,
		},
		{
			name:                 "without plugins initialized",
			initializePlugins:    false,
			expectedMinimumCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			logger := newTestLogger(t)
			manager := NewPluginManager(logger)
			ctx := context.Background()

			if tt.initializePlugins {
				err := manager.InitializePlugins(ctx)
				if err != nil {
					t.Fatalf("Failed to initialize plugins: %v", err)
				}
			}

			plugins := manager.ListAvailablePlugins(ctx)
			if plugins == nil {
				t.Error("ListAvailablePlugins() returned nil")
			}

			if len(plugins) < tt.expectedMinimumCount {
				t.Errorf(
					"ListAvailablePlugins() returned %d plugins, expected at least %d",
					len(plugins),
					tt.expectedMinimumCount,
				)
			}

			if tt.initializePlugins {
				// Verify plugin info structure for initialized plugins
				for _, pluginInfo := range plugins {
					if pluginInfo.Name == "" {
						t.Error("ListAvailablePlugins() plugin has empty name")
					}
					if pluginInfo.Version == "" {
						t.Error("ListAvailablePlugins() plugin has empty version")
					}
					if pluginInfo.Description == "" {
						t.Error("ListAvailablePlugins() plugin has empty description")
					}
				}
			}
		})
	}
}

func TestPluginManager_RunComplianceAudit(t *testing.T) {
	t.Parallel()

	logger := newTestLogger(t)
	manager := NewPluginManager(logger)
	ctx := context.Background()

	// Initialize plugins first
	err := manager.InitializePlugins(ctx)
	if err != nil {
		t.Fatalf("Failed to initialize plugins: %v", err)
	}

	// Create test configuration
	testConfig := &common.CommonDevice{
		System: common.System{
			Hostname: "test-host",
			Domain:   "test.local",
		},
	}

	tests := []struct {
		name        string
		pluginNames []string
		wantErr     bool
	}{
		{
			name:        "valid single plugin",
			pluginNames: []string{"stig"},
			wantErr:     false,
		},
		{
			name:        "valid multiple plugins",
			pluginNames: []string{"stig", "sans"},
			wantErr:     false,
		},
		{
			name:        "empty plugin list",
			pluginNames: []string{},
			wantErr:     false,
		},
		{
			name:        "nil plugin list",
			pluginNames: nil,
			wantErr:     false,
		},
		{
			name:        "nonexistent plugin",
			pluginNames: []string{"nonexistent"},
			wantErr:     true,
		},
		{
			name:        "mixed valid and invalid plugins",
			pluginNames: []string{"stig", "nonexistent"},
			wantErr:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result, err := manager.RunComplianceAudit(ctx, testConfig, tt.pluginNames)
			if (err != nil) != tt.wantErr {
				t.Errorf("RunComplianceAudit() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				if result == nil {
					t.Error("RunComplianceAudit() returned nil result when no error expected")
					return
				}

				if result.Summary == nil {
					t.Error("RunComplianceAudit() result has nil summary")
				}

				if result.Findings == nil {
					t.Error("RunComplianceAudit() result has nil findings")
				}

				if result.Compliance == nil {
					t.Error("RunComplianceAudit() result has nil compliance")
				}

				if result.PluginInfo == nil {
					t.Error("RunComplianceAudit() result has nil plugin info")
				}
			}
		})
	}
}

func TestPluginManager_GetPluginControlInfo(t *testing.T) {
	t.Parallel()

	logger := newTestLogger(t)
	manager := NewPluginManager(logger)
	ctx := context.Background()

	// Initialize plugins first
	err := manager.InitializePlugins(ctx)
	if err != nil {
		t.Fatalf("Failed to initialize plugins: %v", err)
	}

	tests := []struct {
		name       string
		pluginName string
		controlID  string
		wantErr    bool
	}{
		{
			name:       "valid plugin and control",
			pluginName: "stig",
			controlID:  "V-206694",
			wantErr:    false,
		},
		{
			name:       "nonexistent plugin",
			pluginName: "nonexistent",
			controlID:  "CONTROL-001",
			wantErr:    true,
		},
		{
			name:       "valid plugin but nonexistent control",
			pluginName: "stig",
			controlID:  "V-NONEXISTENT",
			wantErr:    true,
		},
		{
			name:       "empty plugin name",
			pluginName: "",
			controlID:  "CONTROL-001",
			wantErr:    true,
		},
		{
			name:       "empty control ID",
			pluginName: "stig",
			controlID:  "",
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			control, err := manager.GetPluginControlInfo(tt.pluginName, tt.controlID)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetPluginControlInfo() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				if control == nil {
					t.Error("GetPluginControlInfo() returned nil control when no error expected")
					return
				}

				if control.ID != tt.controlID {
					t.Errorf("GetPluginControlInfo() control ID = %v, want %v", control.ID, tt.controlID)
				}
			}
		})
	}
}

func TestPluginManager_ValidatePluginConfiguration(t *testing.T) {
	t.Parallel()

	logger := newTestLogger(t)
	manager := NewPluginManager(logger)
	ctx := context.Background()

	// Initialize plugins first
	err := manager.InitializePlugins(ctx)
	if err != nil {
		t.Fatalf("Failed to initialize plugins: %v", err)
	}

	tests := []struct {
		name       string
		pluginName string
		wantErr    bool
	}{
		{
			name:       "valid plugin",
			pluginName: "stig",
			wantErr:    false,
		},
		{
			name:       "another valid plugin",
			pluginName: "sans",
			wantErr:    false,
		},
		{
			name:       "nonexistent plugin",
			pluginName: "nonexistent",
			wantErr:    true,
		},
		{
			name:       "empty plugin name",
			pluginName: "",
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := manager.ValidatePluginConfiguration(tt.pluginName)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidatePluginConfiguration() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

//nolint:tparallel // subtests share manager state from parent setup
func TestPluginManager_GetPluginStatistics(t *testing.T) {
	t.Parallel()

	logger := newTestLogger(t)
	manager := NewPluginManager(logger)
	ctx := context.Background()

	// Test with no plugins initialized
	t.Run("no plugins initialized", func(t *testing.T) {
		stats := manager.GetPluginStatistics()
		if stats == nil {
			t.Error("GetPluginStatistics() returned nil")
		}

		totalPlugins, ok := stats["total_plugins"].(int)
		if !ok || totalPlugins != 0 {
			t.Errorf("GetPluginStatistics() total_plugins = %v, want 0", totalPlugins)
		}

		availablePlugins, ok := stats["available_plugins"].([]string)
		if !ok || len(availablePlugins) != 0 {
			t.Errorf("GetPluginStatistics() available_plugins length = %v, want 0", len(availablePlugins))
		}

		controlCounts, ok := stats["control_counts"].(map[string]int)
		if !ok || len(controlCounts) != 0 {
			t.Errorf("GetPluginStatistics() control_counts length = %v, want 0", len(controlCounts))
		}
	})

	// Initialize plugins
	err := manager.InitializePlugins(ctx)
	if err != nil {
		t.Fatalf("Failed to initialize plugins: %v", err)
	}

	// Test with plugins initialized
	t.Run("plugins initialized", func(t *testing.T) {
		stats := manager.GetPluginStatistics()
		if stats == nil {
			t.Error("GetPluginStatistics() returned nil")
		}

		totalPlugins, ok := stats["total_plugins"].(int)
		if !ok || totalPlugins < 3 {
			t.Errorf("GetPluginStatistics() total_plugins = %v, want at least 3", totalPlugins)
		}

		availablePlugins, ok := stats["available_plugins"].([]string)
		if !ok || len(availablePlugins) < 3 {
			t.Errorf("GetPluginStatistics() available_plugins length = %v, want at least 3", len(availablePlugins))
		}

		controlCounts, ok := stats["control_counts"].(map[string]int)
		if !ok {
			t.Error("GetPluginStatistics() control_counts not found or wrong type")
		}

		// Verify that we have control counts for each plugin
		for _, pluginName := range availablePlugins {
			count, exists := controlCounts[pluginName]
			if !exists {
				t.Errorf("GetPluginStatistics() missing control count for plugin %s", pluginName)
			}
			if count < 0 {
				t.Errorf("GetPluginStatistics() negative control count for plugin %s: %d", pluginName, count)
			}
		}
	})
}

// TestPluginManager_WithNilConfig tests error handling when config is nil.
func TestPluginManager_WithNilConfig(t *testing.T) {
	t.Parallel()

	logger := newTestLogger(t)
	manager := NewPluginManager(logger)
	ctx := context.Background()

	// Initialize plugins first
	err := manager.InitializePlugins(ctx)
	if err != nil {
		t.Fatalf("Failed to initialize plugins: %v", err)
	}

	// Create a test configuration (empty but not nil)
	testConfig := &common.CommonDevice{}

	// Test RunComplianceAudit with valid config
	_, err = manager.RunComplianceAudit(ctx, testConfig, []string{"stig"})
	if err != nil {
		t.Errorf("RunComplianceAudit() with valid config returned error: %v", err)
	}
}

// mockFailingPlugin is a plugin that fails validation for testing error paths.
type mockFailingPlugin struct {
	mockCompliancePlugin

	shouldFailValidation bool
}

func (m *mockFailingPlugin) ValidateConfiguration() error {
	if m.shouldFailValidation {
		return compliance.ErrPluginValidation
	}
	return m.mockCompliancePlugin.ValidateConfiguration()
}

// TestPluginManager_PluginValidationFailure tests handling of plugin validation failures.
func TestPluginManager_PluginValidationFailure(t *testing.T) {
	t.Parallel()

	logger := newTestLogger(t)
	manager := NewPluginManager(logger)

	// Try to register a plugin that fails validation
	failingPlugin := &mockFailingPlugin{
		mockCompliancePlugin: mockCompliancePlugin{
			name:        "failing-plugin",
			description: "A plugin that fails validation",
			version:     "1.0.0",
		},
		shouldFailValidation: true,
	}

	err := manager.registry.RegisterPlugin(failingPlugin)
	if err == nil {
		t.Error("Expected error when registering plugin that fails validation")
	}
}
