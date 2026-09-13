package audit

import (
	"context"
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/compliance"
	"github.com/EvilBit-Labs/opnDossier/internal/logging"
	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
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

	t.Run("nil registry allocates a private one", func(t *testing.T) {
		t.Parallel()

		manager := NewPluginManager(logger, nil)
		if manager == nil {
			t.Fatal("NewPluginManager() returned nil")
		}
		if manager.registry == nil {
			t.Error("NewPluginManager(nil) registry not initialized")
		}
		if manager.logger != logger {
			t.Error("NewPluginManager() logger not set correctly")
		}
	})

	t.Run("explicit registry is retained (single source of truth)", func(t *testing.T) {
		t.Parallel()

		reg := NewPluginRegistry()
		manager := NewPluginManager(logger, reg)
		if manager == nil {
			t.Fatal("NewPluginManager() returned nil")
		}
		if manager.registry != reg {
			t.Error(
				"NewPluginManager(reg) did not retain the supplied registry; a second registry was allocated — see todo #143",
			)
		}
	})

	t.Run("explicit registry is shared across managers", func(t *testing.T) {
		t.Parallel()

		reg := NewPluginRegistry()
		m1 := NewPluginManager(logger, reg)
		m2 := NewPluginManager(logger, reg)
		if m1.registry != m2.registry {
			t.Error("shared registry should be observable across managers")
		}
	})
}

func TestPluginManager_InitializePlugins(t *testing.T) {
	t.Parallel()

	logger := newTestLogger(t)
	manager := NewPluginManager(logger, nil)

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
	manager := NewPluginManager(logger, nil)

	registry := manager.GetRegistry()
	if registry == nil {
		t.Error("GetRegistry() returned nil")
	}

	if registry != manager.registry {
		t.Error("GetRegistry() returned different registry than internal")
	}
}

// TestPluginManager_WithNilConfig tests error handling when config is nil.
//
// ListAvailablePlugins, RunComplianceAudit, GetPluginControlInfo,
// ValidatePluginConfiguration, and GetPluginStatistics (formerly tested here)
// had no production caller — every real caller reads pm.GetRegistry() and
// calls PluginRegistry methods directly (RunComplianceChecks, GetPlugin,
// ListPlugins) — so they were removed along with their tests. Their coverage
// lives on: RunComplianceChecks behavior across many plugin/error
// combinations is pinned in plugin_global_test.go's TestRunComplianceChecks_*
// suite, and GetControlByID / ValidateConfiguration are tested directly on
// each plugin implementation (internal/plugins/{stig,sans,firewall}).
func TestPluginManager_WithNilConfig(t *testing.T) {
	t.Parallel()

	logger := newTestLogger(t)
	manager := NewPluginManager(logger, nil)
	ctx := context.Background()

	// Initialize plugins first
	err := manager.InitializePlugins(ctx)
	if err != nil {
		t.Fatalf("Failed to initialize plugins: %v", err)
	}

	// Create a test configuration (empty but not nil)
	testConfig := &common.CommonDevice{}

	// Test RunComplianceChecks with valid config, via the manager's registry
	// (the actual production call path — see mode_controller.go).
	_, err = manager.GetRegistry().RunComplianceChecks(testConfig, []string{"stig"}, logger)
	if err != nil {
		t.Errorf("RunComplianceChecks() with valid config returned error: %v", err)
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
	manager := NewPluginManager(logger, nil)

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
