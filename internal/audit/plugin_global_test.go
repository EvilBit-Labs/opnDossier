package audit

import (
	"context"
	"errors"
	"fmt"
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

	ctx := context.Background()

	t.Run("nonexistent directory", func(t *testing.T) {
		t.Parallel()

		registry := NewPluginRegistry()
		logger := newTestLogger(t)

		result, err := registry.LoadDynamicPlugins(ctx, "/nonexistent/path/to/plugins", false, logger)
		if err != nil {
			t.Errorf("LoadDynamicPlugins() unexpected error: %v", err)
		}

		if result.Loaded != 0 || result.Failed() != 0 {
			t.Errorf("LoadDynamicPlugins() Loaded=%d, Failed=%d; want 0, 0", result.Loaded, result.Failed())
		}
	})

	t.Run("empty directory", func(t *testing.T) {
		t.Parallel()

		registry := NewPluginRegistry()
		logger := newTestLogger(t)

		result, err := registry.LoadDynamicPlugins(ctx, t.TempDir(), false, logger)
		if err != nil {
			t.Errorf("LoadDynamicPlugins() unexpected error: %v", err)
		}

		if result.Loaded != 0 || result.Failed() != 0 {
			t.Errorf("LoadDynamicPlugins() Loaded=%d, Failed=%d; want 0, 0", result.Loaded, result.Failed())
		}
	})

	t.Run("directory with non-.so files", func(t *testing.T) {
		t.Parallel()

		registry := NewPluginRegistry()
		logger := newTestLogger(t)
		dir := createTestDirWithNonSOFiles(t)

		result, err := registry.LoadDynamicPlugins(ctx, dir, false, logger)
		if err != nil {
			t.Errorf("LoadDynamicPlugins() unexpected error: %v", err)
		}

		if result.Loaded != 0 || result.Failed() != 0 {
			t.Errorf("LoadDynamicPlugins() Loaded=%d, Failed=%d; want 0, 0", result.Loaded, result.Failed())
		}
	})

	t.Run("explicit dir not found returns error", func(t *testing.T) {
		t.Parallel()

		registry := NewPluginRegistry()
		logger := newTestLogger(t)

		missingDir := filepath.Join(t.TempDir(), "explicit-missing")
		result, loadErr := registry.LoadDynamicPlugins(ctx, missingDir, true, logger)
		if loadErr == nil {
			t.Fatal("LoadDynamicPlugins() expected error for explicit missing directory")
		}

		if !strings.Contains(loadErr.Error(), "does not exist") {
			t.Errorf("expected 'does not exist' in error, got: %v", loadErr)
		}

		if result.Loaded != 0 || result.Failed() != 0 {
			t.Errorf("LoadDynamicPlugins() Loaded=%d, Failed=%d; want 0, 0", result.Loaded, result.Failed())
		}
	})

	t.Run("nonexplicit dir not found emits Debug", func(t *testing.T) {
		t.Parallel()

		registry := NewPluginRegistry()

		var buf strings.Builder
		bufLogger, err := logging.New(logging.Config{
			Level:  "debug",
			Output: &buf,
		})
		if err != nil {
			t.Fatalf("failed to create buffer logger: %v", err)
		}

		missingDir := filepath.Join(t.TempDir(), "optional-missing")
		result, loadErr := registry.LoadDynamicPlugins(ctx, missingDir, false, bufLogger)
		if loadErr != nil {
			t.Errorf("LoadDynamicPlugins() unexpected error: %v", loadErr)
		}

		if result.Loaded != 0 || result.Failed() != 0 {
			t.Errorf("LoadDynamicPlugins() Loaded=%d, Failed=%d; want 0, 0", result.Loaded, result.Failed())
		}

		logOutput := buf.String()
		if !strings.Contains(logOutput, "DEBU") {
			t.Errorf("expected DEBUG-level log for non-explicit missing directory, got:\n%s", logOutput)
		}

		// Should NOT contain WARN for the non-explicit case.
		if strings.Contains(logOutput, "WARN") {
			t.Errorf("did not expect WARN-level log for non-explicit missing directory, got:\n%s", logOutput)
		}
	})

	t.Run("all .so files fail", func(t *testing.T) {
		t.Parallel()

		dir := createTestDirWithDummySOFiles(t, 3)

		// Use injectable loader for deterministic, platform-independent failures.
		registry := newPluginRegistryWithLoader(func(path string) (compliance.Plugin, error) {
			return nil, fmt.Errorf("simulated failure for %s", path)
		})
		logger := newTestLogger(t)

		result, err := registry.LoadDynamicPlugins(ctx, dir, false, logger)
		if err == nil {
			t.Error("LoadDynamicPlugins() expected error when all .so files fail")
		}

		if result.Loaded != 0 {
			t.Errorf("LoadDynamicPlugins() Loaded = %d, want 0", result.Loaded)
		}

		if result.Failed() != 3 {
			t.Fatalf("LoadDynamicPlugins() Failed = %d, want 3", result.Failed())
		}

		for _, f := range result.Failures {
			if f.Err == nil {
				t.Errorf("PluginLoadError for %q has nil Err", f.Name)
			}

			if filepath.Ext(f.Name) != ".so" {
				t.Errorf("PluginLoadError Name %q does not end in .so", f.Name)
			}
		}
	})

	t.Run("partial failure — mixed success and failure", func(t *testing.T) {
		t.Parallel()

		// Create a directory with two .so files.
		dir := t.TempDir()
		goodFile := "good_plugin.so"
		badFile := "bad_plugin.so"

		for _, name := range []string{goodFile, badFile} {
			err := os.WriteFile(filepath.Join(dir, name), []byte("stub"), 0o600)
			if err != nil {
				t.Fatalf("Failed to create %s: %v", name, err)
			}
		}

		// Build a registry with a custom pluginLoader that succeeds for
		// good_plugin.so and fails for bad_plugin.so.
		registry := newPluginRegistryWithLoader(func(path string) (compliance.Plugin, error) {
			if strings.Contains(path, "good_plugin") {
				return &mockCompliancePlugin{
					name:        "good-dynamic-plugin",
					version:     "1.0.0",
					description: "A successfully loaded plugin",
				}, nil
			}

			return nil, fmt.Errorf("simulated load failure for %s", path)
		})

		logger := newTestLogger(t)

		result, err := registry.LoadDynamicPlugins(ctx, dir, false, logger)
		if err == nil {
			t.Error("LoadDynamicPlugins() expected error when some .so files fail")
		}

		if result.Loaded != 1 {
			t.Errorf("LoadDynamicPlugins() Loaded = %d, want 1", result.Loaded)
		}

		if result.Failed() != 1 {
			t.Errorf("LoadDynamicPlugins() Failed = %d, want 1", result.Failed())
		}

		if len(result.Failures) != 1 {
			t.Fatalf("LoadDynamicPlugins() len(Failures) = %d, want 1", len(result.Failures))
		}

		if result.Failures[0].Name != badFile {
			t.Errorf("LoadDynamicPlugins() Failures[0].Name = %q, want %q", result.Failures[0].Name, badFile)
		}

		if result.Failures[0].Err == nil {
			t.Error("LoadDynamicPlugins() Failures[0].Err should not be nil")
		}

		// Verify the successfully loaded plugin was actually registered.
		_, getErr := registry.GetPlugin("good-dynamic-plugin")
		if getErr != nil {
			t.Errorf("expected good-dynamic-plugin to be registered, got error: %v", getErr)
		}
	})
}

// TestLoadDynamicPlugins_NilLogger verifies that LoadDynamicPlugins returns an
// error immediately when called with a nil logger.
func TestLoadDynamicPlugins_NilLogger(t *testing.T) {
	t.Parallel()

	registry := NewPluginRegistry()
	result, err := registry.LoadDynamicPlugins(context.Background(), t.TempDir(), false, nil)

	if err == nil {
		t.Fatal("LoadDynamicPlugins() expected error for nil logger")
	}

	if !strings.Contains(err.Error(), "nil logger") {
		t.Errorf("expected 'nil logger' in error, got: %v", err)
	}

	if result.Loaded != 0 || result.Failed() != 0 {
		t.Errorf("LoadDynamicPlugins() Loaded=%d, Failed=%d; want 0, 0", result.Loaded, result.Failed())
	}
}

// TestLoadDynamicPlugins_RegistrationFailure verifies that a plugin whose loader
// succeeds but whose registration fails (e.g., duplicate name) is recorded as
// a failure with a "register" error message.
func TestLoadDynamicPlugins_RegistrationFailure(t *testing.T) {
	t.Parallel()

	dir := createTestDirWithDummySOFiles(t, 1)

	// Loader always returns the same plugin name, but we pre-register it
	// so the second registration attempt fails.
	registry := newPluginRegistryWithLoader(func(_ string) (compliance.Plugin, error) {
		return &mockCompliancePlugin{
			name:        "already-registered",
			version:     "1.0.0",
			description: "duplicate",
		}, nil
	})

	// Pre-register so LoadDynamicPlugins hits the duplicate path.
	err := registry.RegisterPlugin(&mockCompliancePlugin{
		name:        "already-registered",
		version:     "1.0.0",
		description: "original",
	})
	if err != nil {
		t.Fatalf("pre-registration failed: %v", err)
	}

	logger := newTestLogger(t)
	result, loadErr := registry.LoadDynamicPlugins(context.Background(), dir, false, logger)

	if loadErr == nil {
		t.Error("LoadDynamicPlugins() expected error for registration failure")
	}

	if result.Loaded != 0 {
		t.Errorf("LoadDynamicPlugins() Loaded = %d, want 0", result.Loaded)
	}

	if result.Failed() != 1 {
		t.Fatalf("LoadDynamicPlugins() Failed = %d, want 1", result.Failed())
	}

	if !strings.Contains(result.Failures[0].Error(), "register") {
		t.Errorf("expected 'register' in failure error, got: %v", result.Failures[0].Err)
	}
}

// TestLoadDynamicPlugins_NilPlugin verifies that a loader returning (nil, nil)
// is treated as a failure rather than causing a nil-pointer panic.
func TestLoadDynamicPlugins_NilPlugin(t *testing.T) {
	t.Parallel()

	dir := createTestDirWithDummySOFiles(t, 1)

	registry := newPluginRegistryWithLoader(func(_ string) (compliance.Plugin, error) {
		//nolint:nilnil // intentional: testing nil-plugin guard
		return nil, nil
	})

	logger := newTestLogger(t)
	result, loadErr := registry.LoadDynamicPlugins(context.Background(), dir, false, logger)

	if loadErr == nil {
		t.Error("LoadDynamicPlugins() expected error for nil plugin")
	}

	if result.Loaded != 0 {
		t.Errorf("LoadDynamicPlugins() Loaded = %d, want 0", result.Loaded)
	}

	if result.Failed() != 1 {
		t.Fatalf("LoadDynamicPlugins() Failed = %d, want 1", result.Failed())
	}

	if !strings.Contains(result.Failures[0].Error(), "nil plugin") {
		t.Errorf("expected 'nil plugin' in failure error, got: %v", result.Failures[0].Err)
	}
}

// TestPluginLoadError_Error verifies that PluginLoadError implements the
// error interface with a descriptive message.
func TestPluginLoadError_Error(t *testing.T) {
	t.Parallel()

	f := PluginLoadError{Name: "bad.so", Err: errors.New("corrupt file")}
	got := f.Error()

	if !strings.Contains(got, "bad.so") {
		t.Errorf("Error() should contain filename, got: %s", got)
	}

	if !strings.Contains(got, "corrupt file") {
		t.Errorf("Error() should contain underlying error, got: %s", got)
	}
}

// TestPluginLoadError_Unwrap verifies that PluginLoadError supports
// errors.Is and errors.As through its Unwrap method.
func TestPluginLoadError_Unwrap(t *testing.T) {
	t.Parallel()

	sentinel := errors.New("sentinel")
	f := PluginLoadError{Name: "bad.so", Err: sentinel}

	if !errors.Is(f, sentinel) {
		t.Error("errors.Is should match the underlying sentinel error")
	}

	unwrapped := f.Unwrap()
	if !errors.Is(unwrapped, sentinel) {
		t.Errorf("Unwrap() = %v, want sentinel", unwrapped)
	}
}

// TestLoadDynamicPlugins_ExplicitDirWrapsErrNotExist verifies that the error
// returned for an explicit missing directory wraps os.ErrNotExist.
func TestLoadDynamicPlugins_ExplicitDirWrapsErrNotExist(t *testing.T) {
	t.Parallel()

	registry := NewPluginRegistry()
	logger := newTestLogger(t)

	missingDir := filepath.Join(t.TempDir(), "explicit-missing")
	_, loadErr := registry.LoadDynamicPlugins(context.Background(), missingDir, true, logger)

	if loadErr == nil {
		t.Fatal("expected error for explicit missing directory")
	}

	if !errors.Is(loadErr, os.ErrNotExist) {
		t.Errorf("expected error to wrap os.ErrNotExist, got: %v", loadErr)
	}
}

// TestPluginManager_SetPluginDir_Integration verifies the full lifecycle:
// SetPluginDir → InitializePlugins → GetLoadResult with both success and
// failure dynamic plugins.
func TestPluginManager_SetPluginDir_Integration(t *testing.T) {
	t.Parallel()

	t.Run("no plugin dir configured", func(t *testing.T) {
		t.Parallel()

		logger := newTestLogger(t)
		pm := NewPluginManager(logger)

		if err := pm.InitializePlugins(context.Background()); err != nil {
			t.Fatalf("InitializePlugins() unexpected error: %v", err)
		}

		result := pm.GetLoadResult()
		if result.Loaded != 0 || result.Failed() != 0 {
			t.Errorf("GetLoadResult() Loaded=%d, Failed=%d; want 0, 0", result.Loaded, result.Failed())
		}
	})

	t.Run("explicit dir missing returns error", func(t *testing.T) {
		t.Parallel()

		logger := newTestLogger(t)
		pm := NewPluginManager(logger)

		missingDir := filepath.Join(t.TempDir(), "does-not-exist")
		pm.SetPluginDir(missingDir, true)

		err := pm.InitializePlugins(context.Background())
		if err == nil {
			t.Fatal("InitializePlugins() expected error for explicit missing dir")
		}

		if !strings.Contains(err.Error(), "does not exist") {
			t.Errorf("expected 'does not exist' in error, got: %v", err)
		}
	})

	t.Run("empty plugin dir loads nothing", func(t *testing.T) {
		t.Parallel()

		logger := newTestLogger(t)
		pm := NewPluginManager(logger)
		pm.SetPluginDir(t.TempDir(), false)

		if err := pm.InitializePlugins(context.Background()); err != nil {
			t.Fatalf("InitializePlugins() unexpected error: %v", err)
		}

		result := pm.GetLoadResult()
		if result.Loaded != 0 || result.Failed() != 0 {
			t.Errorf("GetLoadResult() Loaded=%d, Failed=%d; want 0, 0", result.Loaded, result.Failed())
		}
	})
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

// createTestDirWithDummySOFiles creates a temporary directory containing count
// dummy .so files (plain text, not valid shared objects) for testing load failures.
func createTestDirWithDummySOFiles(t *testing.T, count int) string {
	t.Helper()

	dir := t.TempDir()

	for i := range count {
		name := fmt.Sprintf("dummy_%d.so", i)
		filePath := filepath.Join(dir, name)

		err := os.WriteFile(filePath, []byte("not a real shared object"), 0o600)
		if err != nil {
			t.Fatalf("Failed to create dummy .so file %s: %v", name, err)
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

func (m *mockPluginWithFindings) EvaluatedControlIDs(_ *common.CommonDevice) []string {
	ids := make([]string, len(m.controls))
	for i, c := range m.controls {
		ids[i] = c.ID
	}

	return ids
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

func (m *mockPanickingPlugin) EvaluatedControlIDs(_ *common.CommonDevice) []string {
	ids := make([]string, len(m.controls))
	for i, c := range m.controls {
		ids[i] = c.ID
	}

	return ids
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
				Type:        common.RuleTypePass,
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
