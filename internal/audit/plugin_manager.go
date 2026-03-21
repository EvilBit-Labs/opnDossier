package audit

import (
	"context"
	"fmt"

	"github.com/EvilBit-Labs/opnDossier/internal/compliance"
	"github.com/EvilBit-Labs/opnDossier/internal/logging"
	"github.com/EvilBit-Labs/opnDossier/internal/plugins/firewall"
	"github.com/EvilBit-Labs/opnDossier/internal/plugins/sans"
	"github.com/EvilBit-Labs/opnDossier/internal/plugins/stig"
	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
)

// PluginManager manages the lifecycle of compliance plugins.
type PluginManager struct {
	registry          *PluginRegistry
	logger            *logging.Logger
	pluginDir         string
	explicitPluginDir bool
	loadResult        LoadResult
}

// NewPluginManager creates a new plugin manager.
func NewPluginManager(logger *logging.Logger) *PluginManager {
	return &PluginManager{
		registry: NewPluginRegistry(),
		logger:   logger,
	}
}

// InitializePlugins registers all built-in compliance plugins (STIG, SANS,
// Firewall) with the manager's own PluginRegistry. This method is the
// sequential initialization entrypoint and must be called during application
// startup before the manager's registry is used concurrently. All built-in
// plugin registration for this manager happens here, ensuring the manager's
// registry is fully populated before any concurrent audit operations begin.
// Callers must not invoke this method concurrently.
//
// Dynamic plugin loading: if SetPluginDir was called before this method,
// dynamic .so plugins are loaded from the configured directory. Per-plugin
// load failures are non-fatal — they do NOT cause InitializePlugins to return
// an error. Callers must inspect GetLoadResult() after this method returns to
// detect and surface dynamic plugin load failures.
//
// Note: this populates pm.registry only, not the global singleton returned by
// GetGlobalRegistry(). If plugins need to be available via the global registry,
// callers must use RegisterGlobalPlugin() separately.
func (pm *PluginManager) InitializePlugins(ctx context.Context) error {
	logger := pm.logger.WithContext(ctx)
	logger.Info("Initializing compliance plugins")

	// Reset load result so repeated calls don't carry stale state.
	pm.loadResult = LoadResult{}

	// Register STIG plugin
	stigPlugin := stig.NewPlugin()
	if err := pm.registry.RegisterPlugin(stigPlugin); err != nil {
		return fmt.Errorf("failed to register STIG plugin: %w", err)
	}

	logger.Info("Registered STIG plugin", "name", stigPlugin.Name(), "version", stigPlugin.Version())

	// Register SANS plugin
	sansPlugin := sans.NewPlugin()
	if err := pm.registry.RegisterPlugin(sansPlugin); err != nil {
		return fmt.Errorf("failed to register SANS plugin: %w", err)
	}

	logger.Info("Registered SANS plugin", "name", sansPlugin.Name(), "version", sansPlugin.Version())

	// Register Firewall plugin
	firewallPlugin := firewall.NewPlugin()
	if err := pm.registry.RegisterPlugin(firewallPlugin); err != nil {
		return fmt.Errorf("failed to register Firewall plugin: %w", err)
	}

	logger.Info("Registered Firewall plugin",
		"name", firewallPlugin.Name(),
		"version", firewallPlugin.Version(),
	)

	// Load dynamic plugins from the configured directory, if any.
	// Directory-level errors (missing explicit dir, unreadable dir) are fatal.
	// Per-plugin load failures are non-fatal — available via GetLoadResult().
	if pm.pluginDir != "" {
		result, loadErr := pm.registry.LoadDynamicPlugins(ctx, pm.pluginDir, pm.explicitPluginDir, logger)
		pm.loadResult = result

		if loadErr != nil && result.Loaded == 0 && len(result.Failures) == 0 {
			// Directory-level error (not per-plugin failures).
			return fmt.Errorf("load dynamic plugins: %w", loadErr)
		}

		logger.Info("Dynamic plugin loading completed",
			"loaded", result.Loaded,
			"failed", result.Failed(),
		)
	}

	logger.Info("Plugin initialization completed", "total_plugins", len(pm.registry.ListPlugins()))

	return nil
}

// SetPluginDir configures the directory from which dynamic .so plugins are
// loaded during InitializePlugins. The explicit flag controls the behavior
// when the directory does not exist: true means the user explicitly configured
// this path (returns an error), false means it is a default/optional path
// (logs at Debug and continues).
func (pm *PluginManager) SetPluginDir(dir string, explicit bool) {
	pm.pluginDir = dir
	pm.explicitPluginDir = explicit
}

// GetLoadResult returns the result of the most recent LoadDynamicPlugins call
// performed during InitializePlugins. If no dynamic plugin directory was
// configured, or InitializePlugins has not been called, the zero-value
// LoadResult is returned. The Failures slice is copied so callers cannot
// mutate the manager's internal slice state; error values within each
// PluginLoadError are shared references.
func (pm *PluginManager) GetLoadResult() LoadResult {
	result := pm.loadResult
	if len(result.Failures) > 0 {
		result.Failures = append([]PluginLoadError(nil), result.Failures...)
	}

	return result
}

// GetRegistry returns the plugin registry.
func (pm *PluginManager) GetRegistry() *PluginRegistry {
	return pm.registry
}

// ListAvailablePlugins returns information about all available plugins.
func (pm *PluginManager) ListAvailablePlugins(ctx context.Context) []PluginInfo {
	logger := pm.logger.WithContext(ctx)
	pluginNames := pm.registry.ListPlugins()
	pluginInfos := make([]PluginInfo, 0, len(pluginNames))

	for _, pluginName := range pluginNames {
		p, err := pm.registry.GetPlugin(pluginName)
		if err != nil {
			// This should not happen since ListPlugins and GetPlugin read the
			// same registry. A failure here indicates registry corruption or a
			// concurrent unregister — log and skip the entry.
			logger.Error("Failed to get plugin info", "plugin", pluginName, "error", err)

			continue
		}

		pluginInfos = append(pluginInfos, PluginInfo{
			Name:        p.Name(),
			Version:     p.Version(),
			Description: p.Description(),
			Controls:    p.GetControls(),
		})
	}

	return pluginInfos
}

// RunComplianceAudit runs compliance checks using specified plugins.
func (pm *PluginManager) RunComplianceAudit(
	ctx context.Context,
	device *common.CommonDevice,
	pluginNames []string,
) (*ComplianceResult, error) {
	logger := pm.logger.WithContext(ctx)
	logger.Info("Starting compliance audit", "plugins", pluginNames)

	result, err := pm.registry.RunComplianceChecks(device, pluginNames, pm.logger)
	if err != nil {
		return nil, fmt.Errorf("compliance audit failed: %w", err)
	}

	logger.Info("Compliance audit completed",
		"total_findings", result.Summary.TotalFindings,
		"plugins_used", len(pluginNames))

	return result, nil
}

// GetPluginControlInfo returns detailed information about a specific control.
func (pm *PluginManager) GetPluginControlInfo(pluginName, controlID string) (*compliance.Control, error) {
	p, err := pm.registry.GetPlugin(pluginName)
	if err != nil {
		return nil, fmt.Errorf("plugin '%s' not found: %w", pluginName, err)
	}

	control, err := p.GetControlByID(controlID)
	if err != nil {
		return nil, fmt.Errorf("control '%s' not found in plugin '%s': %w", controlID, pluginName, err)
	}

	return control, nil
}

// ValidatePluginConfiguration validates the configuration of a specific plugin.
func (pm *PluginManager) ValidatePluginConfiguration(pluginName string) error {
	p, err := pm.registry.GetPlugin(pluginName)
	if err != nil {
		return fmt.Errorf("plugin '%s' not found: %w", pluginName, err)
	}

	return p.ValidateConfiguration()
}

// GetPluginStatistics returns statistics about plugin usage and plugin.
func (pm *PluginManager) GetPluginStatistics() map[string]any {
	stats := make(map[string]any)

	pluginNames := pm.registry.ListPlugins()
	stats["total_plugins"] = len(pluginNames)
	stats["available_plugins"] = pluginNames

	// Get control counts per plugin
	controlCounts := make(map[string]int)

	for _, pluginName := range pluginNames {
		p, err := pm.registry.GetPlugin(pluginName)
		if err != nil {
			pm.logger.Error("Failed to get plugin for statistics", "plugin", pluginName, "error", err)
			continue
		}

		controlCounts[pluginName] = len(p.GetControls())
	}

	stats["control_counts"] = controlCounts

	return stats
}
