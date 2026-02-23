package audit

import (
	"context"
	"fmt"
	"maps"
	"slices"

	"github.com/EvilBit-Labs/opnDossier/internal/compliance"
	"github.com/EvilBit-Labs/opnDossier/internal/logging"
	"github.com/EvilBit-Labs/opnDossier/internal/model/common"
	"github.com/EvilBit-Labs/opnDossier/internal/plugins/firewall"
	"github.com/EvilBit-Labs/opnDossier/internal/plugins/sans"
	"github.com/EvilBit-Labs/opnDossier/internal/plugins/stig"
)

// PluginManager manages the lifecycle of compliance plugins.
type PluginManager struct {
	registry *PluginRegistry
	logger   *logging.Logger
}

// NewPluginManager creates a new plugin manager.
func NewPluginManager(logger *logging.Logger) *PluginManager {
	return &PluginManager{
		registry: NewPluginRegistry(),
		logger:   logger,
	}
}

// InitializePlugins initializes and registers all available plugins.
func (pm *PluginManager) InitializePlugins(ctx context.Context) error {
	logger := pm.logger.WithContext(ctx)
	logger.Info("Initializing compliance plugins")

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

	logger.Info("Plugin initialization completed", "total_plugins", len(pm.registry.ListPlugins()))

	return nil
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
// It returns one ComplianceResult per plugin, keyed by plugin name.
func (pm *PluginManager) RunComplianceAudit(
	ctx context.Context,
	device *common.CommonDevice,
	pluginNames []string,
) (map[string]*ComplianceResult, error) {
	logger := pm.logger.WithContext(ctx)
	logger.Info("Starting compliance audit", "plugins", pluginNames)

	results, err := pm.registry.RunComplianceChecks(device, pluginNames)
	if err != nil {
		return nil, fmt.Errorf("compliance audit failed: %w", err)
	}

	for _, pluginName := range slices.Sorted(maps.Keys(results)) {
		result := results[pluginName]
		if result == nil {
			logger.Warn("Nil result for plugin", "plugin", pluginName)
			continue
		}
		totalFindings := 0
		if result.Summary != nil {
			totalFindings = result.Summary.TotalFindings
		}
		logger.Info("Plugin compliance results",
			"plugin", pluginName,
			"total_findings", totalFindings)
	}

	logger.Info("Compliance audit completed",
		"plugins_used", len(results))

	return results, nil
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

// GetPluginStatistics returns statistics about plugin usage and control counts.
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
