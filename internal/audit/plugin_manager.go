package audit

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/EvilBit-Labs/opnDossier/internal/model"
	"github.com/EvilBit-Labs/opnDossier/internal/plugin"
	"github.com/EvilBit-Labs/opnDossier/internal/plugins/firewall"
	"github.com/EvilBit-Labs/opnDossier/internal/plugins/sans"
	"github.com/EvilBit-Labs/opnDossier/internal/plugins/stig"
)

// PluginManager manages the lifecycle of compliance plugins.
type PluginManager struct {
	registry *PluginRegistry
	logger   *slog.Logger
}

// NewPluginManager creates a new plugin manager.
func NewPluginManager(logger *slog.Logger) *PluginManager {
	return &PluginManager{
		registry: NewPluginRegistry(),
		logger:   logger,
	}
}

// InitializePlugins initializes and registers all available plugins.
func (pm *PluginManager) InitializePlugins(ctx context.Context) error {
	pm.logger.InfoContext(ctx, "Initializing compliance plugins")

	// Register STIG plugin
	stigPlugin := stig.NewPlugin()
	if err := pm.registry.RegisterPlugin(stigPlugin); err != nil {
		return fmt.Errorf("failed to register STIG plugin: %w", err)
	}

	pm.logger.InfoContext(ctx, "Registered STIG plugin", "name", stigPlugin.Name(), "version", stigPlugin.Version())

	// Register SANS plugin
	sansPlugin := sans.NewPlugin()
	if err := pm.registry.RegisterPlugin(sansPlugin); err != nil {
		return fmt.Errorf("failed to register SANS plugin: %w", err)
	}

	pm.logger.InfoContext(ctx, "Registered SANS plugin", "name", sansPlugin.Name(), "version", sansPlugin.Version())

	// Register Firewall plugin
	firewallPlugin := firewall.NewPlugin()
	if err := pm.registry.RegisterPlugin(firewallPlugin); err != nil {
		return fmt.Errorf("failed to register Firewall plugin: %w", err)
	}

	pm.logger.InfoContext(
		ctx,
		"Registered Firewall plugin",
		"name",
		firewallPlugin.Name(),
		"version",
		firewallPlugin.Version(),
	)

	pm.logger.InfoContext(ctx, "Plugin initialization completed", "total_plugins", len(pm.registry.ListPlugins()))

	return nil
}

// GetRegistry returns the plugin registry.
func (pm *PluginManager) GetRegistry() *PluginRegistry {
	return pm.registry
}

// ListAvailablePlugins returns information about all available plugins.
func (pm *PluginManager) ListAvailablePlugins(ctx context.Context) []PluginInfo {
	pluginNames := pm.registry.ListPlugins()
	pluginInfos := make([]PluginInfo, 0, len(pluginNames))

	for _, pluginName := range pluginNames {
		p, err := pm.registry.GetPlugin(pluginName)
		if err != nil {
			pm.logger.ErrorContext(ctx, "Failed to get plugin info", "plugin", pluginName, "error", err)
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
	config *model.OpnSenseDocument,
	pluginNames []string,
) (*ComplianceResult, error) {
	pm.logger.InfoContext(ctx, "Starting compliance audit", "plugins", pluginNames)

	result, err := pm.registry.RunComplianceChecks(config, pluginNames)
	if err != nil {
		return nil, fmt.Errorf("compliance audit failed: %w", err)
	}

	pm.logger.InfoContext(ctx, "Compliance audit completed",
		"total_findings", result.Summary.TotalFindings,
		"plugins_used", len(pluginNames))

	return result, nil
}

// GetPluginControlInfo returns detailed information about a specific control.
func (pm *PluginManager) GetPluginControlInfo(pluginName, controlID string) (*plugin.Control, error) {
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

// GetPluginStatistics returns statistics about plugin usage and compliance.
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
			continue
		}

		controlCounts[pluginName] = len(p.GetControls())
	}

	stats["control_counts"] = controlCounts

	return stats
}
