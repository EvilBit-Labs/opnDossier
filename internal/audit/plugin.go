// Package audit provides security audit functionality for OPNsense configurations
// against industry-standard compliance frameworks through a plugin-based architecture.
package audit

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"

	pluginlib "plugin"

	"github.com/unclesp1d3r/opnFocus/internal/model"
	"github.com/unclesp1d3r/opnFocus/internal/plugin"
)

// PluginRegistry manages the registration and retrieval of compliance plugins.
type PluginRegistry struct {
	plugins map[string]plugin.CompliancePlugin
	mutex   sync.RWMutex
}

// NewPluginRegistry creates a new plugin registry.
func NewPluginRegistry() *PluginRegistry {
	return &PluginRegistry{
		plugins: make(map[string]plugin.CompliancePlugin),
	}
}

// RegisterPlugin registers a compliance plugin.
func (pr *PluginRegistry) RegisterPlugin(p plugin.CompliancePlugin) error {
	pr.mutex.Lock()
	defer pr.mutex.Unlock()

	if err := p.ValidateConfiguration(); err != nil {
		return fmt.Errorf("plugin validation failed for %s: %w", p.Name(), err)
	}

	pr.plugins[p.Name()] = p
	return nil
}

// GetPlugin retrieves a plugin by name.
func (pr *PluginRegistry) GetPlugin(name string) (plugin.CompliancePlugin, error) {
	pr.mutex.RLock()
	defer pr.mutex.RUnlock()

	p, exists := pr.plugins[name]
	if !exists {
		return nil, plugin.ErrPluginNotFound
	}

	return p, nil
}

// ListPlugins returns all registered plugin names.
func (pr *PluginRegistry) ListPlugins() []string {
	pr.mutex.RLock()
	defer pr.mutex.RUnlock()

	names := make([]string, 0, len(pr.plugins))
	for name := range pr.plugins {
		names = append(names, name)
	}

	return names
}

// LoadDynamicPlugins loads .so plugins from the specified directory and registers them.
// It is safe to call even if the directory does not exist.
func (pr *PluginRegistry) LoadDynamicPlugins(ctx context.Context, dir string, logger *slog.Logger) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		logger.InfoContext(ctx, "Dynamic plugin directory not found or not accessible", "dir", dir)
		return nil //nolint:nilerr // Intentionally ignore directory access errors
	}

	for _, entry := range entries {
		if filepath.Ext(entry.Name()) != ".so" {
			continue
		}

		path := filepath.Join(dir, entry.Name())
		p, err := pluginlib.Open(path)
		if err != nil {
			logger.ErrorContext(ctx, "Failed to open plugin", "file", path, "error", err)
			continue
		}

		sym, err := p.Lookup("Plugin")
		if err != nil {
			logger.ErrorContext(ctx, "Failed to find Plugin symbol", "file", path, "error", err)
			continue
		}

		compliancePlugin, ok := sym.(plugin.CompliancePlugin)
		if !ok {
			logger.ErrorContext(ctx, "Symbol Plugin does not implement CompliancePlugin", "file", path)
			continue
		}

		if err := pr.RegisterPlugin(compliancePlugin); err != nil {
			logger.ErrorContext(ctx, "Failed to register dynamic plugin", "file", path, "error", err)
			continue
		}

		logger.InfoContext(ctx, "Loaded dynamic plugin", "file", path, "name", compliancePlugin.Name(), "version", compliancePlugin.Version())
	}

	return nil
}

// RunComplianceChecks runs compliance checks for specified plugins.
func (pr *PluginRegistry) RunComplianceChecks(config *model.OpnSenseDocument, pluginNames []string) (*ComplianceResult, error) {
	result := &ComplianceResult{
		Findings:   []plugin.Finding{},
		Compliance: make(map[string]map[string]bool),
		Summary:    &ComplianceSummary{},
		PluginInfo: make(map[string]PluginInfo),
	}

	for _, pluginName := range pluginNames {
		p, err := pr.GetPlugin(pluginName)
		if err != nil {
			return nil, fmt.Errorf("failed to get plugin '%s': %w", pluginName, err)
		}

		// Run checks for this plugin
		findings := p.RunChecks(config)
		result.Findings = append(result.Findings, findings...)

		// Track plugin information
		result.PluginInfo[pluginName] = PluginInfo{
			Name:        p.Name(),
			Version:     p.Version(),
			Description: p.Description(),
			Controls:    p.GetControls(),
		}

		// Initialize compliance tracking for this plugin
		result.Compliance[pluginName] = make(map[string]bool)
		for _, control := range p.GetControls() {
			result.Compliance[pluginName][control.ID] = true // Default to compliant
		}

		// Update compliance status based on findings
		for _, finding := range findings {
			for _, ref := range finding.References {
				if result.Compliance[pluginName] != nil {
					result.Compliance[pluginName][ref] = false // Non-compliant
				}
			}
		}
	}

	// Calculate summary
	result.Summary = pr.calculateSummary(result)

	return result, nil
}

// calculateSummary calculates compliance summary statistics.
func (pr *PluginRegistry) calculateSummary(result *ComplianceResult) *ComplianceSummary {
	summary := &ComplianceSummary{
		TotalFindings: len(result.Findings),
		PluginCount:   len(result.PluginInfo),
		Compliance:    make(map[string]PluginCompliance),
	}

	// Count findings by severity
	for _, finding := range result.Findings {
		switch finding.Type {
		case "critical":
			summary.CriticalFindings++
		case "high":
			summary.HighFindings++
		case "medium":
			summary.MediumFindings++
		case "low":
			summary.LowFindings++
		}
	}

	// Calculate compliance per plugin
	for pluginName, compliance := range result.Compliance {
		compliant := 0
		nonCompliant := 0

		for _, isCompliant := range compliance {
			if isCompliant {
				compliant++
			} else {
				nonCompliant++
			}
		}

		summary.Compliance[pluginName] = PluginCompliance{
			Compliant:    compliant,
			NonCompliant: nonCompliant,
			Total:        compliant + nonCompliant,
		}
	}

	return summary
}

// ComplianceResult represents the complete result of compliance checks.
type ComplianceResult struct {
	Findings   []plugin.Finding           `json:"findings"`
	Compliance map[string]map[string]bool `json:"compliance"`
	Summary    *ComplianceSummary         `json:"summary"`
	PluginInfo map[string]PluginInfo      `json:"pluginInfo"`
}

// ComplianceSummary provides summary statistics.
type ComplianceSummary struct {
	TotalFindings    int                         `json:"totalFindings"`
	CriticalFindings int                         `json:"criticalFindings"`
	HighFindings     int                         `json:"highFindings"`
	MediumFindings   int                         `json:"mediumFindings"`
	LowFindings      int                         `json:"lowFindings"`
	PluginCount      int                         `json:"pluginCount"`
	Compliance       map[string]PluginCompliance `json:"compliance"`
}

// PluginCompliance represents compliance statistics for a single plugin.
type PluginCompliance struct {
	Compliant    int `json:"compliant"`
	NonCompliant int `json:"nonCompliant"`
	Total        int `json:"total"`
}

// PluginInfo contains metadata about a plugin.
type PluginInfo struct {
	Name        string           `json:"name"`
	Version     string           `json:"version"`
	Description string           `json:"description"`
	Controls    []plugin.Control `json:"controls"`
}

// GlobalRegistry is the global plugin registry instance.
//
//nolint:gochecknoglobals // Global registry for convenience functions
var GlobalRegistry *PluginRegistry

// Initialize the global registry.
func init() {
	GlobalRegistry = NewPluginRegistry()
}

// RegisterGlobalPlugin registers a plugin with the global registry.
func RegisterGlobalPlugin(p plugin.CompliancePlugin) error {
	return GlobalRegistry.RegisterPlugin(p)
}

// GetGlobalPlugin retrieves a plugin from the global registry.
func GetGlobalPlugin(name string) (plugin.CompliancePlugin, error) {
	return GlobalRegistry.GetPlugin(name)
}

// ListGlobalPlugins returns all plugins in the global registry.
func ListGlobalPlugins() []string {
	return GlobalRegistry.ListPlugins()
}
