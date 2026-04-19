// Package audit provides security audit functionality for OPNsense configurations against industry-standard compliance frameworks through a plugin-based architecture.
package audit

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	pluginlib "plugin"
	"runtime/debug"
	"slices"
	"strings"
	"sync"

	"github.com/EvilBit-Labs/opnDossier/internal/analysis"
	"github.com/EvilBit-Labs/opnDossier/internal/compliance"
	"github.com/EvilBit-Labs/opnDossier/internal/logging"
	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
)

// pluginLoaderFunc loads a compliance.Plugin from a shared object file path.
// It encapsulates the open → lookup → type-assert pipeline so that tests can
// inject a fake loader without requiring real .so files.
type pluginLoaderFunc func(path string) (compliance.Plugin, error)

// defaultPluginLoader is the production plugin loader that opens a .so file,
// looks up the exported "Plugin" symbol, and asserts it implements compliance.Plugin.
func defaultPluginLoader(path string) (compliance.Plugin, error) {
	p, err := pluginlib.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open %q: %w", path, err)
	}

	sym, err := p.Lookup("Plugin")
	if err != nil {
		return nil, fmt.Errorf("lookup Plugin in %q: %w", path, err)
	}

	// plugin.Lookup returns a pointer to the exported variable, not the value
	// itself. For `var Plugin compliance.Plugin`, sym is *compliance.Plugin.
	pSym, ok := sym.(*compliance.Plugin)
	if !ok {
		return nil, fmt.Errorf("symbol Plugin in %q is not *compliance.Plugin (got %T)", path, sym)
	}

	return *pSym, nil
}

// PluginRegistry manages the registration and retrieval of compliance plugins.
type PluginRegistry struct {
	plugins      map[string]compliance.Plugin
	mutex        sync.RWMutex
	pluginLoader pluginLoaderFunc
}

// NewPluginRegistry creates a new plugin registry with the default plugin loader.
func NewPluginRegistry() *PluginRegistry {
	return newPluginRegistryWithLoader(defaultPluginLoader)
}

// newPluginRegistryWithLoader creates a plugin registry with the given loader.
// This constructor is the single injection point for pluginLoader, ensuring
// the field is set exactly once at construction time. A nil loader defaults
// to defaultPluginLoader.
func newPluginRegistryWithLoader(loader pluginLoaderFunc) *PluginRegistry {
	if loader == nil {
		loader = defaultPluginLoader
	}

	return &PluginRegistry{
		plugins:      make(map[string]compliance.Plugin),
		pluginLoader: loader,
	}
}

// RegisterPlugin registers a compliance plugin.
func (pr *PluginRegistry) RegisterPlugin(p compliance.Plugin) error {
	pr.mutex.Lock()
	defer pr.mutex.Unlock()

	if err := p.ValidateConfiguration(); err != nil {
		return fmt.Errorf("plugin validation failed for %s: %w", p.Name(), err)
	}

	// Check if plugin is already registered
	if _, exists := pr.plugins[p.Name()]; exists {
		return fmt.Errorf("plugin %s is already registered", p.Name())
	}

	pr.plugins[p.Name()] = p

	return nil
}

// GetPlugin retrieves a plugin by name.
func (pr *PluginRegistry) GetPlugin(name string) (compliance.Plugin, error) {
	pr.mutex.RLock()
	defer pr.mutex.RUnlock()

	p, exists := pr.plugins[name]
	if !exists {
		return nil, compliance.ErrPluginNotFound
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

	slices.Sort(names)

	return names
}

// LoadDynamicPlugins loads .so plugins from the specified directory and registers them.
// When explicitDir is false, a missing directory is silently ignored (Debug log).
// When explicitDir is true, a missing directory returns an error because the user
// explicitly configured the path.
// A nil logger returns an error immediately.
// Per-plugin failures are collected in the returned LoadResult and aggregated into
// the returned error via errors.Join.
func (pr *PluginRegistry) LoadDynamicPlugins(
	_ context.Context,
	dir string,
	explicitDir bool,
	logger *logging.Logger,
) (LoadResult, error) {
	if logger == nil {
		return LoadResult{}, errors.New("nil logger provided to LoadDynamicPlugins")
	}

	ctxLogger := logger

	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			if explicitDir {
				return LoadResult{}, fmt.Errorf("plugin directory %q does not exist: %w", dir, err)
			}

			ctxLogger.Debug("Dynamic plugin directory does not exist", "dir", dir)

			return LoadResult{}, nil
		}

		ctxLogger.Error("Failed to read dynamic plugin directory", "dir", dir, "error", err)

		return LoadResult{}, fmt.Errorf("failed to read plugin directory %q: %w", dir, err)
	}

	var (
		loaded   int
		failures []PluginLoadError
	)

	for _, entry := range entries {
		if filepath.Ext(entry.Name()) != ".so" {
			continue
		}

		path := filepath.Join(dir, entry.Name())

		// Preflight hardening (see GOTCHAS §2.5 — Phase A): reject
		// symlinks, group/world-writable plugin files, group/world-writable
		// container directories, and non-absolute paths before plugin.Open
		// is ever called. A structured audit-log entry is emitted for every
		// attempt, accepted or rejected.
		preflight := runPluginPreflight(path)
		logPreflight(ctxLogger, preflight)

		if preflight.verdict != pluginVerdictAccepted {
			failures = append(failures, PluginLoadError{Name: entry.Name(), Err: preflight.err})

			continue
		}

		compliancePlugin, err := pr.pluginLoader(path)
		if err != nil {
			ctxLogger.Error("Failed to load plugin", "file", path, "error", err)
			failures = append(failures, PluginLoadError{Name: entry.Name(), Err: err})

			continue
		}

		if compliancePlugin == nil {
			nilErr := fmt.Errorf("loader returned nil plugin for %q", path)
			ctxLogger.Error("Failed to load plugin", "file", path, "error", nilErr)
			failures = append(failures, PluginLoadError{Name: entry.Name(), Err: nilErr})

			continue
		}

		if err := pr.RegisterPlugin(compliancePlugin); err != nil {
			ctxLogger.Error("Failed to register dynamic plugin", "file", path, "error", err)
			failures = append(
				failures,
				PluginLoadError{Name: entry.Name(), Err: fmt.Errorf("register %q: %w", path, err)},
			)

			continue
		}

		ctxLogger.Info(
			"Loaded dynamic plugin",
			"file",
			path,
			"name",
			compliancePlugin.Name(),
			"version",
			compliancePlugin.Version(),
		)

		loaded++
	}

	// Build aggregate error from individual failures.
	var aggregateErr error
	if len(failures) > 0 {
		errs := make([]error, len(failures))
		for i := range failures {
			errs[i] = failures[i]
		}

		aggregateErr = errors.Join(errs...)
	}

	return LoadResult{Loaded: loaded, Failures: failures}, aggregateErr
}

// RunComplianceChecks runs compliance checks for specified plugins.
// Each plugin's RunChecks call is wrapped in a panic recovery boundary so that
// a misbehaving (especially dynamically-loaded) plugin cannot crash the entire
// audit. Panicking plugins are logged and retained in the result with zero
// findings, ensuring downstream consumers can see they were requested and
// evaluated.
func (pr *PluginRegistry) RunComplianceChecks(
	device *common.CommonDevice,
	pluginNames []string,
	logger *logging.Logger,
) (*ComplianceResult, error) {
	if device == nil {
		return nil, ErrConfigurationNil
	}

	// Guard against nil logger so the recovery path never panics on a log call.
	if logger == nil {
		fallback, err := logging.New(logging.Config{Level: "info"})
		if err != nil {
			return nil, fmt.Errorf("failed to create fallback logger: %w", err)
		}

		logger = fallback
	}

	// Deduplicate plugin names to ensure consistent results across
	// aggregate findings and per-plugin maps.
	pluginNames = deduplicatePluginNames(pluginNames)

	result := &ComplianceResult{
		Findings:       []compliance.Finding{},
		PluginFindings: make(map[string][]compliance.Finding),
		Compliance:     make(map[string]map[string]bool),
		Summary:        &ComplianceSummary{},
		PluginInfo:     make(map[string]PluginInfo),
	}

	for _, pluginName := range pluginNames {
		p, err := pr.GetPlugin(pluginName)
		if err != nil {
			return nil, fmt.Errorf("failed to get plugin '%s': %w", pluginName, err)
		}

		// Run checks for this plugin inside a recovery boundary so that a
		// panicking plugin (especially a dynamically-loaded one) cannot crash
		// the entire audit process. On panic, findings/evaluated remain nil
		// and the plugin is retained in the result with zero findings.
		var (
			findings  []compliance.Finding
			evaluated []string
			runErr    error
			panicked  bool
		)

		func() {
			defer func() {
				if r := recover(); r != nil {
					panicked = true
					// Gate stack dumps behind verbose logging — function names
					// in stack traces can leak internal plugin paths (e.g.,
					// "acmecorp-pci-plugin.RunChecks") into centralized logs,
					// revealing a customer's compliance posture.
					if logger.IsVerbose() {
						logger.Error("plugin panicked during RunChecks",
							"plugin", pluginName,
							"panic", r,
							"stack", string(debug.Stack()),
						)
					} else {
						logger.Error("plugin panicked during RunChecks",
							"plugin", pluginName,
							"panic", r,
						)
					}
				}
			}()
			findings, evaluated, runErr = p.RunChecks(device)
		}()

		// When a plugin panicked, its internal state may be corrupt.
		// Use only the pluginName (already known) and skip method calls
		// that could trigger a secondary unrecovered panic.
		if panicked {
			result.PluginFindings[pluginName] = nil
			result.PluginInfo[pluginName] = PluginInfo{
				Name:    pluginName,
				Version: "unknown (panicked)",
			}
			result.Compliance[pluginName] = make(map[string]bool)

			continue
		}

		if runErr != nil {
			return nil, fmt.Errorf("plugin %q RunChecks failed: %w", pluginName, runErr)
		}

		// Normalize findings: derive missing Severity from control metadata
		for i := range findings {
			if findings[i].Severity == "" {
				severity, err := deriveSeverityFromControl(p, findings[i])
				if err != nil {
					return nil, fmt.Errorf("plugin %q produced invalid finding: %w", pluginName, err)
				}

				findings[i].Severity = severity
			}
		}

		result.PluginFindings[pluginName] = findings
		result.Findings = append(result.Findings, findings...)

		// Track plugin information. GetControls is contractually required to
		// return a defensive deep copy (see compliance.Plugin) so we assign it
		// directly without an additional CloneControls call — dropping the
		// historical double-clone on every audit.
		result.PluginInfo[pluginName] = PluginInfo{
			Name:        p.Name(),
			Version:     p.Version(),
			Description: p.Description(),
			Controls:    p.GetControls(),
		}

		// Initialize compliance tracking for this plugin.
		// Only controls the plugin can evaluate are initialized (to true/compliant).
		// Controls absent from the map are UNCONFIRMED — not evaluable from the
		// available configuration data.
		result.Compliance[pluginName] = make(map[string]bool, len(evaluated))
		for _, id := range evaluated {
			result.Compliance[pluginName][id] = true // Default evaluated controls to compliant
		}

		// Update compliance status based on findings — flip evaluated controls to false.
		// Inventory findings (Type: "inventory") are informational observations, not
		// compliance failures. Their referenced controls are not in the evaluated
		// slice and thus not in the compliance map, so the flip would be a no-op. We
		// skip them explicitly for clarity and to guard against accidental map pollution.
		for _, finding := range findings {
			if finding.Type == "inventory" {
				continue
			}

			for _, ref := range finding.References {
				if result.Compliance[pluginName] != nil {
					result.Compliance[pluginName][ref] = false // Non-compliant
				}
			}
		}
	}

	// Calculate summary. Surface unknown-severity findings (see GOTCHAS §2.4)
	// so operators notice plugins producing severities outside the known set.
	summary, unknownSeverityCount := pr.calculateSummary(result)
	result.Summary = summary

	if unknownSeverityCount > 0 {
		logger.Warn(
			"Compliance summary contains findings with unrecognized severity",
			"unknownCount", unknownSeverityCount,
		)
	}

	return result, nil
}

// deduplicatePluginNames normalizes names to lowercase and returns a new slice
// with duplicate names removed, preserving the order of first occurrence.
func deduplicatePluginNames(names []string) []string {
	seen := make(map[string]struct{}, len(names))
	unique := make([]string, 0, len(names))

	for _, name := range names {
		normalized := strings.ToLower(name)
		if _, exists := seen[normalized]; exists {
			continue
		}

		seen[normalized] = struct{}{}
		unique = append(unique, normalized)
	}

	return unique
}

// deriveSeverityFromControl resolves a finding's severity from the plugin's
// control definitions. It checks References first, then falls back to
// Reference. Returns an error if no referenced control has a non-empty severity.
func deriveSeverityFromControl(p compliance.Plugin, f compliance.Finding) (string, error) {
	// Collect all unresolved references for error reporting
	var unresolvedRefs []string

	// Try each reference in the finding
	for _, ref := range f.References {
		ctrl, err := p.GetControlByID(ref)
		if err == nil && ctrl.Severity != "" {
			normalized := strings.ToLower(ctrl.Severity)
			if !analysis.IsValidSeverity(analysis.Severity(normalized)) {
				return "", fmt.Errorf(
					"control %q has unrecognized severity %q",
					ref, ctrl.Severity,
				)
			}

			return normalized, nil
		}

		unresolvedRefs = append(unresolvedRefs, ref)
	}

	// Fall back to single Reference field
	if f.Reference != "" {
		ctrl, err := p.GetControlByID(f.Reference)
		if err == nil && ctrl.Severity != "" {
			normalized := strings.ToLower(ctrl.Severity)
			if !analysis.IsValidSeverity(analysis.Severity(normalized)) {
				return "", fmt.Errorf(
					"control %q has unrecognized severity %q",
					f.Reference, ctrl.Severity,
				)
			}

			return normalized, nil
		}

		// Only add if not already tracked via References
		if !slices.Contains(unresolvedRefs, f.Reference) {
			unresolvedRefs = append(unresolvedRefs, f.Reference)
		}
	}

	if len(unresolvedRefs) == 0 {
		return "", fmt.Errorf(
			"finding %q has no control references to derive severity from",
			f.Title,
		)
	}

	return "", fmt.Errorf(
		"finding %q references unresolved controls: [%s]",
		f.Title,
		strings.Join(unresolvedRefs, ", "),
	)
}

// Severity level constants for summary calculation, derived from the canonical
// analysis.Severity values.
const (
	severityCritical = string(analysis.SeverityCritical)
	severityHigh     = string(analysis.SeverityHigh)
	severityMedium   = string(analysis.SeverityMedium)
	severityLow      = string(analysis.SeverityLow)
	severityInfo     = string(analysis.SeverityInfo)
)

// severityCounts holds the result of tallying findings by severity level.
type severityCounts struct {
	critical int
	high     int
	medium   int
	low      int
	info     int
	unknown  int
}

// countSeverities tallies findings by severity level.
func countSeverities(findings []compliance.Finding) severityCounts {
	var counts severityCounts

	for _, finding := range findings {
		switch strings.ToLower(finding.Severity) {
		case severityCritical:
			counts.critical++
		case severityHigh:
			counts.high++
		case severityMedium:
			counts.medium++
		case severityLow:
			counts.low++
		case severityInfo:
			counts.info++
		default:
			counts.unknown++
		}
	}

	return counts
}

// calculateSummary calculates compliance summary statistics and returns the
// number of findings with unrecognized severity values so the caller can
// decide how to surface them (for example, a WARN log entry). Returning the
// count keeps `calculateSummary` free of logger dependencies and keeps the API
// testable.
//
//nolint:gocritic // unnamedResult retained; project-wide nonamedreturns disables the typical fix.
func (pr *PluginRegistry) calculateSummary(result *ComplianceResult) (*ComplianceSummary, int) {
	counts := countSeverities(result.Findings)

	summary := &ComplianceSummary{
		TotalFindings:    len(result.Findings),
		CriticalFindings: counts.critical,
		HighFindings:     counts.high,
		MediumFindings:   counts.medium,
		LowFindings:      counts.low,
		InfoFindings:     counts.info,
		PluginCount:      len(result.PluginInfo),
		Compliance:       make(map[string]PluginCompliance),
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

	return summary, counts.unknown
}

// computePerPluginSummary calculates compliance summary statistics for a single plugin.
func computePerPluginSummary(
	pluginName string,
	findings []compliance.Finding,
	complianceMap map[string]bool,
) *ComplianceSummary {
	counts := countSeverities(findings)

	summary := &ComplianceSummary{
		TotalFindings:    len(findings),
		CriticalFindings: counts.critical,
		HighFindings:     counts.high,
		MediumFindings:   counts.medium,
		LowFindings:      counts.low,
		InfoFindings:     counts.info,
		PluginCount:      1,
		Compliance:       make(map[string]PluginCompliance),
	}

	compliant := 0
	nonCompliant := 0

	for _, isCompliant := range complianceMap {
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

	return summary
}

// ComplianceResult represents the complete result of compliance checks.
type ComplianceResult struct {
	Findings       []compliance.Finding            `json:"findings"`
	PluginFindings map[string][]compliance.Finding `json:"pluginFindings"`
	Compliance     map[string]map[string]bool      `json:"compliance"`
	Summary        *ComplianceSummary              `json:"summary"`
	PluginInfo     map[string]PluginInfo           `json:"pluginInfo"`
}

// ComplianceSummary provides summary statistics.
type ComplianceSummary struct {
	TotalFindings    int                         `json:"totalFindings"`
	CriticalFindings int                         `json:"criticalFindings"`
	HighFindings     int                         `json:"highFindings"`
	MediumFindings   int                         `json:"mediumFindings"`
	LowFindings      int                         `json:"lowFindings"`
	InfoFindings     int                         `json:"infoFindings"`
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
	Name        string               `json:"name"`
	Version     string               `json:"version"`
	Description string               `json:"description"`
	Controls    []compliance.Control `json:"controls"`
}

// PluginLoadError records a single dynamic plugin that failed to load,
// capturing the .so filename and the underlying error.
// It implements the error interface for use with errors.Join.
type PluginLoadError struct {
	Name string
	Err  error
}

// Error returns a human-readable description of the load failure.
func (f PluginLoadError) Error() string {
	return fmt.Sprintf("plugin %s: %v", f.Name, f.Err)
}

// Unwrap returns the underlying error that caused the plugin load to fail.
// This allows consumers to use errors.Is and errors.As with PluginLoadError,
// including when these errors are combined via errors.Join.
func (f PluginLoadError) Unwrap() error {
	return f.Err
}

// LoadResult summarises the outcome of a LoadDynamicPlugins call, reporting
// how many plugins loaded successfully, how many failed, and the individual
// failure details. The zero value represents "no dynamic plugins attempted".
type LoadResult struct {
	Loaded   int
	Failures []PluginLoadError
}

// Failed returns the number of plugins that failed to load.
func (r LoadResult) Failed() int {
	return len(r.Failures)
}

// globalRegistry holds the (deprecated) singleton PluginRegistry instance, and
// globalRegistryOnce gates its one-time initialization.
//
// Deprecated: the global registry is retained only for backwards compatibility
// with a small number of tests that exercise the old singleton API. Production
// code must use NewPluginManager with an explicit *PluginRegistry (pass nil to
// allocate a private one). Scheduled for removal in v2.0. See todo #143.
//
// Thread-safety guarantee: sync.Once.Do(f) guarantees that all writes
// within f happen-before any call to Do returns (per the Go memory model,
// https://go.dev/ref/mem#once). The assignment of globalRegistry inside Do
// is therefore visible to every goroutine that subsequently calls
// GetGlobalRegistry() without additional synchronization.
//
//nolint:gochecknoglobals // Deprecated global registry retained for v2.0 removal.
var (
	globalRegistry     *PluginRegistry
	globalRegistryOnce sync.Once
)

// GetGlobalRegistry returns the (deprecated) global plugin registry singleton,
// initializing it on first access via sync.Once.
//
// Deprecated: use NewPluginManager with an explicit *PluginRegistry (pass nil
// to allocate a private one). The global registry is scheduled for removal in
// v2.0. New code must not depend on this function. See todo #143.
func GetGlobalRegistry() *PluginRegistry {
	globalRegistryOnce.Do(func() {
		globalRegistry = NewPluginRegistry()
	})
	return globalRegistry
}

// RegisterGlobalPlugin registers a compliance plugin with the (deprecated)
// global singleton registry.
//
// Deprecated: use NewPluginManager with an explicit *PluginRegistry and call
// RegisterPlugin on that instance directly. Scheduled for removal in v2.0.
// See todo #143.
func RegisterGlobalPlugin(p compliance.Plugin) error {
	return GetGlobalRegistry().RegisterPlugin(p)
}

// GetGlobalPlugin retrieves a plugin from the (deprecated) global registry.
//
// Deprecated: use NewPluginManager with an explicit *PluginRegistry and call
// GetPlugin on that instance directly. Scheduled for removal in v2.0.
// See todo #143.
func GetGlobalPlugin(name string) (compliance.Plugin, error) {
	return GetGlobalRegistry().GetPlugin(name)
}

// ListGlobalPlugins returns all plugins in the (deprecated) global registry.
//
// Deprecated: use NewPluginManager with an explicit *PluginRegistry and call
// ListPlugins on that instance directly. Scheduled for removal in v2.0.
// See todo #143.
func ListGlobalPlugins() []string {
	return GetGlobalRegistry().ListPlugins()
}
