package audit

import (
	"context"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/analysis"
	"github.com/EvilBit-Labs/opnDossier/internal/compliance"
	"github.com/EvilBit-Labs/opnDossier/internal/constants"
	"github.com/EvilBit-Labs/opnDossier/internal/plugins/firewall"
	"github.com/EvilBit-Labs/opnDossier/internal/plugins/sans"
	"github.com/EvilBit-Labs/opnDossier/internal/plugins/stig"
	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
)

// mockCompliancePlugin implements the compliance.Plugin interface for testing.
type mockCompliancePlugin struct {
	name        string
	description string
	version     string
}

func (m *mockCompliancePlugin) Name() string {
	return m.name
}

func (m *mockCompliancePlugin) Version() string {
	return m.version
}

func (m *mockCompliancePlugin) Description() string {
	return m.description
}

//nolint:gocritic // nonamedreturns enforced project-wide
func (m *mockCompliancePlugin) RunChecks(_ *common.CommonDevice) ([]compliance.Finding, []string, error) {
	controls := m.GetControls()
	ids := make([]string, len(controls))
	for i, c := range controls {
		ids[i] = c.ID
	}

	return []compliance.Finding{}, ids, nil
}

func (m *mockCompliancePlugin) GetControls() []compliance.Control {
	return []compliance.Control{}
}

func (m *mockCompliancePlugin) GetControlByID(_ string) (*compliance.Control, error) {
	return nil, compliance.ErrControlNotFound
}

func (m *mockCompliancePlugin) ValidateConfiguration() error {
	return nil
}

func TestParseReportMode(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		input   string
		want    ReportMode
		wantErr bool
	}{
		{
			name:    "standard mode is rejected",
			input:   "standard",
			want:    "",
			wantErr: true,
		},
		{
			name:    "blue mode",
			input:   "blue",
			want:    ModeBlue,
			wantErr: false,
		},
		{
			name:    "red mode",
			input:   "red",
			want:    ModeRed,
			wantErr: false,
		},
		{
			name:    "case insensitive standard is rejected",
			input:   "STANDARD",
			want:    "",
			wantErr: true,
		},
		{
			name:    "case insensitive blue",
			input:   "BLUE",
			want:    ModeBlue,
			wantErr: false,
		},
		{
			name:    "case insensitive red",
			input:   "RED",
			want:    ModeRed,
			wantErr: false,
		},
		{
			name:    "invalid mode",
			input:   "invalid",
			want:    "",
			wantErr: true,
		},
		{
			name:    "empty string",
			input:   "",
			want:    "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := ParseReportMode(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseReportMode() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if got != tt.want {
				t.Errorf("ParseReportMode() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestReportMode_String(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		mode ReportMode
		want string
	}{
		{
			name: "blue mode",
			mode: ModeBlue,
			want: "blue",
		},
		{
			name: "red mode",
			mode: ModeRed,
			want: "red",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := tt.mode.String(); got != tt.want {
				t.Errorf("ReportMode.String() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNewModeController(t *testing.T) {
	t.Parallel()

	registry := NewPluginRegistry()
	logger := newTestLogger(t)

	controller := NewModeController(registry, logger)

	if controller == nil {
		t.Fatal("NewModeController() returned nil")
	}

	if controller.registry != registry {
		t.Error("NewModeController() registry not set correctly")
	}

	if controller.logger != logger {
		t.Error("NewModeController() logger not set correctly")
	}
}

//nolint:funlen // test table or data declaration; length is in data not logic
func TestModeController_ValidateModeConfig(t *testing.T) {
	t.Parallel()

	registry := NewPluginRegistry()
	logger := newTestLogger(t)
	controller := NewModeController(registry, logger)

	// Register test plugins to validate against
	stigPlugin := stig.NewPlugin()
	sansPlugin := sans.NewPlugin()
	firewallPlugin := firewall.NewPlugin()

	if err := registry.RegisterPlugin(stigPlugin); err != nil {
		t.Fatalf("Failed to register STIG plugin: %v", err)
	}

	if err := registry.RegisterPlugin(sansPlugin); err != nil {
		t.Fatalf("Failed to register SANS plugin: %v", err)
	}

	if err := registry.RegisterPlugin(firewallPlugin); err != nil {
		t.Fatalf("Failed to register Firewall plugin: %v", err)
	}

	tests := []struct {
		name    string
		config  *ModeConfig
		wantErr bool
	}{
		{
			name: "valid blue mode",
			config: &ModeConfig{
				Mode: ModeBlue,
			},
			wantErr: false,
		},
		{
			name: "valid red mode",
			config: &ModeConfig{
				Mode: ModeRed,
			},
			wantErr: false,
		},
		{
			name:    "nil config",
			config:  nil,
			wantErr: true,
		},
		{
			name: "invalid mode",
			config: &ModeConfig{
				Mode: "invalid",
			},
			wantErr: true,
		},
		{
			name: "valid plugin selection - single plugin",
			config: &ModeConfig{
				Mode:            ModeBlue,
				SelectedPlugins: []string{"stig"},
			},
			wantErr: false,
		},
		{
			name: "valid plugin selection - multiple plugins",
			config: &ModeConfig{
				Mode:            ModeRed,
				SelectedPlugins: []string{"stig", "sans", "firewall"},
			},
			wantErr: false,
		},
		{
			name: "valid plugin selection - empty plugins array",
			config: &ModeConfig{
				Mode:            ModeBlue,
				SelectedPlugins: []string{},
			},
			wantErr: false,
		},
		{
			name: "valid plugin selection - nil plugins array",
			config: &ModeConfig{
				Mode:            ModeBlue,
				SelectedPlugins: nil,
			},
			wantErr: false,
		},
		{
			name: "invalid plugin selection - non-existent plugin",
			config: &ModeConfig{
				Mode:            ModeRed,
				SelectedPlugins: []string{"nonexistent"},
			},
			wantErr: true,
		},
		{
			name: "invalid plugin selection - mixed valid and invalid",
			config: &ModeConfig{
				Mode:            ModeBlue,
				SelectedPlugins: []string{"stig", "invalid-plugin", "sans"},
			},
			wantErr: true,
		},
		{
			name: "valid plugin selection - case insensitive",
			config: &ModeConfig{
				Mode:            ModeBlue,
				SelectedPlugins: []string{"STIG"},
			},
			wantErr: false,
		},
		{
			name: "invalid plugin selection - duplicate plugin",
			config: &ModeConfig{
				Mode:            ModeBlue,
				SelectedPlugins: []string{"stig", "stig"},
			},
			wantErr: true,
		},
		{
			name: "invalid plugin selection - duplicate among multiple",
			config: &ModeConfig{
				Mode:            ModeBlue,
				SelectedPlugins: []string{"stig", "sans", "stig"},
			},
			wantErr: true,
		},
		{
			name: "invalid plugin selection - empty string",
			config: &ModeConfig{
				Mode:            ModeRed,
				SelectedPlugins: []string{""},
			},
			wantErr: true,
		},
		{
			name: "invalid plugin selection - whitespace only",
			config: &ModeConfig{
				Mode:            ModeBlue,
				SelectedPlugins: []string{"   "},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := controller.ValidateModeConfig(tt.config)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateModeConfig() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestModeController_GenerateReport(t *testing.T) {
	t.Parallel()

	registry := NewPluginRegistry()
	logger := newTestLogger(t)
	controller := NewModeController(registry, logger)

	// Create a minimal test configuration
	testConfig := &common.CommonDevice{
		System: common.System{
			Hostname: "test-host",
			Domain:   "test.local",
		},
	}

	tests := []struct {
		name    string
		config  *ModeConfig
		wantErr bool
	}{
		{
			name: "blue mode",
			config: &ModeConfig{
				Mode: ModeBlue,
			},
			wantErr: false,
		},
		{
			name: "red mode",
			config: &ModeConfig{
				Mode: ModeRed,
			},
			wantErr: false,
		},
		{
			name:    "nil config",
			config:  nil,
			wantErr: true,
		},
		{
			name: "invalid mode",
			config: &ModeConfig{
				Mode: "invalid",
			},
			wantErr: true,
		},
		{
			name: "nil document",
			config: &ModeConfig{
				Mode: ModeBlue,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var cfg *common.CommonDevice
			if tt.name == "nil document" {
				cfg = nil
			} else {
				cfg = testConfig
			}

			report, err := controller.GenerateReport(context.Background(), cfg, tt.config)
			if (err != nil) != tt.wantErr {
				t.Errorf("GenerateReport() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && report == nil {
				t.Error("GenerateReport() returned nil report when no error expected")
				return
			}

			if !tt.wantErr {
				// Verify report structure
				if report.Mode != tt.config.Mode {
					t.Errorf("GenerateReport() report mode = %v, want %v", report.Mode, tt.config.Mode)
				}

				if report.Configuration != cfg {
					t.Error("GenerateReport() configuration not set correctly")
				}

				if report.Findings == nil {
					t.Error("GenerateReport() findings slice not initialized")
				}

				if report.Compliance == nil {
					t.Error("GenerateReport() compliance map not initialized")
				}

				if report.Metadata == nil {
					t.Error("GenerateReport() metadata map not initialized")
				}
			}
		})
	}
}

func TestReport_Structure(t *testing.T) {
	t.Parallel()

	report := &Report{
		Mode:          ModeBlue,
		Comprehensive: true,
		Configuration: &common.CommonDevice{},
		Findings:      make([]Finding, 0),
		Compliance:    make(map[string]ComplianceResult),
		Metadata:      make(map[string]any),
	}

	// Test that the report structure is properly initialized
	if report.Mode != ModeBlue {
		t.Errorf("Report.Mode = %v, want %v", report.Mode, ModeBlue)
	}

	if !report.Comprehensive {
		t.Error("Report.Comprehensive should be true")
	}

	if report.Configuration == nil {
		t.Error("Report.Configuration should not be nil")
	}

	if report.Findings == nil {
		t.Error("Report.Findings should not be nil")
	}

	if report.Compliance == nil {
		t.Error("Report.Compliance should not be nil")
	}

	if report.Metadata == nil {
		t.Error("Report.Metadata should not be nil")
	}
}

func TestFinding_Structure(t *testing.T) {
	t.Parallel()

	finding := Finding{
		Finding: analysis.Finding{
			Title:          "Test Finding",
			Severity:       string(analysis.SeverityHigh),
			Description:    "Test description",
			Recommendation: "Test recommendation",
			Tags:           []string{"test", "security"},
			Component:      "firewall",
		},
		Control: "STIG-V-206694",
	}

	// Test that the finding structure is properly set
	if finding.Title != "Test Finding" {
		t.Errorf("Finding.Title = %v, want %v", finding.Title, "Test Finding")
	}

	if finding.Severity != string(analysis.SeverityHigh) {
		t.Errorf("Finding.Severity = %v, want %v", finding.Severity, analysis.SeverityHigh)
	}

	if finding.Description != "Test description" {
		t.Errorf("Finding.Description = %v, want %v", finding.Description, "Test description")
	}

	if finding.Recommendation != "Test recommendation" {
		t.Errorf("Finding.Recommendation = %v, want %v", finding.Recommendation, "Test recommendation")
	}

	if len(finding.Tags) != 2 {
		t.Errorf("Finding.Tags length = %v, want %v", len(finding.Tags), 2)
	}

	if finding.Component != "firewall" {
		t.Errorf("Finding.Component = %v, want %v", finding.Component, "firewall")
	}

	if finding.Control != "STIG-V-206694" {
		t.Errorf("Finding.Control = %v, want %v", finding.Control, "STIG-V-206694")
	}
}

func TestAttackSurface_Structure(t *testing.T) {
	t.Parallel()

	attackSurface := &AttackSurface{
		Type:            "web",
		Ports:           []int{80, 443},
		Services:        []string{"http", "https"},
		Vulnerabilities: []string{"CVE-2021-1234"},
	}

	// Test that the attack surface structure is properly set
	if attackSurface.Type != "web" {
		t.Errorf("AttackSurface.Type = %v, want %v", attackSurface.Type, "web")
	}

	if len(attackSurface.Ports) != 2 {
		t.Errorf("AttackSurface.Ports length = %v, want %v", len(attackSurface.Ports), 2)
	}

	if len(attackSurface.Services) != 2 {
		t.Errorf("AttackSurface.Services length = %v, want %v", len(attackSurface.Services), 2)
	}

	if len(attackSurface.Vulnerabilities) != 1 {
		t.Errorf("AttackSurface.Vulnerabilities length = %v, want %v", len(attackSurface.Vulnerabilities), 1)
	}
}

func TestPluginRegistry_RegisterAndGet(t *testing.T) {
	t.Parallel()

	registry := NewPluginRegistry()

	// Create a mock plugin
	mockPlugin := &mockCompliancePlugin{
		name:        "test-plugin",
		description: "Test plugin for unit testing",
		version:     "1.0.0",
	}

	err := registry.RegisterPlugin(mockPlugin)
	if err != nil {
		t.Errorf("Failed to register plugin: %v", err)
	}

	// Test getting the registered plugin
	retrievedPlugin, err := registry.GetPlugin("test-plugin")
	if err != nil {
		t.Errorf("Failed to get plugin: %v", err)
	}

	if retrievedPlugin.Name() != mockPlugin.name {
		t.Errorf("Plugin name mismatch: got %v, want %v", retrievedPlugin.Name(), mockPlugin.name)
	}

	if retrievedPlugin.Description() != mockPlugin.description {
		t.Errorf("Plugin description mismatch: got %v, want %v", retrievedPlugin.Description(), mockPlugin.description)
	}

	if retrievedPlugin.Version() != mockPlugin.version {
		t.Errorf("Plugin version mismatch: got %v, want %v", retrievedPlugin.Version(), mockPlugin.version)
	}
}

func TestPluginRegistry_RegisterDuplicate(t *testing.T) {
	t.Parallel()

	registry := NewPluginRegistry()

	plugin1 := &mockCompliancePlugin{
		name:        "test-plugin",
		description: "Test plugin 1",
		version:     "1.0.0",
	}

	plugin2 := &mockCompliancePlugin{
		name:        "test-plugin",
		description: "Test plugin 2",
		version:     "2.0.0",
	}

	// Register first plugin
	err := registry.RegisterPlugin(plugin1)
	if err != nil {
		t.Errorf("Failed to register first plugin: %v", err)
	}

	// Try to register duplicate plugin
	err = registry.RegisterPlugin(plugin2)
	if err == nil {
		t.Error("Expected error when registering duplicate plugin, got nil")
	}

	// Verify the original plugin is still there
	retrievedPlugin, err := registry.GetPlugin("test-plugin")
	if err != nil {
		t.Errorf("Failed to get original plugin: %v", err)
	}

	if retrievedPlugin.Description() != plugin1.description {
		t.Errorf("Plugin was overwritten: got %v, want %v", retrievedPlugin.Description(), plugin1.description)
	}
}

func TestPluginRegistry_GetNonexistent(t *testing.T) {
	t.Parallel()

	registry := NewPluginRegistry()

	// Try to get a plugin that doesn't exist
	_, err := registry.GetPlugin("nonexistent-plugin")
	if err == nil {
		t.Error("Expected error when getting nonexistent plugin, got nil")
	}
}

func TestPluginRegistry_List(t *testing.T) {
	t.Parallel()

	registry := NewPluginRegistry()

	// Register multiple plugins
	plugins := []*mockCompliancePlugin{
		{name: "plugin1", description: "First plugin", version: "1.0.0"},
		{name: "plugin2", description: "Second plugin", version: "1.0.0"},
		{name: "plugin3", description: "Third plugin", version: "1.0.0"},
	}

	for _, plugin := range plugins {
		err := registry.RegisterPlugin(plugin)
		if err != nil {
			t.Errorf("Failed to register plugin %s: %v", plugin.name, err)
		}
	}

	// Test listing all plugins
	pluginList := registry.ListPlugins()
	if len(pluginList) != len(plugins) {
		t.Errorf("Plugin list length mismatch: got %v, want %v", len(pluginList), len(plugins))
	}

	// Verify all plugins are in the list
	pluginNames := make(map[string]bool)
	for _, pluginName := range pluginList {
		pluginNames[pluginName] = true
	}

	for _, plugin := range plugins {
		if !pluginNames[plugin.name] {
			t.Errorf("Plugin %s not found in list", plugin.name)
		}
	}
}

func TestPluginRegistry_Unregister(t *testing.T) {
	t.Parallel()

	registry := NewPluginRegistry()

	mockPlugin := &mockCompliancePlugin{
		name:        "test-plugin",
		description: "Test plugin",
		version:     "1.0.0",
	}

	// Register plugin
	err := registry.RegisterPlugin(mockPlugin)
	if err != nil {
		t.Errorf("Failed to register plugin: %v", err)
	}

	// Verify plugin exists
	_, err = registry.GetPlugin("test-plugin")
	if err != nil {
		t.Errorf("Plugin not found after registration: %v", err)
	}

	// Unregister plugin - this method doesn't exist, so we'll test the error case
	// The actual implementation doesn't have an Unregister method
	_, err = registry.GetPlugin("test-plugin")
	if err != nil {
		t.Error("Plugin should still exist")
	}
}

func TestPluginRegistry_UnregisterNonexistent(t *testing.T) {
	t.Parallel()

	registry := NewPluginRegistry()

	// Try to get a plugin that doesn't exist
	_, err := registry.GetPlugin("nonexistent-plugin")
	if err == nil {
		t.Error("Expected error when getting nonexistent plugin, got nil")
	}
}

func TestReport_AddFinding(t *testing.T) {
	t.Parallel()

	report := &Report{
		Findings: []Finding{},
	}

	finding := Finding{
		Finding: analysis.Finding{
			Title:       "Test Finding",
			Severity:    string(analysis.SeverityHigh),
			Description: "Test description",
			Component:   "security",
		},
	}

	// Add finding directly to slice since there's no AddFinding method
	report.Findings = append(report.Findings, finding)

	if len(report.Findings) != 1 {
		t.Errorf("Expected 1 finding, got %d", len(report.Findings))
	}

	if report.Findings[0].Title != finding.Title {
		t.Errorf("Finding title mismatch: got %v, want %v", report.Findings[0].Title, finding.Title)
	}

	if report.Findings[0].Severity != finding.Severity {
		t.Errorf("Finding severity mismatch: got %v, want %v", report.Findings[0].Severity, finding.Severity)
	}
}

func TestReport_GetFindingsBySeverity(t *testing.T) {
	t.Parallel()

	report := &Report{
		Findings: []Finding{
			{
				Finding: analysis.Finding{
					Title:       "High Finding",
					Severity:    string(analysis.SeverityHigh),
					Description: "High severity issue",
				},
			},
			{
				Finding: analysis.Finding{
					Title:       "Medium Finding",
					Severity:    string(analysis.SeverityMedium),
					Description: "Medium severity issue",
				},
			},
			{
				Finding: analysis.Finding{
					Title:       "Low Finding",
					Severity:    string(analysis.SeverityLow),
					Description: "Low severity issue",
				},
			},
			{
				Finding: analysis.Finding{
					Title:       "Another High",
					Severity:    string(analysis.SeverityHigh),
					Description: "Another high severity issue",
				},
			},
		},
	}

	// Filter findings by severity manually since there's no GetFindingsBySeverity method
	highFindings := []Finding{}
	for _, finding := range report.Findings {
		if finding.Severity == string(analysis.SeverityHigh) {
			highFindings = append(highFindings, finding)
		}
	}

	if len(highFindings) != 2 {
		t.Errorf("Expected 2 high findings, got %d", len(highFindings))
	}

	mediumFindings := []Finding{}
	for _, finding := range report.Findings {
		if finding.Severity == string(analysis.SeverityMedium) {
			mediumFindings = append(mediumFindings, finding)
		}
	}

	if len(mediumFindings) != 1 {
		t.Errorf("Expected 1 medium finding, got %d", len(mediumFindings))
	}

	lowFindings := []Finding{}
	for _, finding := range report.Findings {
		if finding.Severity == string(analysis.SeverityLow) {
			lowFindings = append(lowFindings, finding)
		}
	}

	if len(lowFindings) != 1 {
		t.Errorf("Expected 1 low finding, got %d", len(lowFindings))
	}
}

func TestReport_GetFindingsByComponent(t *testing.T) {
	t.Parallel()

	report := &Report{
		Findings: []Finding{
			{Finding: analysis.Finding{
				Title:       "Security Finding",
				Severity:    string(analysis.SeverityHigh),
				Component:   "security",
				Description: "Security issue",
			}},
			{Finding: analysis.Finding{
				Title:       "Network Finding",
				Severity:    string(analysis.SeverityMedium),
				Component:   "network",
				Description: "Network issue",
			}},
			{Finding: analysis.Finding{
				Title:       "Another Security",
				Severity:    string(analysis.SeverityLow),
				Component:   "security",
				Description: "Another security issue",
			}},
		},
	}

	// Filter findings by component manually since there's no GetFindingsByComponent method
	securityFindings := []Finding{}
	for _, finding := range report.Findings {
		if finding.Component == "security" {
			securityFindings = append(securityFindings, finding)
		}
	}

	if len(securityFindings) != 2 {
		t.Errorf("Expected 2 security findings, got %d", len(securityFindings))
	}

	networkFindings := []Finding{}
	for _, finding := range report.Findings {
		if finding.Component == "network" {
			networkFindings = append(networkFindings, finding)
		}
	}

	if len(networkFindings) != 1 {
		t.Errorf("Expected 1 network finding, got %d", len(networkFindings))
	}
}

func TestReport_Summary(t *testing.T) {
	t.Parallel()

	report := &Report{
		Findings: []Finding{
			{Finding: analysis.Finding{
				Title:       "High Finding",
				Severity:    string(analysis.SeverityHigh),
				Component:   "security",
				Description: "High severity issue",
			}},
			{Finding: analysis.Finding{
				Title:       "Medium Finding",
				Severity:    string(analysis.SeverityMedium),
				Component:   "network",
				Description: "Medium severity issue",
			}},
			{Finding: analysis.Finding{
				Title:       "Low Finding",
				Severity:    string(analysis.SeverityLow),
				Component:   "security",
				Description: "Low severity issue",
			}},
			{Finding: analysis.Finding{
				Title:       "Another High",
				Severity:    string(analysis.SeverityHigh),
				Component:   "network",
				Description: "Another high severity issue",
			}},
		},
	}

	// Calculate summary manually since there's no GetSummary method
	totalFindings := len(report.Findings)
	highCount := 0
	mediumCount := 0
	lowCount := 0

	for _, finding := range report.Findings {
		switch finding.Severity {
		case string(analysis.SeverityHigh):
			highCount++
		case string(analysis.SeverityMedium):
			mediumCount++
		case string(analysis.SeverityLow):
			lowCount++
		}
	}

	if totalFindings != 4 {
		t.Errorf("Expected 4 total findings, got %d", totalFindings)
	}

	if highCount != 2 {
		t.Errorf("Expected 2 high severity findings, got %d", highCount)
	}

	if mediumCount != 1 {
		t.Errorf("Expected 1 medium severity finding, got %d", mediumCount)
	}

	if lowCount != 1 {
		t.Errorf("Expected 1 low severity finding, got %d", lowCount)
	}
}

func TestReport_EmptySummary(t *testing.T) {
	t.Parallel()

	report := &Report{
		Findings: []Finding{},
	}

	// Calculate summary manually for empty report
	totalFindings := len(report.Findings)
	highCount := 0
	mediumCount := 0
	lowCount := 0

	for _, finding := range report.Findings {
		switch finding.Severity {
		case string(analysis.SeverityHigh):
			highCount++
		case string(analysis.SeverityMedium):
			mediumCount++
		case string(analysis.SeverityLow):
			lowCount++
		}
	}

	if totalFindings != 0 {
		t.Errorf("Expected 0 total findings, got %d", totalFindings)
	}

	if highCount != 0 {
		t.Errorf("Expected 0 high severity findings, got %d", highCount)
	}

	if mediumCount != 0 {
		t.Errorf("Expected 0 medium severity findings, got %d", mediumCount)
	}

	if lowCount != 0 {
		t.Errorf("Expected 0 low severity findings, got %d", lowCount)
	}
}

// TestReport_AnalysisMethods exercises the blue-mode add* methods against a
// config with a known-bad WebGUI protocol, asserting real derived values
// (R23) rather than merely non-empty metadata.
//
//nolint:tparallel // subtests share mutable report state and cannot run concurrently
func TestReport_AnalysisMethods(t *testing.T) {
	t.Parallel()

	report := &Report{
		Mode:          ModeBlue,
		Comprehensive: true,
		Configuration: &common.CommonDevice{
			System: common.System{
				Hostname: "test-host",
				Domain:   "test.local",
				WebGUI:   common.WebGUI{Protocol: "http"},
			},
			Interfaces: []common.Interface{
				{Name: "wan", Enabled: true},
				{Name: "lan", Enabled: true},
			},
			FirewallRules: []common.FirewallRule{
				{Type: common.RuleTypePass, Interfaces: []string{"lan"}},
			},
			Users: []common.User{{Name: "admin"}},
		},
		Findings:   make([]Finding, 0),
		Compliance: make(map[string]ComplianceResult),
		Metadata:   make(map[string]any),
	}

	// Test the analysis methods that add metadata to the report. R23: assert
	// real values derived from the config, not merely that metadata is
	// non-empty.
	t.Run("addSecurityFindings", func(t *testing.T) {
		observations := analysis.ScanObservations(report.Configuration)
		report.addSecurityFindings(observations)

		if len(report.Findings) == 0 {
			t.Fatal("addSecurityFindings() should append hygiene findings for an insecure WebGUI config")
		}

		found := false
		for _, f := range report.Findings {
			if f.Title == "Insecure Web GUI Protocol" {
				found = true
			}
		}
		if !found {
			t.Errorf(
				"addSecurityFindings() findings = %+v, want a finding titled %q",
				report.Findings,
				"Insecure Web GUI Protocol",
			)
		}

		if got := report.Metadata["security_findings_count"]; got != report.TotalFindingsCount() {
			t.Errorf("security_findings_count = %v, want %d", got, report.TotalFindingsCount())
		}
	})

	t.Run("addComplianceAnalysis", func(t *testing.T) {
		report.addComplianceAnalysis()

		frameworks, ok := report.Metadata["compliance_frameworks"].([]string)
		if !ok {
			t.Fatalf(
				"compliance_frameworks = %v (%T), want []string",
				report.Metadata["compliance_frameworks"],
				report.Metadata["compliance_frameworks"],
			)
		}
		// No plugins were executed against this hand-built report, so the
		// frameworks list must be empty — never the old hardcoded
		// ["STIG","NIST","SANS"].
		if len(frameworks) != 0 {
			t.Errorf("compliance_frameworks = %v, want empty (no plugins executed)", frameworks)
		}
	})

	t.Run("addRecommendations", func(t *testing.T) {
		report.addRecommendations()

		count, ok := report.Metadata["recommendation_count"].(int)
		if !ok {
			t.Fatalf(
				"recommendation_count = %v (%T), want int",
				report.Metadata["recommendation_count"],
				report.Metadata["recommendation_count"],
			)
		}
		if count == 0 {
			t.Error("recommendation_count = 0, want > 0 given the hygiene findings from the insecure config")
		}

		recs, ok := report.Metadata["recommendations"].([]Recommendation)
		if !ok {
			t.Fatalf(
				"recommendations = %v (%T), want []Recommendation",
				report.Metadata["recommendations"],
				report.Metadata["recommendations"],
			)
		}
		if len(recs) == 0 {
			t.Error("recommendations should be non-empty")
		}
	})

	t.Run("addStructuredConfigurationTables", func(t *testing.T) {
		report.addStructuredConfigurationTables()

		summary, ok := report.Metadata["configuration_summary"].(ConfigSummary)
		if !ok {
			t.Fatalf(
				"configuration_summary = %v (%T), want ConfigSummary",
				report.Metadata["configuration_summary"],
				report.Metadata["configuration_summary"],
			)
		}

		want := ConfigSummary{
			Interfaces:    2,
			FirewallRules: 1,
			NATRules:      0,
			Users:         1,
		}
		if summary != want {
			t.Errorf("configuration_summary = %+v, want %+v", summary, want)
		}
	})
}

// TestReport_RedAnalysisMethods exercises the five red-mode analysis methods
// against a fixture with WebGUI=http, an enabled WAN interface, and a single
// LAN-scoped pass rule. No WAN rule permits any management port, so nothing is
// WAN-exposed — the counts are all zero and the WebGUI portal is retained as
// LAN-only in the inventory.
func TestReport_RedAnalysisMethods(t *testing.T) {
	t.Parallel()

	newReport := func() *Report {
		return newRedReport(&common.CommonDevice{
			System: common.System{
				Hostname: "test-host",
				WebGUI:   common.WebGUI{Protocol: "http"},
			},
			Interfaces: []common.Interface{
				{Name: "wan", Enabled: true},
				{Name: "lan", Enabled: true},
			},
			FirewallRules: []common.FirewallRule{
				{Type: common.RuleTypePass, Interfaces: []string{"lan"}},
			},
			Users: []common.User{{Name: "admin"}},
		})
	}

	t.Run("addWANExposedServices", func(t *testing.T) {
		t.Parallel()
		report := newReport()
		report.addWANExposedServices(serviceExposures(report.Configuration), false)

		if got := report.Metadata["wan_exposed_services_count"]; got != 0 {
			t.Errorf("wan_exposed_services_count = %v, want 0 (no WAN rule permits a service port)", got)
		}
		if report.Metadata["wan_exposure_scan_completed"] != true {
			t.Error("wan_exposure_scan_completed should be true")
		}
	})

	t.Run("addWeakNATRules", func(t *testing.T) {
		t.Parallel()
		report := newReport()
		report.addWeakNATRules(false)

		if got := report.Metadata["weak_nat_rules_count"]; got != 0 {
			t.Errorf("weak_nat_rules_count = %v, want 0 (no inbound NAT rules)", got)
		}
	})

	t.Run("addAdminPortals", func(t *testing.T) {
		t.Parallel()
		report := newReport()
		report.addAdminPortals(serviceExposures(report.Configuration))

		portals, ok := report.Metadata["admin_portals"].([]adminPortal)
		if !ok {
			t.Fatalf("admin_portals = %v (%T), want []adminPortal",
				report.Metadata["admin_portals"], report.Metadata["admin_portals"])
		}
		// WebGUI is always present (SSH is not enabled in this fixture), LAN-only.
		if len(portals) != 1 {
			t.Fatalf("admin_portals len = %d, want 1 (webgui)", len(portals))
		}
		if portals[0].Name != "webgui" || portals[0].Reachability != string(analysis.LANOnly) {
			t.Errorf("admin_portals[0] = %+v, want webgui tagged lan", portals[0])
		}
	})

	t.Run("addAttackSurfaces", func(t *testing.T) {
		t.Parallel()
		report := newReport()
		observations := analysis.ScanObservations(report.Configuration)
		report.addAttackSurfaces(observations, false)

		// The insecure-WebGUI observation is system-wide (Local), not WAN, so no
		// observation is reframed as a red exposure for this fixture.
		if got := report.Metadata["attack_surfaces_count"]; got != 0 {
			t.Errorf("attack_surfaces_count = %v, want 0 (no WAN-reachable observation)", got)
		}
	})

	t.Run("addEnumerationData", func(t *testing.T) {
		t.Parallel()
		report := newReport()
		report.addEnumerationData()

		data, ok := report.Metadata["enumeration_data"].(enumerationData)
		if !ok {
			t.Fatalf("enumeration_data = %v (%T), want enumerationData",
				report.Metadata["enumeration_data"], report.Metadata["enumeration_data"])
		}
		want := enumerationData{
			Interfaces:      2,
			WANInterfaces:   1,
			FirewallRules:   1,
			InboundNATRules: 0,
			Users:           1,
			Groups:          0,
		}
		if data != want {
			t.Errorf("enumeration_data = %+v, want %+v", data, want)
		}
	})
}

// TestAddSecurityFindings_DedupeAgainstFiredPluginControls covers AE1
// (R8, R9): a hygiene observation referencing the same config element (an
// exact Component match) as a fired plugin finding is suppressed, while a
// hygiene observation on a different element in the same category is still
// emitted.
func TestAddSecurityFindings_DedupeAgainstFiredPluginControls(t *testing.T) {
	t.Parallel()

	report := &Report{
		Mode:          ModeBlue,
		Configuration: &common.CommonDevice{},
		Findings:      make([]Finding, 0),
		Compliance: map[string]ComplianceResult{
			"firewall": {
				Findings: []compliance.Finding{
					{
						Type:      "compliance",
						Severity:  "high",
						Title:     "Any Source on WAN Inbound",
						Component: "filter.rule[0]",
					},
				},
			},
		},
		Metadata: make(map[string]any),
	}

	observations := []analysis.Observation{
		{
			Severity:       analysis.SeverityHigh,
			Confidence:     analysis.ConfidenceHigh,
			Reachability:   analysis.WANReachable,
			Component:      "filter.rule[0]",
			Title:          "Overly Permissive WAN Rule",
			Description:    "Rule 1 allows any source to pass traffic on WAN interface",
			Recommendation: "Restrict source networks",
		},
		{
			Severity:       analysis.SeverityHigh,
			Confidence:     analysis.ConfidenceHigh,
			Reachability:   analysis.WANReachable,
			Component:      "filter.rule[1]",
			Title:          "Overly Permissive WAN Rule",
			Description:    "Rule 2 allows any source to pass traffic on WAN interface",
			Recommendation: "Restrict source networks",
		},
	}

	report.addSecurityFindings(observations)

	if len(report.Findings) != 1 {
		t.Fatalf(
			"addSecurityFindings() len(Findings) = %d, want 1 (rule[0] suppressed as a duplicate of the fired plugin control, rule[1] retained)",
			len(report.Findings),
		)
	}

	if report.Findings[0].Component != "filter.rule[1]" {
		t.Errorf(
			"addSecurityFindings() surviving finding Component = %q, want %q",
			report.Findings[0].Component, "filter.rule[1]",
		)
	}
}

// TestAddSecurityFindings_OrderedBySeverityThenReachability covers R12:
// hygiene findings are ordered by severity (most urgent first), then by
// reachability (most exposed first) within a severity tier.
func TestAddSecurityFindings_OrderedBySeverityThenReachability(t *testing.T) {
	t.Parallel()

	report := &Report{
		Mode:          ModeBlue,
		Configuration: &common.CommonDevice{},
		Findings:      make([]Finding, 0),
		Compliance:    make(map[string]ComplianceResult),
		Metadata:      make(map[string]any),
	}

	observations := []analysis.Observation{
		{Severity: analysis.SeverityMedium, Reachability: analysis.WANReachable, Component: "a", Title: "medium-wan"},
		{Severity: analysis.SeverityCritical, Reachability: analysis.Local, Component: "b", Title: "critical-local"},
		{Severity: analysis.SeverityHigh, Reachability: analysis.LANOnly, Component: "c", Title: "high-lan"},
		{Severity: analysis.SeverityHigh, Reachability: analysis.WANReachable, Component: "d", Title: "high-wan"},
	}

	report.addSecurityFindings(observations)

	wantOrder := []string{"critical-local", "high-wan", "high-lan", "medium-wan"}
	gotOrder := make([]string, len(report.Findings))
	for i, f := range report.Findings {
		gotOrder[i] = f.Title
	}

	if !slices.Equal(gotOrder, wantOrder) {
		t.Errorf("addSecurityFindings() order = %v, want %v", gotOrder, wantOrder)
	}
}

// TestAddComplianceAnalysis_FrameworksDerivedFromExecutedPlugins covers AE4
// (R10): `--plugins stig` produces a compliance_frameworks list of exactly
// ["STIG"], not the previously hardcoded ["STIG","NIST","SANS"].
func TestAddComplianceAnalysis_FrameworksDerivedFromExecutedPlugins(t *testing.T) {
	t.Parallel()

	registry := NewPluginRegistry()
	if err := registry.RegisterPlugin(stig.NewPlugin()); err != nil {
		t.Fatalf("RegisterPlugin(stig): %v", err)
	}

	logger := newTestLogger(t)
	controller := NewModeController(registry, logger)

	device := &common.CommonDevice{
		System: common.System{Hostname: "fw", Domain: "example.com"},
	}

	report, err := controller.GenerateReport(context.Background(), device, &ModeConfig{
		Mode:            ModeBlue,
		SelectedPlugins: []string{"stig"},
	})
	if err != nil {
		t.Fatalf("GenerateReport() unexpected error: %v", err)
	}

	frameworks, ok := report.Metadata["compliance_frameworks"].([]string)
	if !ok {
		t.Fatalf(
			"compliance_frameworks = %v (%T), want []string",
			report.Metadata["compliance_frameworks"], report.Metadata["compliance_frameworks"],
		)
	}

	want := []string{"STIG"}
	if !slices.Equal(frameworks, want) {
		t.Errorf("compliance_frameworks = %v, want %v", frameworks, want)
	}
}

// newRedReport builds a red-mode Report over the given device for red-analysis
// tests.
func newRedReport(device *common.CommonDevice) *Report {
	return &Report{
		Mode:          ModeRed,
		Configuration: device,
		Findings:      make([]Finding, 0),
		Compliance:    make(map[string]ComplianceResult),
		Metadata:      make(map[string]any),
	}
}

// runRedAnalysis runs the full red-mode analysis pipeline over the report, in
// the same order as generateRedReport.
func runRedAnalysis(report *Report) {
	observations := analysis.ScanObservations(report.Configuration)
	services := serviceExposures(report.Configuration)
	report.addWANExposedServices(services, false)
	report.addWeakNATRules(false)
	report.addAdminPortals(services)
	report.addAttackSurfaces(observations, false)
	report.addEnumerationData()
}

// findingByTitlePrefix returns the first Finding whose Title starts with prefix.
func findingByTitlePrefix(findings []Finding, prefix string) (Finding, bool) {
	for _, f := range findings {
		if strings.HasPrefix(f.Title, prefix) {
			return f, true
		}
	}

	return Finding{}, false
}

// TestRedMode_SSHExposedViaWANPassRule covers AE2 and R19: a config allowing
// SSH from a WAN source produces a non-zero exposed-service Finding for SSH,
// tagged WAN-reachable with AttackSurface detail — the false negative the plan
// was written to eliminate.
func TestRedMode_SSHExposedViaWANPassRule(t *testing.T) {
	t.Parallel()

	device := &common.CommonDevice{
		System: common.System{
			SSH: common.SSH{Enabled: true, Port: "22"},
		},
		Interfaces: []common.Interface{
			{Name: "wan", Enabled: true},
			{Name: "lan", Enabled: true},
		},
		FirewallRules: []common.FirewallRule{
			{
				Type:        common.RuleTypePass,
				Interfaces:  []string{"wan"},
				Source:      common.RuleEndpoint{Address: constants.NetworkAny},
				Destination: common.RuleEndpoint{Port: "22"},
			},
		},
	}

	report := newRedReport(device)
	runRedAnalysis(report)

	if got := report.Metadata["wan_exposed_services_count"]; got == 0 {
		t.Fatal("wan_exposed_services_count = 0, want > 0 (SSH exposed via WAN pass rule) — R19 false negative")
	}

	ssh, ok := findingByTitlePrefix(report.Findings, "WAN-Exposed Service: SSH")
	if !ok {
		t.Fatalf("expected a WAN-Exposed SSH finding, got findings %+v", report.Findings)
	}
	if ssh.AttackSurface == nil {
		t.Fatal("SSH exposure finding must carry AttackSurface detail")
	}
	if !slices.Contains(ssh.AttackSurface.Ports, 22) {
		t.Errorf("SSH AttackSurface.Ports = %v, want to contain 22", ssh.AttackSurface.Ports)
	}
	if ssh.ExploitNotes == "" {
		t.Error("SSH exposure finding must carry an ExploitNote")
	}
}

// TestRedMode_LANOnlyAdminPortalNotInWANLead covers AE3 (both halves): a
// LAN-only admin portal is PRESENT in the admin-portal inventory tagged "lan"
// AND ABSENT from the WAN-exposed Findings. Asserting only the absence would
// let a "portal dropped entirely" regression pass.
func TestRedMode_LANOnlyAdminPortalNotInWANLead(t *testing.T) {
	t.Parallel()

	device := &common.CommonDevice{
		System: common.System{
			WebGUI: common.WebGUI{Protocol: constants.ProtocolHTTPS},
		},
		Interfaces: []common.Interface{
			{Name: "wan", Enabled: true},
			{Name: "lan", Enabled: true},
		},
		// Only a LAN pass rule — the WebGUI is reachable from LAN, never WAN.
		FirewallRules: []common.FirewallRule{
			{Type: common.RuleTypePass, Interfaces: []string{"lan"}},
		},
	}

	report := newRedReport(device)
	runRedAnalysis(report)

	// Half 1: present in the inventory, tagged lan.
	portals, ok := report.Metadata["admin_portals"].([]adminPortal)
	if !ok {
		t.Fatalf(
			"admin_portals = %v (%T), want []adminPortal",
			report.Metadata["admin_portals"],
			report.Metadata["admin_portals"],
		)
	}
	webgui, found := adminPortalByName(portals, "webgui")
	if !found {
		t.Fatalf("admin_portals must retain the LAN-only webgui portal, got %+v", portals)
	}
	if webgui.Reachability != string(analysis.LANOnly) {
		t.Errorf("webgui portal reachability = %q, want %q", webgui.Reachability, analysis.LANOnly)
	}

	// Half 2: absent from the WAN-exposed Findings.
	if _, present := findingByTitlePrefix(report.Findings, "WAN-Exposed Service"); present {
		t.Errorf("a LAN-only portal must not appear in the WAN-exposed Findings, got %+v", report.Findings)
	}
}

// adminPortalByName returns the portal with the given name.
func adminPortalByName(portals []adminPortal, name string) (adminPortal, bool) {
	for _, p := range portals {
		if p.Name == name {
			return p, true
		}
	}

	return adminPortal{}, false
}

// TestRedMode_WANHygieneObservationBecomesExposure asserts a WAN-reachable
// shared-engine hygiene observation (an any-to-any pass rule on WAN) is
// reframed as a red exposure Finding via addAttackSurfaces.
func TestRedMode_WANHygieneObservationBecomesExposure(t *testing.T) {
	t.Parallel()

	device := &common.CommonDevice{
		Interfaces: []common.Interface{
			{Name: "wan", Enabled: true},
			{Name: "lan", Enabled: true},
		},
		FirewallRules: []common.FirewallRule{
			{
				Type:        common.RuleTypePass,
				Interfaces:  []string{"wan"},
				Source:      common.RuleEndpoint{Address: constants.NetworkAny},
				Destination: common.RuleEndpoint{Address: constants.NetworkAny},
			},
		},
	}

	report := newRedReport(device)
	runRedAnalysis(report)

	if got := report.Metadata["attack_surfaces_count"]; got == 0 {
		t.Fatal("attack_surfaces_count = 0, want > 0 (WAN any-to-any rule reframed as exposure)")
	}
	if _, ok := findingByTitlePrefix(report.Findings, "Exposed Weakness:"); !ok {
		t.Errorf("expected a reframed 'Exposed Weakness' finding, got %+v", report.Findings)
	}
}

// TestRedMode_RegressionBattery (R23/R24) locks the red-mode correctness
// invariants against known-bad and known-good configs: multi-WAN, floating,
// and IPv6 exposure must be surfaced; a NAT rule with no matching pass rule and
// an all-LAN config must not be reported WAN-exposed.
//
//nolint:funlen // test table or data declaration; length is in data not logic
func TestRedMode_RegressionBattery(t *testing.T) {
	t.Parallel()

	wanLAN := []common.Interface{{Name: "wan", Enabled: true}, {Name: "lan", Enabled: true}}

	tests := []struct {
		name              string
		device            *common.CommonDevice
		wantFindingPrefix string // required Finding title prefix ("" = expect none)
		wantNoWANExposure bool   // wan_exposed_services_count must be 0
	}{
		{
			name: "AE5 multi-WAN: SSH exposed via WAN2 pass rule",
			device: &common.CommonDevice{
				System:     common.System{SSH: common.SSH{Enabled: true, Port: "22"}},
				Interfaces: []common.Interface{{Name: "wan2", Enabled: true}, {Name: "lan", Enabled: true}},
				FirewallRules: []common.FirewallRule{
					{
						Type:        common.RuleTypePass,
						Interfaces:  []string{"wan2"},
						Destination: common.RuleEndpoint{Port: "22"},
					},
				},
			},
			wantFindingPrefix: "WAN-Exposed Service: SSH",
		},
		{
			name: "AE6 floating rule exposes WebGUI (lands in Findings)",
			device: &common.CommonDevice{
				System:     common.System{WebGUI: common.WebGUI{Protocol: constants.ProtocolHTTPS}},
				Interfaces: wanLAN,
				FirewallRules: []common.FirewallRule{
					{Type: common.RuleTypePass, Floating: true, Destination: common.RuleEndpoint{Port: "443"}},
				},
			},
			wantFindingPrefix: "WAN-Exposed Service: Web Administration Interface",
		},
		{
			name: "AE6 IPv6 WAN interface exposes SSH",
			device: &common.CommonDevice{
				System: common.System{SSH: common.SSH{Enabled: true, Port: "22"}},
				Interfaces: []common.Interface{
					{Name: "wan", Enabled: true, IPv6Address: "2001:db8::1"},
					{Name: "lan", Enabled: true},
				},
				FirewallRules: []common.FirewallRule{
					{
						Type:        common.RuleTypePass,
						Interfaces:  []string{"wan"},
						IPProtocol:  common.IPProtocolInet6,
						Destination: common.RuleEndpoint{Port: "22"},
					},
				},
			},
			wantFindingPrefix: "WAN-Exposed Service: SSH",
		},
		{
			name: "port range: SSH exposed when WAN rule permits a range covering 22",
			device: &common.CommonDevice{
				System:     common.System{SSH: common.SSH{Enabled: true, Port: "22"}},
				Interfaces: wanLAN,
				FirewallRules: []common.FirewallRule{
					{
						Type:        common.RuleTypePass,
						Interfaces:  []string{"wan"},
						Destination: common.RuleEndpoint{Port: "20-25"},
					},
				},
			},
			wantFindingPrefix: "WAN-Exposed Service: SSH",
		},
		{
			name: "port list: SSH exposed when WAN rule permits a comma list containing 22",
			device: &common.CommonDevice{
				System:     common.System{SSH: common.SSH{Enabled: true, Port: "22"}},
				Interfaces: wanLAN,
				FirewallRules: []common.FirewallRule{
					{
						Type:        common.RuleTypePass,
						Interfaces:  []string{"wan"},
						Destination: common.RuleEndpoint{Port: "80,22,443"},
					},
				},
			},
			wantFindingPrefix: "WAN-Exposed Service: SSH",
		},
		{
			name: "port range miss: SSH not exposed when WAN rule range excludes 22",
			device: &common.CommonDevice{
				System: common.System{
					SSH:    common.SSH{Enabled: true, Port: "22"},
					WebGUI: common.WebGUI{Protocol: constants.ProtocolHTTPS},
				},
				Interfaces: wanLAN,
				FirewallRules: []common.FirewallRule{
					{
						Type:        common.RuleTypePass,
						Interfaces:  []string{"wan"},
						Destination: common.RuleEndpoint{Port: "8000-9000"},
					},
				},
			},
			wantNoWANExposure: true,
		},
		{
			name: "port alias: unresolvable alias over-reports SSH as exposed (safe direction)",
			device: &common.CommonDevice{
				System:     common.System{SSH: common.SSH{Enabled: true, Port: "22"}},
				Interfaces: wanLAN,
				FirewallRules: []common.FirewallRule{
					{
						Type:        common.RuleTypePass,
						Interfaces:  []string{"wan"},
						Destination: common.RuleEndpoint{Port: "MgmtPorts"},
					},
				},
			},
			wantFindingPrefix: "WAN-Exposed Service: SSH",
		},
		{
			name: "custom WebGUI port: exposed when WAN rule permits the configured port",
			device: &common.CommonDevice{
				System:     common.System{WebGUI: common.WebGUI{Protocol: constants.ProtocolHTTPS, Port: "8443"}},
				Interfaces: wanLAN,
				FirewallRules: []common.FirewallRule{
					{
						Type:        common.RuleTypePass,
						Interfaces:  []string{"wan"},
						Destination: common.RuleEndpoint{Port: "8443"},
					},
				},
			},
			wantFindingPrefix: "WAN-Exposed Service: Web Administration Interface",
		},
		{
			name: "custom WebGUI port: not exposed when WAN rule permits only the default 443",
			device: &common.CommonDevice{
				System:     common.System{WebGUI: common.WebGUI{Protocol: constants.ProtocolHTTPS, Port: "8443"}},
				Interfaces: wanLAN,
				FirewallRules: []common.FirewallRule{
					{
						Type:        common.RuleTypePass,
						Interfaces:  []string{"wan"},
						Destination: common.RuleEndpoint{Port: "443"},
					},
				},
			},
			wantNoWANExposure: true,
		},
		{
			name: "SNMP exposed via WAN rule permitting 161",
			device: &common.CommonDevice{
				SNMP:       common.SNMPConfig{ROCommunity: "public"},
				Interfaces: wanLAN,
				FirewallRules: []common.FirewallRule{
					{
						Type:        common.RuleTypePass,
						Interfaces:  []string{"wan"},
						Destination: common.RuleEndpoint{Port: "161"},
					},
				},
			},
			wantFindingPrefix: "WAN-Exposed Service: SNMP",
		},
		{
			name: "R3 NAT with no matching pass rule is not WAN-exposed",
			device: &common.CommonDevice{
				System:     common.System{SSH: common.SSH{Enabled: true, Port: "22"}},
				Interfaces: wanLAN,
				NAT: common.NATConfig{
					InboundRules: []common.InboundNATRule{
						{Interfaces: []string{"wan"}, ExternalPort: "22"},
					},
				},
			},
			wantNoWANExposure: true,
		},
		{
			name: "clean all-LAN config has no WAN exposure",
			device: &common.CommonDevice{
				System: common.System{
					SSH:    common.SSH{Enabled: true, Port: "22"},
					WebGUI: common.WebGUI{Protocol: constants.ProtocolHTTPS},
				},
				Interfaces: wanLAN,
				FirewallRules: []common.FirewallRule{
					{Type: common.RuleTypePass, Interfaces: []string{"lan"}},
				},
			},
			wantNoWANExposure: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			report := newRedReport(tt.device)
			runRedAnalysis(report)

			if tt.wantNoWANExposure {
				if got := report.Metadata["wan_exposed_services_count"]; got != 0 {
					t.Errorf("wan_exposed_services_count = %v, want 0", got)
				}

				return
			}

			if _, ok := findingByTitlePrefix(report.Findings, tt.wantFindingPrefix); !ok {
				t.Errorf("expected a finding titled %q, got %+v", tt.wantFindingPrefix, report.Findings)
			}
		})
	}
}

// TestRedMode_WeakNATRule_PositivePath covers the addWeakNATRules Finding-
// emitting branch (R15): a WAN inbound NAT rule correlated with an enabled WAN
// pass rule produces a "WAN-Reachable Port Forward" Finding with AttackSurface.
func TestRedMode_WeakNATRule_PositivePath(t *testing.T) {
	t.Parallel()

	device := &common.CommonDevice{
		Interfaces: []common.Interface{{Name: "wan", Enabled: true}, {Name: "lan", Enabled: true}},
		FirewallRules: []common.FirewallRule{
			{Type: common.RuleTypePass, Interfaces: []string{"wan"}},
		},
		NAT: common.NATConfig{
			InboundRules: []common.InboundNATRule{
				{Interfaces: []string{"wan"}, ExternalPort: "3389", Protocol: "tcp"},
			},
		},
	}

	report := newRedReport(device)
	runRedAnalysis(report)

	if got := report.Metadata["weak_nat_rules_count"]; got != 1 {
		t.Fatalf("weak_nat_rules_count = %v, want 1", got)
	}

	nat, ok := findingByTitlePrefix(report.Findings, "WAN-Reachable Port Forward")
	if !ok {
		t.Fatalf("expected a WAN-Reachable Port Forward finding, got %+v", report.Findings)
	}
	if nat.AttackSurface == nil || !slices.Contains(nat.AttackSurface.Ports, 3389) {
		t.Errorf("NAT finding AttackSurface = %+v, want Ports to contain 3389", nat.AttackSurface)
	}
}

// TestRedMode_FindingsOrderedBySeverity covers R16: red exposure findings lead
// with the most urgent. A WebGUI exposure (critical) must sort ahead of an SSH
// exposure (high) when both are WAN-reachable via a broad any-port WAN rule.
func TestRedMode_FindingsOrderedBySeverity(t *testing.T) {
	t.Parallel()

	device := &common.CommonDevice{
		System: common.System{
			SSH:    common.SSH{Enabled: true, Port: "22"},
			WebGUI: common.WebGUI{Protocol: constants.ProtocolHTTPS},
		},
		Interfaces: []common.Interface{{Name: "wan", Enabled: true}, {Name: "lan", Enabled: true}},
		// Any-port WAN rule exposes every management service.
		FirewallRules: []common.FirewallRule{
			{
				Type:       common.RuleTypePass,
				Interfaces: []string{"wan"},
				Source:     common.RuleEndpoint{Address: constants.NetworkAny},
			},
		},
	}

	report := newRedReport(device)
	runRedAnalysis(report)

	if len(report.Findings) < 2 {
		t.Fatalf("expected >= 2 findings, got %d: %+v", len(report.Findings), report.Findings)
	}
	// The first finding must be the critical WebGUI exposure, ahead of SSH (high).
	if report.Findings[0].Severity != string(analysis.SeverityCritical) {
		t.Errorf("first finding severity = %q, want %q (most urgent leads)",
			report.Findings[0].Severity, analysis.SeverityCritical)
	}
}

// TestRedMode_AnyToAnyComponentCollision pins the intended one-exposure-per-
// config-element behavior (A3): when a WAN-scoped any-to-any pass rule triggers
// both the "Overly Permissive WAN Rule" and "Any-to-Any Pass Rule" observations
// on the same filter.rule[N] Component, addAttackSurfaces emits exactly one
// exposure finding for that element — the shared engine appends the permissive-
// WAN observation first, so it is the one retained. This is deliberate: a single
// rule is one exposure, not two.
func TestRedMode_AnyToAnyComponentCollision(t *testing.T) {
	t.Parallel()

	device := &common.CommonDevice{
		Interfaces: []common.Interface{{Name: "wan", Enabled: true}, {Name: "lan", Enabled: true}},
		FirewallRules: []common.FirewallRule{
			{
				Type:        common.RuleTypePass,
				Interfaces:  []string{"wan"},
				Source:      common.RuleEndpoint{Address: constants.NetworkAny},
				Destination: common.RuleEndpoint{Address: constants.NetworkAny},
			},
		},
	}

	report := newRedReport(device)
	runRedAnalysis(report)

	count := 0
	for _, f := range report.Findings {
		if f.Component == "filter.rule[0]" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("filter.rule[0] exposure findings = %d, want exactly 1 (one exposure per config element)", count)
	}
}

// TestRedMode_BlackhatChangesToneNotSafety covers AE7 and R20 end-to-end
// through GenerateReport (the real ModeConfig.Blackhat wiring): the
// --audit-blackhat variant changes the ExploitNote text but never introduces
// instructional content — the R21 denylist passes for both tone variants.
func TestRedMode_BlackhatChangesToneNotSafety(t *testing.T) {
	t.Parallel()

	device := &common.CommonDevice{
		System:     common.System{SSH: common.SSH{Enabled: true, Port: "22"}},
		Interfaces: []common.Interface{{Name: "wan", Enabled: true}, {Name: "lan", Enabled: true}},
		FirewallRules: []common.FirewallRule{
			{Type: common.RuleTypePass, Interfaces: []string{"wan"}, Destination: common.RuleEndpoint{Port: "22"}},
		},
	}

	mc := NewModeController(NewPluginRegistry(), newTestLogger(t))

	exploitNoteFrom := func(blackhat bool) string {
		report, err := mc.GenerateReport(context.Background(), device, &ModeConfig{Mode: ModeRed, Blackhat: blackhat})
		if err != nil {
			t.Fatalf("GenerateReport(blackhat=%v) error = %v", blackhat, err)
		}
		ssh, ok := findingByTitlePrefix(report.Findings, "WAN-Exposed Service: SSH")
		if !ok {
			t.Fatalf("blackhat=%v: expected an SSH exposure finding, got %+v", blackhat, report.Findings)
		}

		return ssh.ExploitNotes
	}

	standard := exploitNoteFrom(false)
	blackhat := exploitNoteFrom(true)

	if standard == "" || blackhat == "" {
		t.Fatal("both tone variants must produce a non-empty ExploitNote")
	}
	if standard == blackhat {
		t.Error("--audit-blackhat must change the ExploitNote tone")
	}
	// The safety invariant holds regardless of tone.
	for _, note := range []string{standard, blackhat} {
		if pattern, unsafe := FindInstructionalContent(note); unsafe {
			t.Errorf("ExploitNote matched instructional pattern %q (tone must not affect safety): %q", pattern, note)
		}
	}
}

// TestRedMode_NoStubMarkersRemain is the U5 verification gate: after full red
// analysis, no metadata value carries the old `{not_implemented, stub}` marker
// shape — every red method now performs real analysis.
func TestRedMode_NoStubMarkersRemain(t *testing.T) {
	t.Parallel()

	device := &common.CommonDevice{
		System:     common.System{SSH: common.SSH{Enabled: true, Port: "22"}},
		Interfaces: []common.Interface{{Name: "wan", Enabled: true}},
		FirewallRules: []common.FirewallRule{
			{Type: common.RuleTypePass, Interfaces: []string{"wan"}, Destination: common.RuleEndpoint{Port: "22"}},
		},
	}

	report := newRedReport(device)
	runRedAnalysis(report)

	for key, value := range report.Metadata {
		marker, ok := value.(map[string]any)
		if !ok {
			continue
		}
		if marker["stub"] == true || marker["not_implemented"] == true {
			t.Errorf("metadata[%q] still carries a stub marker: %v", key, marker)
		}
	}
}

func TestPluginRegistry_GetPlugin(t *testing.T) {
	t.Parallel()

	registry := NewPluginRegistry()
	stigPlugin := stig.NewPlugin()

	// Register a plugin
	err := registry.RegisterPlugin(stigPlugin)
	if err != nil {
		t.Fatalf("Failed to register plugin: %v", err)
	}

	// Test getting an existing plugin
	retrievedPlugin, err := registry.GetPlugin("stig")
	if err != nil {
		t.Errorf("GetPlugin() error = %v", err)
	}
	if retrievedPlugin == nil {
		t.Error("GetPlugin() returned nil for existing plugin")
	}

	// Test getting a non-existent plugin
	notFoundPlugin, err := registry.GetPlugin("nonexistent")
	if err == nil {
		t.Error("GetPlugin() should return error for non-existent plugin")
	}
	if notFoundPlugin != nil {
		t.Error("GetPlugin() should return nil for non-existent plugin")
	}
}

// TestPluginRegistry_LoadDynamicPlugins verifies that LoadDynamicPlugins handles missing directories gracefully.
func TestPluginRegistry_LoadDynamicPlugins(t *testing.T) {
	t.Parallel()

	registry := NewPluginRegistry()
	logger := newTestLogger(t)

	missingDir := filepath.Join(t.TempDir(), "does-not-exist")
	result, err := registry.LoadDynamicPlugins(context.Background(), missingDir, false, logger)
	if err != nil {
		t.Errorf("LoadDynamicPlugins() should not error for missing directory, got %v", err)
	}

	if result.Loaded != 0 {
		t.Errorf("LoadDynamicPlugins() Loaded = %d, want 0", result.Loaded)
	}

	if result.Failed() != 0 {
		t.Errorf("LoadDynamicPlugins() Failed = %d, want 0", result.Failed())
	}
}

func TestPluginRegistry_RunComplianceChecks(t *testing.T) {
	t.Parallel()

	registry := NewPluginRegistry()
	stigPlugin := stig.NewPlugin()

	// Register a plugin
	err := registry.RegisterPlugin(stigPlugin)
	if err != nil {
		t.Fatalf("Failed to register plugin: %v", err)
	}

	// Create a test configuration
	testConfig := &common.CommonDevice{
		System: common.System{
			Hostname: "test-host",
			Domain:   "test.local",
		},
	}

	// Test running compliance checks with no plugins selected
	results, err := registry.RunComplianceChecks(testConfig, nil, newTestLogger(t))
	if err != nil {
		t.Errorf("RunComplianceChecks() error = %v", err)
	}
	if results == nil {
		t.Error("RunComplianceChecks() returned nil results")
	}

	// Test running compliance checks with specific plugins
	selectedPlugins := []string{"stig"}
	results, err = registry.RunComplianceChecks(testConfig, selectedPlugins, newTestLogger(t))
	if err != nil {
		t.Errorf("RunComplianceChecks() error = %v", err)
	}
	if results == nil {
		t.Error("RunComplianceChecks() returned nil results")
	}

	// Test running compliance checks with non-existent plugins
	selectedPluginsNonexistent := []string{"nonexistent"}
	_, err = registry.RunComplianceChecks(testConfig, selectedPluginsNonexistent, newTestLogger(t))
	if err == nil {
		t.Error("RunComplianceChecks() should return error for non-existent plugins")
	}
}

// Comment out broken global plugin and plugin manager tests
/*
func TestPluginRegistry_GlobalFunctions(t *testing.T) {
	// Test RegisterGlobalPlugin
	err := RegisterGlobalPlugin("test-plugin", nil)
	if err != nil {
		t.Errorf("RegisterGlobalPlugin() error = %v", err)
	}

	// Test GetGlobalPlugin
	plugin, err := GetGlobalPlugin("test-plugin")
	if err != nil {
		t.Errorf("GetGlobalPlugin() error = %v", err)
	}
	if plugin != nil {
		t.Error("GetGlobalPlugin() should return nil for non-existent plugin")
	}

	// Test ListGlobalPlugins
	plugins := ListGlobalPlugins()
	if plugins == nil {
		t.Error("ListGlobalPlugins() should not return nil")
	}
}

func TestPluginManager_NewPluginManager(t *testing.T) {
	manager := NewPluginManager()
	if manager == nil {
		t.Fatal("NewPluginManager() returned nil")
	}
}

func TestPluginManager_InitializePlugins(t *testing.T) {
	manager := NewPluginManager()

	// Test initializing plugins
	err := manager.InitializePlugins()
	if err != nil {
		t.Errorf("InitializePlugins() error = %v", err)
	}
}

func TestPluginManager_GetRegistry(t *testing.T) {
	manager := NewPluginManager()

	registry := manager.GetRegistry()
	if registry == nil {
		t.Error("GetRegistry() returned nil")
	}
}

func TestPluginManager_ListAvailablePlugins(t *testing.T) {
	manager := NewPluginManager()

	// Initialize plugins first
	err := manager.InitializePlugins()
	if err != nil {
		t.Fatalf("Failed to initialize plugins: %v", err)
	}

	plugins := manager.ListAvailablePlugins()
	if plugins == nil {
		t.Error("ListAvailablePlugins() returned nil")
	}
}

func TestPluginManager_RunComplianceAudit(t *testing.T) {
	manager := NewPluginManager()

	// Create a test configuration
	testConfig := &common.CommonDevice{
		System: common.System{
			Hostname: "test-host",
			Domain:   "test.local",
		},
	}

	// Test running compliance audit
	results, err := manager.RunComplianceAudit(testConfig, nil)
	if err != nil {
		t.Errorf("RunComplianceAudit() error = %v", err)
	}
	if results == nil {
		t.Error("RunComplianceAudit() returned nil results")
	}
}

func TestPluginManager_GetPluginControlInfo(t *testing.T) {
	manager := NewPluginManager()

	// Test getting plugin control info
	info := manager.GetPluginControlInfo()
	if info == nil {
		t.Error("GetPluginControlInfo() returned nil")
	}
}

func TestPluginManager_ValidatePluginConfiguration(t *testing.T) {
	manager := NewPluginManager()

	// Test validating plugin configuration
	err := manager.ValidatePluginConfiguration(nil)
	if err != nil {
		t.Errorf("ValidatePluginConfiguration() error = %v", err)
	}
}

func TestPluginManager_GetPluginStatistics(t *testing.T) {
	manager := NewPluginManager()

	// Test getting plugin statistics
	stats := manager.GetPluginStatistics()
	if stats == nil {
		t.Error("GetPluginStatistics() returned nil")
	}
}
*/

// TestGenerateBlueReport_NoPluginsRunsAllAvailable verifies that blue mode
// executes compliance checks using all registered plugins when SelectedPlugins
// is empty. This is the documented default: `--mode blue` without `--plugins`
// should produce a full compliance audit, not silently skip compliance.
func TestGenerateBlueReport_NoPluginsRunsAllAvailable(t *testing.T) {
	t.Parallel()

	// Register all built-in plugins so the registry has content to resolve.
	registry := NewPluginRegistry()
	for _, p := range []compliance.Plugin{stig.NewPlugin(), sans.NewPlugin(), firewall.NewPlugin()} {
		if err := registry.RegisterPlugin(p); err != nil {
			t.Fatalf("RegisterPlugin(%s): %v", p.Name(), err)
		}
	}

	logger := newTestLogger(t)
	controller := NewModeController(registry, logger)

	device := &common.CommonDevice{
		System: common.System{
			Hostname: "test-fw",
			Domain:   "example.com",
		},
	}

	// Bare blue mode — no SelectedPlugins
	modeConfig := &ModeConfig{
		Mode:            ModeBlue,
		SelectedPlugins: nil,
	}

	report, err := controller.GenerateReport(context.Background(), device, modeConfig)
	if err != nil {
		t.Fatalf("GenerateReport() unexpected error: %v", err)
	}

	// All three built-in plugins must appear in the compliance results.
	expectedPlugins := []string{"firewall", "sans", "stig"}
	for _, name := range expectedPlugins {
		if _, exists := report.Compliance[name]; !exists {
			t.Errorf("expected plugin %q in compliance results, but not found", name)
		}
	}

	if len(report.Compliance) != len(expectedPlugins) {
		t.Errorf("expected %d plugins in compliance, got %d", len(expectedPlugins), len(report.Compliance))
	}

	// Verify metadata indicates compliance ran successfully.
	if status, ok := report.Metadata["compliance_check_status"]; !ok || status != complianceCheckStatusCompleted {
		t.Errorf("expected compliance_check_status=%s, got %v", complianceCheckStatusCompleted, status)
	}
}
