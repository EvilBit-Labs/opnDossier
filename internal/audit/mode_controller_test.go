package audit

import (
	"context"
	"log/slog"
	"os"
	"testing"

	"github.com/unclesp1d3r/opnFocus/internal/model"
	"github.com/unclesp1d3r/opnFocus/internal/plugins/firewall"
	"github.com/unclesp1d3r/opnFocus/internal/plugins/sans"
	"github.com/unclesp1d3r/opnFocus/internal/plugins/stig"
	"github.com/unclesp1d3r/opnFocus/internal/processor"
)

func TestParseReportMode(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    ReportMode
		wantErr bool
	}{
		{
			name:    "standard mode",
			input:   "standard",
			want:    ModeStandard,
			wantErr: false,
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
			name:    "case insensitive standard",
			input:   "STANDARD",
			want:    ModeStandard,
			wantErr: false,
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
	tests := []struct {
		name string
		mode ReportMode
		want string
	}{
		{
			name: "standard mode",
			mode: ModeStandard,
			want: "standard",
		},
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
			if got := tt.mode.String(); got != tt.want {
				t.Errorf("ReportMode.String() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNewModeController(t *testing.T) {
	registry := NewPluginRegistry()
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

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

func TestModeController_ValidateModeConfig(t *testing.T) {
	registry := NewPluginRegistry()
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
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
			name: "valid standard mode",
			config: &ModeConfig{
				Mode: ModeStandard,
			},
			wantErr: false,
		},
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
				Mode:            ModeStandard,
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
			name: "invalid plugin selection - case sensitive",
			config: &ModeConfig{
				Mode:            ModeStandard,
				SelectedPlugins: []string{"STIG"},
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
			err := controller.ValidateModeConfig(tt.config)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateModeConfig() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestModeController_GenerateReport(t *testing.T) {
	registry := NewPluginRegistry()
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	controller := NewModeController(registry, logger)

	// Create a minimal test configuration
	testConfig := &model.OpnSenseDocument{
		System: model.System{
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
			name: "standard mode",
			config: &ModeConfig{
				Mode: ModeStandard,
			},
			wantErr: false,
		},
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
			name: "red mode with blackhat",
			config: &ModeConfig{
				Mode:         ModeRed,
				BlackhatMode: true,
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
				Mode: ModeStandard,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var cfg *model.OpnSenseDocument
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

				if report.BlackhatMode != tt.config.BlackhatMode {
					t.Errorf("GenerateReport() blackhat mode = %v, want %v", report.BlackhatMode, tt.config.BlackhatMode)
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
	report := &Report{
		Mode:          ModeStandard,
		BlackhatMode:  false,
		Comprehensive: true,
		Configuration: &model.OpnSenseDocument{},
		Findings:      make([]Finding, 0),
		Compliance:    make(map[string]ComplianceResult),
		Metadata:      make(map[string]any),
	}

	// Test that the report structure is properly initialized
	if report.Mode != ModeStandard {
		t.Errorf("Report.Mode = %v, want %v", report.Mode, ModeStandard)
	}

	if report.BlackhatMode {
		t.Error("Report.BlackhatMode should be false")
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
	finding := Finding{
		Title:          "Test Finding",
		Severity:       processor.SeverityHigh,
		Description:    "Test description",
		Recommendation: "Test recommendation",
		Tags:           []string{"test", "security"},
		Component:      "firewall",
		Control:        "CIS-1.1",
	}

	// Test that the finding structure is properly set
	if finding.Title != "Test Finding" {
		t.Errorf("Finding.Title = %v, want %v", finding.Title, "Test Finding")
	}

	if finding.Severity != processor.SeverityHigh {
		t.Errorf("Finding.Severity = %v, want %v", finding.Severity, processor.SeverityHigh)
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

	if finding.Control != "CIS-1.1" {
		t.Errorf("Finding.Control = %v, want %v", finding.Control, "CIS-1.1")
	}
}

func TestAttackSurface_Structure(t *testing.T) {
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
