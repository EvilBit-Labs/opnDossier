package cmd

import (
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/config"
	"github.com/EvilBit-Labs/opnDossier/internal/log"
)

// TestEngineValidation tests the new config validation for the engine field
func TestEngineValidation(t *testing.T) {
	tests := []struct {
		name      string
		cfg       *config.Config
		expectErr bool
	}{
		{
			name: "valid programmatic engine",
			cfg: &config.Config{
				Engine: "programmatic",
			},
			expectErr: false,
		},
		{
			name: "valid template engine",
			cfg: &config.Config{
				Engine: "template",
			},
			expectErr: false,
		},
		{
			name: "empty engine is valid (defaults to programmatic)",
			cfg: &config.Config{
				Engine: "",
			},
			expectErr: false,
		},
		{
			name: "invalid engine should fail validation",
			cfg: &config.Config{
				Engine: "invalid",
			},
			expectErr: true,
		},
		{
			name: "case insensitive engine validation",
			cfg: &config.Config{
				Engine: "TEMPLATE",
			},
			expectErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.Validate()
			hasErr := err != nil
			if hasErr != tt.expectErr {
				if tt.expectErr {
					t.Errorf("Expected validation error for engine '%s', but got none", tt.cfg.Engine)
				} else {
					t.Errorf("Unexpected validation error for engine '%s': %v", tt.cfg.Engine, err)
				}
			}
		})
	}
}

// TestConfigGetters tests the new config getter methods
func TestConfigGetters(t *testing.T) {
	cfg := &config.Config{
		Engine:      "template",
		UseTemplate: true,
	}

	if cfg.GetEngine() != "template" {
		t.Errorf("Expected GetEngine() to return 'template', got '%s'", cfg.GetEngine())
	}

	if !cfg.IsUseTemplate() {
		t.Errorf("Expected IsUseTemplate() to return true")
	}

	// Test with defaults
	defaultCfg := &config.Config{}
	if defaultCfg.GetEngine() != "" {
		t.Errorf("Expected GetEngine() to return empty string for default, got '%s'", defaultCfg.GetEngine())
	}

	if defaultCfg.IsUseTemplate() {
		t.Errorf("Expected IsUseTemplate() to return false for default")
	}
}

// TestFlagPrecedence tests the complete precedence order for all generation flags
func TestFlagPrecedence(t *testing.T) {
	tests := []struct {
		name                 string
		sharedEngine         string
		sharedLegacy         bool
		sharedCustomTemplate string
		sharedUseTemplate    bool
		expected             bool
		description          string
	}{
		{
			name:        "engine=programmatic overrides everything",
			sharedEngine: "programmatic",
			sharedLegacy: true,
			sharedCustomTemplate: "/path/to/template.tmpl",
			sharedUseTemplate: true,
			expected:     false,
			description:  "engine flag should override all other settings",
		},
		{
			name:        "engine=template overrides everything",
			sharedEngine: "template",
			sharedLegacy: false,
			sharedCustomTemplate: "",
			sharedUseTemplate: false,
			expected:     true,
			description:  "engine flag should enable template mode regardless of other flags",
		},
		{
			name:                 "custom template without engine enables template mode",
			sharedCustomTemplate: "/path/to/template.tmpl",
			sharedUseTemplate:    false,
			expected:             true,
			description:          "custom template should automatically enable template mode",
		},
		{
			name:              "use-template without other flags enables template mode",
			sharedUseTemplate: true,
			expected:          true,
			description:       "use-template flag should enable template mode",
		},
		{
			name:         "legacy without other flags enables template mode",
			sharedLegacy: true,
			expected:     true,
			description:  "legacy flag should enable template mode",
		},
		{
			name:        "all flags false defaults to programmatic",
			expected:    false,
			description: "default behavior should be programmatic mode",
		},
	}

	// Create a test logger
	logger, err := createTestLogger()
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset all global variables
			sharedEngine = tt.sharedEngine
			sharedLegacy = tt.sharedLegacy
			sharedCustomTemplate = tt.sharedCustomTemplate
			sharedUseTemplate = tt.sharedUseTemplate

			result := determineGenerationEngine(logger)
			if result != tt.expected {
				t.Errorf("%s: determineGenerationEngine() = %v, expected %v", 
					tt.description, result, tt.expected)
			}
		})
	}

	// Clean up global variables
	resetGlobalFlags()
}

// resetGlobalFlags resets all global flag variables to their default state
func resetGlobalFlags() {
	sharedEngine = ""
	sharedLegacy = false
	sharedCustomTemplate = ""
	sharedUseTemplate = false
}

// createTestLogger creates a logger for testing
func createTestLogger() (*log.Logger, error) {
	return log.New(log.Config{})
}