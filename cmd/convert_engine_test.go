package cmd

import (
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/config"
	"github.com/EvilBit-Labs/opnDossier/internal/log"
)

func TestDetermineGenerationEngine(t *testing.T) {
	// Create a test logger
	logger, err := log.New(log.Config{})
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}

	tests := []struct {
		name                 string
		sharedEngine         string
		sharedLegacy         bool
		sharedCustomTemplate string
		sharedUseTemplate    bool
		expected             bool // true = template mode, false = programmatic mode
	}{
		{
			name:     "default should use programmatic mode",
			expected: false,
		},
		{
			name:         "explicit engine=programmatic",
			sharedEngine: "programmatic",
			expected:     false,
		},
		{
			name:         "explicit engine=template",
			sharedEngine: "template",
			expected:     true,
		},
		{
			name:         "unknown engine defaults to programmatic",
			sharedEngine: "unknown",
			expected:     false,
		},
		{
			name:         "legacy flag enables template mode",
			sharedLegacy: true,
			expected:     true,
		},
		{
			name:                 "custom template enables template mode",
			sharedCustomTemplate: "/path/to/template.tmpl",
			expected:             true,
		},
		{
			name:              "use-template flag enables template mode",
			sharedUseTemplate: true,
			expected:          true,
		},
		{
			name:              "engine flag overrides use-template flag",
			sharedEngine:      "programmatic",
			sharedUseTemplate: true,
			expected:          false,
		},
		{
			name:                 "engine flag overrides custom template",
			sharedEngine:         "programmatic",
			sharedCustomTemplate: "/path/to/template.tmpl",
			expected:             false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset global variables
			sharedEngine = tt.sharedEngine
			sharedLegacy = tt.sharedLegacy
			sharedCustomTemplate = tt.sharedCustomTemplate
			sharedUseTemplate = tt.sharedUseTemplate

			result := determineGenerationEngine(logger)
			if result != tt.expected {
				t.Errorf("determineGenerationEngine() = %v, expected %v", result, tt.expected)
			}
		})
	}

	// Clean up global variables
	sharedEngine = ""
	sharedLegacy = false
	sharedCustomTemplate = ""
	sharedUseTemplate = false
}

func TestDetermineUseTemplateFromConfig(t *testing.T) {
	tests := []struct {
		name     string
		config   *config.Config
		expected bool
	}{
		{
			name:     "nil config returns false",
			config:   nil,
			expected: false,
		},
		{
			name: "config with engine=template",
			config: &config.Config{
				Engine: "template",
			},
			expected: true,
		},
		{
			name: "config with engine=programmatic",
			config: &config.Config{
				Engine: "programmatic",
			},
			expected: false,
		},
		{
			name: "config with use_template=true",
			config: &config.Config{
				UseTemplate: true,
			},
			expected: true,
		},
		{
			name: "config with engine=template overrides use_template=false",
			config: &config.Config{
				Engine:      "template",
				UseTemplate: false,
			},
			expected: true,
		},
		{
			name:     "empty config defaults to false",
			config:   &config.Config{},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := determineUseTemplateFromConfig(tt.config)
			if result != tt.expected {
				t.Errorf("determineUseTemplateFromConfig() = %v, expected %v", result, tt.expected)
			}
		})
	}
}

func TestValidateTemplatePath(t *testing.T) {
	tests := []struct {
		name         string
		templatePath string
		expectError  bool
	}{
		{
			name:         "empty path is valid",
			templatePath: "",
			expectError:  false,
		},
		{
			name:         "path with directory traversal should fail",
			templatePath: "../../../etc/passwd",
			expectError:  true,
		},
		{
			name:         "path with directory traversal in middle should fail",
			templatePath: "templates/../../../etc/passwd",
			expectError:  true,
		},
		{
			name:         "non-existent file should fail",
			templatePath: "non-existent-file.tmpl",
			expectError:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateTemplatePath(tt.templatePath)
			hasError := err != nil
			if hasError != tt.expectError {
				if tt.expectError {
					t.Errorf("validateTemplatePath() should have failed but didn't")
				} else {
					t.Errorf("validateTemplatePath() failed unexpectedly: %v", err)
				}
			}
		})
	}
}

func TestBuildConversionOptionsWithEngine(t *testing.T) {
	// Reset global variables before test
	sharedSections = []string{"system", "network"}
	sharedWrapWidth = 100
	sharedComprehensive = true
	sharedIncludeTunables = true

	defer func() {
		// Clean up after test
		sharedSections = nil
		sharedWrapWidth = 0
		sharedComprehensive = false
		sharedIncludeTunables = false
	}()

	cfg := &config.Config{
		Theme:       "dark",
		Template:    "custom",
		Sections:    []string{"firewall"}, // Should be overridden by CLI flags
		WrapWidth:   80,                   // Should be overridden by CLI flags
		Engine:      "template",
		UseTemplate: true,
	}

	opts := buildConversionOptions("json", cfg)

	// Check that CLI flags take precedence
	if len(opts.Sections) != 2 || opts.Sections[0] != "system" || opts.Sections[1] != "network" {
		t.Errorf("Expected sections [system network], got %v", opts.Sections)
	}

	if opts.WrapWidth != 100 {
		t.Errorf("Expected wrap width 100, got %d", opts.WrapWidth)
	}

	if !opts.Comprehensive {
		t.Errorf("Expected comprehensive to be true")
	}

	if includeTunables, ok := opts.CustomFields["IncludeTunables"].(bool); !ok || !includeTunables {
		t.Errorf("Expected IncludeTunables to be true")
	}

	// Check that config values are used when CLI flags are not set
	if string(opts.Theme) != "dark" {
		t.Errorf("Expected theme 'dark', got %s", opts.Theme)
	}

	if opts.TemplateName != "custom" {
		t.Errorf("Expected template name 'custom', got %s", opts.TemplateName)
	}

	// Check that engine determination is included
	if !opts.UseTemplateEngine {
		t.Errorf("Expected UseTemplateEngine to be true based on config")
	}
}
