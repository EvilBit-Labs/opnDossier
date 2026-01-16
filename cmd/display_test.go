package cmd

import (
	"io"
	"os"
	"sync"
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/config"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// sharedFlagSnapshot captures a subset of shared flags for test isolation.
// This snapshot is used to save and restore flag state between tests to prevent
// test pollution when flags are modified during test execution.
//
// Included flags (affect output/display behavior):
//   - theme: Terminal rendering theme (light, dark, auto)
//   - wrapWidth: Text wrapping width for display
//   - sections: Which sections to include in output
//   - customTemplate: Path to custom template file
//   - comprehensive: Whether to generate comprehensive reports
//
// Excluded flags (affect generation engine selection or internal state):
//   - sharedIncludeTunables: Content flag, but rarely modified in tests
//   - sharedTemplateCacheSize: Performance tuning, not modified in display tests
//   - sharedUseTemplate: Engine selection flag, not relevant for display tests
//   - sharedEngine: Engine selection flag, not relevant for display tests
//   - sharedLegacy: Engine selection flag, not relevant for display tests
//   - warnedAboutAbsoluteTemplatePath: Internal warning gate, should not be reset between tests
//
// Rationale: The snapshot focuses on flags that directly affect display output
// and are commonly modified in display tests. Engine selection flags are excluded
// because display tests typically work with already-generated content.
type sharedFlagSnapshot struct {
	theme          string
	wrapWidth      int
	sections       []string
	customTemplate string
	comprehensive  bool
}

func captureSharedFlags() sharedFlagSnapshot {
	return sharedFlagSnapshot{
		theme:          sharedTheme,
		wrapWidth:      sharedWrapWidth,
		sections:       sharedSections,
		customTemplate: sharedCustomTemplate,
		comprehensive:  sharedComprehensive,
	}
}

func (s sharedFlagSnapshot) restore() {
	sharedTheme = s.theme
	sharedWrapWidth = s.wrapWidth
	sharedSections = s.sections
	sharedCustomTemplate = s.customTemplate
	sharedComprehensive = s.comprehensive
}

func captureStderr(t *testing.T, fn func()) string {
	t.Helper()

	originalStderr := os.Stderr
	reader, writer, err := os.Pipe()
	require.NoError(t, err)

	os.Stderr = writer

	var (
		output string
		once   sync.Once
	)
	cleanup := func() {
		once.Do(func() {
			os.Stderr = originalStderr
			require.NoError(t, writer.Close())

			captured, readErr := io.ReadAll(reader)
			require.NoError(t, readErr)
			output = string(captured)

			require.NoError(t, reader.Close())
		})
	}
	defer cleanup()

	fn()
	cleanup()

	return output
}

func TestCaptureStderrRestoresOnPanic(t *testing.T) {
	originalStderr := os.Stderr
	defer func() {
		os.Stderr = originalStderr
	}()
	defer func() {
		recovered := recover()
		require.NotNil(t, recovered)
		assert.Equal(t, originalStderr, os.Stderr)
	}()

	_ = captureStderr(t, func() {
		panic("boom")
	})
}

func TestBuildDisplayOptionsWrapWidthPrecedence(t *testing.T) {
	snapshot := captureSharedFlags()
	t.Cleanup(snapshot.restore)

	tests := []struct {
		name       string
		flagWrap   int
		configWrap int
		expected   int
	}{
		{
			name:       "CLI flag takes precedence over config",
			flagWrap:   80,
			configWrap: 120,
			expected:   80,
		},
		{
			name:       "Config used when no CLI flag",
			flagWrap:   -1,
			configWrap: 100,
			expected:   100,
		},
		{
			name:       "Default when neither set",
			flagWrap:   -1,
			configWrap: -1,
			expected:   -1,
		},
		{
			name:       "Explicit wrap zero keeps no wrapping",
			flagWrap:   0,
			configWrap: 0,
			expected:   0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sharedWrapWidth = tt.flagWrap

			cfg := &config.Config{
				WrapWidth: tt.configWrap,
			}

			result := buildDisplayOptions(cfg)
			assert.Equal(t, tt.expected, result.WrapWidth)
		})
	}
}

func TestBuildDisplayOptionsWrapWidthFlagOverridesConfig(t *testing.T) {
	snapshot := captureSharedFlags()
	t.Cleanup(snapshot.restore)

	sharedWrapWidth = 120
	cfg := &config.Config{
		WrapWidth: 80,
	}

	result := buildDisplayOptions(cfg)
	assert.Equal(t, 120, result.WrapWidth)
}

func TestBuildDisplayOptionsWrapWidthZeroDisablesWrapping(t *testing.T) {
	snapshot := captureSharedFlags()
	t.Cleanup(snapshot.restore)

	sharedWrapWidth = 0
	cfg := &config.Config{
		WrapWidth: -1,
	}

	result := buildDisplayOptions(cfg)
	assert.Equal(t, 0, result.WrapWidth)
}

func TestValidateDisplayFlagsWrapWidthWarning(t *testing.T) {
	snapshot := captureSharedFlags()
	t.Cleanup(snapshot.restore)

	tests := []struct {
		name     string
		wrap     int
		wantWarn bool
	}{
		{
			name:     "Auto-detect wrap width sentinel",
			wrap:     -1,
			wantWarn: false,
		},
		{
			name:     "Below minimum recommended wrap width",
			wrap:     MinWrapWidth - 1,
			wantWarn: true,
		},
		{
			name:     "Above maximum recommended wrap width",
			wrap:     MaxWrapWidth + 1,
			wantWarn: true,
		},
		{
			name:     "Within recommended range",
			wrap:     MinWrapWidth,
			wantWarn: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sharedWrapWidth = tt.wrap

			output := captureStderr(t, func() {
				err := validateDisplayFlags(pflag.NewFlagSet("test", pflag.ContinueOnError))
				require.NoError(t, err)
			})

			if tt.wantWarn {
				assert.Contains(t, output, "Warning: wrap width")
			} else {
				assert.Empty(t, output)
			}
		})
	}
}

// TestValidateDisplayFlagsInvalidWrapWidth tests that wrap widths < -1 are rejected with errors.
func TestValidateDisplayFlagsInvalidWrapWidth(t *testing.T) {
	snapshot := captureSharedFlags()
	t.Cleanup(snapshot.restore)

	tests := []struct {
		name      string
		wrap      int
		wantError string
	}{
		{
			name:      "Negative two",
			wrap:      -2,
			wantError: "invalid wrap width -2: must be -1 (auto-detect), 0 (no wrapping), or positive",
		},
		{
			name:      "Negative hundred",
			wrap:      -100,
			wantError: "invalid wrap width -100: must be -1 (auto-detect), 0 (no wrapping), or positive",
		},
		{
			name:      "Math.MinInt equivalent",
			wrap:      -9223372036854775808, // math.MinInt64
			wantError: "invalid wrap width -9223372036854775808: must be -1 (auto-detect), 0 (no wrapping), or positive",
		},
		{
			name:      "Negative ten",
			wrap:      -10,
			wantError: "invalid wrap width -10: must be -1 (auto-detect), 0 (no wrapping), or positive",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sharedWrapWidth = tt.wrap

			err := validateDisplayFlags(pflag.NewFlagSet("test", pflag.ContinueOnError))

			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantError)
		})
	}
}
