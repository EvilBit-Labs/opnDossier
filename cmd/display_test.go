package cmd

import (
	"io"
	"os"
	"strconv"
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
//   - noWrap: Disable text wrapping
//   - sections: Which sections to include in output
//   - comprehensive: Whether to generate comprehensive reports
//
// Rationale: The snapshot focuses on flags that directly affect display output
// and are commonly modified in display tests.
type sharedFlagSnapshot struct {
	theme         string
	wrapWidth     int
	noWrap        bool
	sections      []string
	comprehensive bool
}

func captureSharedFlags() sharedFlagSnapshot {
	return sharedFlagSnapshot{
		theme:         sharedTheme,
		wrapWidth:     sharedWrapWidth,
		noWrap:        sharedNoWrap,
		sections:      sharedSections,
		comprehensive: sharedComprehensive,
	}
}

func (s sharedFlagSnapshot) restore() {
	sharedTheme = s.theme
	sharedWrapWidth = s.wrapWidth
	sharedNoWrap = s.noWrap
	sharedSections = s.sections
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
		flagNoWrap bool
		configWrap int
		expected   int
	}{
		{
			name:       "CLI flag takes precedence over config",
			flagWrap:   80,
			flagNoWrap: false,
			configWrap: 120,
			expected:   80,
		},
		{
			name:       "Config used when no CLI flag",
			flagWrap:   -1,
			flagNoWrap: false,
			configWrap: 100,
			expected:   100,
		},
		{
			name:       "Default when neither set",
			flagWrap:   -1,
			flagNoWrap: false,
			configWrap: -1,
			expected:   -1,
		},
		{
			name:       "Explicit wrap zero keeps no wrapping",
			flagWrap:   0,
			flagNoWrap: false,
			configWrap: 0,
			expected:   0,
		},
		{
			name:       "No-wrap sets wrap width to zero",
			flagWrap:   120,
			flagNoWrap: true,
			configWrap: 90,
			expected:   0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sharedWrapWidth = tt.flagWrap
			sharedNoWrap = tt.flagNoWrap

			flags := pflag.NewFlagSet("test", pflag.ContinueOnError)
			flags.Bool("no-wrap", false, "")
			flags.Int("wrap", -1, "")
			if tt.flagNoWrap {
				require.NoError(t, flags.Set("no-wrap", "true"))
			} else if tt.flagWrap != -1 {
				// Only set wrap flag if no-wrap is not set (mutual exclusivity)
				require.NoError(t, flags.Set("wrap", strconv.Itoa(tt.flagWrap)))
			}

			cfg := &config.Config{
				WrapWidth: tt.configWrap,
			}

			require.NoError(t, validateDisplayFlags(flags))
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
	sharedNoWrap = false
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
			sharedNoWrap = false

			err := validateDisplayFlags(pflag.NewFlagSet("test", pflag.ContinueOnError))

			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantError)
		})
	}
}

func TestValidateDisplayFlagsNoWrapMutualExclusivity(t *testing.T) {
	snapshot := captureSharedFlags()
	t.Cleanup(snapshot.restore)

	baseFlags := func() *pflag.FlagSet {
		flags := pflag.NewFlagSet("test", pflag.ContinueOnError)
		flags.Bool("no-wrap", false, "")
		flags.Int("wrap", -1, "")
		return flags
	}

	tests := []struct {
		name          string
		noWrap        bool
		wrapValue     string
		setWrapFlag   bool
		wantErr       bool
		wantErrSubstr string
	}{
		{
			name:        "No-wrap alone is valid",
			noWrap:      true,
			setWrapFlag: false,
			wantErr:     false,
		},
		{
			name:          "No-wrap with wrap auto-detect",
			noWrap:        true,
			setWrapFlag:   true,
			wrapValue:     "-1",
			wantErr:       true,
			wantErrSubstr: "--no-wrap and --wrap flags are mutually exclusive",
		},
		{
			name:          "No-wrap with wrap zero",
			noWrap:        true,
			setWrapFlag:   true,
			wrapValue:     "0",
			wantErr:       true,
			wantErrSubstr: "--no-wrap and --wrap flags are mutually exclusive",
		},
		{
			name:          "No-wrap with wrap 80",
			noWrap:        true,
			setWrapFlag:   true,
			wrapValue:     "80",
			wantErr:       true,
			wantErrSubstr: "--no-wrap and --wrap flags are mutually exclusive",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			flags := baseFlags()
			sharedNoWrap = tt.noWrap
			sharedWrapWidth = -1

			if tt.noWrap {
				require.NoError(t, flags.Set("no-wrap", "true"))
			}
			if tt.setWrapFlag {
				require.NoError(t, flags.Set("wrap", tt.wrapValue))
				wrapVal, err := flags.GetInt("wrap")
				require.NoError(t, err)
				sharedWrapWidth = wrapVal
			}

			err := validateDisplayFlags(flags)
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErrSubstr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, 0, sharedWrapWidth)
		})
	}
}
