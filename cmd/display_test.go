package cmd

import (
	"io"
	"os"
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/config"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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

	fn()

	require.NoError(t, writer.Close())
	os.Stderr = originalStderr

	output, err := io.ReadAll(reader)
	require.NoError(t, err)
	require.NoError(t, reader.Close())

	return string(output)
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
			expected:   0,
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
