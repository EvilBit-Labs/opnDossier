package converter

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOptions_WithAuditMode(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		mode     string
		expected string
	}{
		{
			name:     "standard mode",
			mode:     "standard",
			expected: "standard",
		},
		{
			name:     "blue mode",
			mode:     "blue",
			expected: "blue",
		},
		{
			name:     "red mode",
			mode:     "red",
			expected: "red",
		},
		{
			name:     "empty mode",
			mode:     "",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			opts := DefaultOptions().WithAuditMode(tt.mode)
			assert.Equal(t, tt.expected, opts.AuditMode)
		})
	}
}

func TestOptions_WithBlackhatMode(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		enabled  bool
		expected bool
	}{
		{
			name:     "enabled",
			enabled:  true,
			expected: true,
		},
		{
			name:     "disabled",
			enabled:  false,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			opts := DefaultOptions().WithBlackhatMode(tt.enabled)
			assert.Equal(t, tt.expected, opts.BlackhatMode)
		})
	}
}

func TestOptions_WithSelectedPlugins(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		plugins  []string
		expected []string
	}{
		{
			name:     "single plugin",
			plugins:  []string{"stig"},
			expected: []string{"stig"},
		},
		{
			name:     "multiple plugins",
			plugins:  []string{"stig", "sans", "firewall"},
			expected: []string{"stig", "sans", "firewall"},
		},
		{
			name:     "empty plugins",
			plugins:  []string{},
			expected: []string{},
		},
		{
			name:     "nil plugins",
			plugins:  nil,
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			opts := DefaultOptions().WithSelectedPlugins(tt.plugins...)
			assert.Equal(t, tt.expected, opts.SelectedPlugins)
		})
	}
}

func TestOptions_AuditFieldsChaining(t *testing.T) {
	t.Parallel()
	// Test that audit fields can be chained with other options
	opts := DefaultOptions().
		WithAuditMode("red").
		WithBlackhatMode(true).
		WithSelectedPlugins("stig", "sans").
		WithFormat(FormatJSON)

	require.Equal(t, "red", opts.AuditMode)
	require.True(t, opts.BlackhatMode)
	require.Equal(t, []string{"stig", "sans"}, opts.SelectedPlugins)
	require.Equal(t, FormatJSON, opts.Format)
}

func TestDefaultOptions_AuditFieldsInitialized(t *testing.T) {
	t.Parallel()
	// Verify default values for audit fields
	opts := DefaultOptions()

	assert.Empty(t, opts.AuditMode, "AuditMode should be empty by default")
	assert.False(t, opts.BlackhatMode, "BlackhatMode should be false by default")
	assert.Nil(t, opts.SelectedPlugins, "SelectedPlugins should be nil by default")
}
