package audit

// Options contains configuration for audit report generation.
// Options is separate from converter.Options because audit concerns
// (mode selection, compliance plugins) are orthogonal to conversion
// concerns (format, theme, wrapping).
type Options struct {
	// AuditMode specifies the audit reporting mode (blue, red).
	AuditMode string

	// SelectedPlugins specifies which compliance plugins to run.
	SelectedPlugins []string

	// PluginDir is the directory from which dynamic .so plugins are loaded.
	// When non-empty, LoadDynamicPlugins scans this path during InitializePlugins.
	PluginDir string

	// ExplicitPluginDir indicates that PluginDir was explicitly configured by
	// the user (via CLI flag). When true and the directory does not exist,
	// LoadDynamicPlugins returns an error instead of silently continuing.
	ExplicitPluginDir bool

	// FailuresOnly filters the control results table to show only non-compliant
	// controls. Only meaningful in blue mode where compliance checks are executed.
	FailuresOnly bool
}
