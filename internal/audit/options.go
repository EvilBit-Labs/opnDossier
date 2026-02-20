package audit

// Options contains configuration for audit report generation.
// Options is separate from converter.Options because audit concerns
// (mode selection, compliance plugins) are orthogonal to conversion
// concerns (format, theme, wrapping).
type Options struct {
	// AuditMode specifies the audit reporting mode (standard, blue, red).
	AuditMode string

	// BlackhatMode enables red team blackhat commentary.
	BlackhatMode bool

	// SelectedPlugins specifies which compliance plugins to run.
	SelectedPlugins []string
}
