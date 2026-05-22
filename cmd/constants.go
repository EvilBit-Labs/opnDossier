// Package cmd provides the command-line interface for opnDossier.
package cmd

// Recurring string literals used by multiple subcommand definitions. The
// strings themselves are part of the CLI surface (group IDs, flag-category
// annotations, flag names) so they cannot be moved into typed enums — Cobra
// and the project's flag-annotation helper both consume plain strings.
// Centralizing them here gives `setFlagAnnotation`, GroupID assignments, and
// the `lightweight` startup-skipper a single point of change.

// Cobra command-group identifiers declared in cmd/root.go's AddGroup() calls.
// Subcommands set `GroupID` to one of these to appear under the right header
// in `opnDossier --help`.
const (
	groupCore    = "core"
	groupAudit   = "audit"
	groupUtility = "utility"
)

// Flag categories passed to setFlagAnnotation. These determine which "Flags"
// section a flag is listed under in the per-command help output. Some values
// match a group ID (groupAudit and categoryAudit are both "audit") because
// the same word is the natural label in both contexts; they are kept as
// distinct constants so a rename in one context does not silently rename
// the other.
const (
	categoryAudit   = "audit"
	categoryDisplay = "display"
	categoryFormat  = "format"
	categoryLogging = "logging"
	categoryOutput  = "output"
	categoryWrap    = "wrap"
)

// Flag names that recur 3+ times across subcommand init() functions.
const (
	flagVerbose = "verbose"
	flagDebug   = "debug"
	flagFormat  = "format"
)

// Cobra Annotations key used to mark subcommands that skip the heavy
// initialization path (config load, plugin discovery) for fast startup.
// Consumed by PersistentPreRunE in cmd/root.go.
const annotationLightweight = "lightweight"

// Log levels passed to logging.New(). Keep in sync with the levels that
// logging.New accepts via logging.ErrInvalidLogLevel — the logging package
// does not export typed constants, so cmd carries its own.
const (
	logLevelDebug = "debug"
	logLevelInfo  = "info"
	logLevelWarn  = "warn"
	logLevelError = "error"
)

// Default values for the global format/log-format flags that appear as
// literals in cmd/root.go's setupLightweightContext, defaultLoggerConfig,
// and several setupFullContext branches.
const (
	defaultFormat     = "markdown"
	defaultLogFormat  = "text"
	annotationValueOn = "true" // The on-value for boolean Cobra Annotations.
	cmdNameVersion    = "version"
)

// Audit modes mirroring internal/audit.ModeBlue / ModeRed but kept as raw
// strings here since cmd flag parsing accepts plain strings (the typed
// ReportMode constants are consumed inside internal/audit).
const (
	auditModeBlue = "blue"
	auditModeRed  = "red"
)

// Severity strings used in human-facing CLI output (audit findings table,
// help text). Mirror internal/analysis.SeverityXxx values, kept as raw
// strings here because the CLI surfaces these as plain text — not as the
// typed Severity enum.
const (
	severityHigh   = "high"
	severityMedium = "medium"
	severityLow    = "low"
)

// Config section names that recur in config-show / config-validate routing.
const (
	configSectionExport  = "export"
	configSectionDisplay = "display"
)

// Display-related primitives.
const (
	primitiveEmpty = "(empty)"
	primitiveFalse = "false"
	flagWidth      = "width"
	cmdNameConfig  = "config"
)

// Output format names. The cmd package consumes these as plain strings via
// Cobra flag defaults and the formatDescriptions lookup table; the typed
// converter.Format constants are an internal/converter concern.
const (
	outputFormatMarkdown = "markdown"
	outputFormatJSON     = "json"
	outputFormatYAML     = "yaml"
	outputFormatText     = "text"
	outputFormatHTML     = "html"
)

// Device-parser names mirroring parser.DefaultRegistry() entries. Used by
// the shell-completion description map and validation messages.
const (
	deviceNameOPNsense = "opnsense"
	deviceNamePfSense  = "pfsense"
)

// Plugin names for shell-completion descriptions and tests.
const (
	pluginNameStig     = "stig"
	pluginNameSans     = "sans"
	pluginNameFirewall = "firewall"
)
