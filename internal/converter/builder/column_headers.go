// Package builder constructs the markdown sections that make up an
// opnDossier report. This file centralizes the column-header strings
// that the report tables share — every builder_*.go assembles tables
// whose headers reuse the same vocabulary ("Description", "Status",
// "Interface", etc.) and goconst flagged them as repeated literals.
//
// These constants are deliberately scoped to package builder. They are
// presentation strings (markdown table headers seen by report readers),
// not part of any external contract; we may freely rename them as the
// report design evolves so long as the strings stay in sync across all
// tables that share a column.
package builder

// Shared markdown table column headers. Repeated across the per-section
// builder_*.go files so report tables align visually under the same
// column when consumers concatenate sections. Use these ONLY in `Header`
// slices of a TableSet — see labelEnabled / labelMode below for the cell
// or field-label variants.
const (
	colDescription = "Description"
	colStatus      = "Status"
	colInterface   = "Interface"
	colValue       = "Value"
	colMode        = "Mode"
	colType        = "Type"
	colSeverity    = "Severity"
	colEnabled     = "Enabled"
	colSetting     = "Setting"
	colProtocol    = "Protocol"
	colName        = "Name"
	colTitle       = "Title"
)

// Field labels and cell values that share string value with column headers
// but appear in different semantic positions — bold inline labels
// ("**Enabled**: true"), row labels in two-column tables, or status cell
// values. Kept as separate constants so renaming a column header for
// alignment never silently retags an unrelated label or value.
const (
	labelEnabled = "Enabled"
	labelMode    = "Mode"
)
