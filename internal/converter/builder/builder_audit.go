package builder

import (
	"bytes"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"

	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
	"github.com/nao1215/markdown"
)

// BuildAuditSection builds the compliance audit section from the device's ComplianceResults.
// If ComplianceResults is nil, it returns an empty string.
//
// When Controls data is available for a plugin, a unified "Plugin Results" table is rendered
// with a Status column (PASS/FAIL). When b.failuresOnly is true, only FAIL rows are included.
// When Controls is empty but Findings exist, the legacy findings table is rendered as a fallback.
func (b *MarkdownBuilder) BuildAuditSection(data *common.CommonDevice) string {
	if data == nil || data.ComplianceResults == nil {
		return ""
	}

	cc := data.ComplianceResults

	var buf bytes.Buffer
	md := markdown.NewMarkdown(&buf)

	md.HorizontalRule()

	b.writeAuditPluginSections(md, cc)
	writeAuditSecurityAndInventory(md, cc)
	writeAuditSummary(md, cc)
	writeAuditMetadata(md, cc)

	//nolint:errcheck,gosec // Build writes to bytes.Buffer which cannot fail
	md.Build()

	return buf.String()
}

// writeAuditPluginSections emits the per-plugin H3 blocks under "Compliance
// Audit Results". When a plugin has Controls data, the unified controls table
// is rendered; otherwise the legacy findings-only fallback is used.
func (b *MarkdownBuilder) writeAuditPluginSections(md *markdown.Markdown, cc *common.ComplianceResults) {
	if len(cc.PluginResults) == 0 {
		return
	}
	md.H2("Compliance Audit Results")
	for _, pluginName := range slices.Sorted(maps.Keys(cc.PluginResults)) {
		result := cc.PluginResults[pluginName]
		md.H3(pluginName)
		switch {
		case len(result.Controls) > 0:
			b.writePluginControlsTable(md, pluginName, result)
		case len(result.Findings) > 0:
			// Legacy fallback: render findings table when no Controls data.
			// failuresOnly does not apply here — findings ARE failures by
			// definition; the flag only filters the controls table which has
			// both PASS and FAIL rows.
			b.writePluginFindingsTable(md, pluginName, result)
		}
	}
}

// writeAuditSecurityAndInventory partitions top-level findings into security
// (compliance) and inventory, plus per-plugin inventory findings, and emits
// the "Security Findings" and "Configuration Notes" tables.
func writeAuditSecurityAndInventory(md *markdown.Markdown, cc *common.ComplianceResults) {
	var securityFindings, inventoryFindings []common.ComplianceFinding
	for _, f := range cc.Findings {
		if f.Type == findingTypeInventory {
			inventoryFindings = append(inventoryFindings, f)
		} else {
			securityFindings = append(securityFindings, f)
		}
	}
	for _, pluginName := range slices.Sorted(maps.Keys(cc.PluginResults)) {
		for _, f := range cc.PluginResults[pluginName].Findings {
			if f.Type == findingTypeInventory {
				inventoryFindings = append(inventoryFindings, f)
			}
		}
	}

	if len(securityFindings) > 0 {
		md.H3("Security Findings")
		findingsTable := markdown.TableSet{
			Header: []string{"Severity", "Component", "Title", "Recommendation"},
			Rows:   make([][]string, 0, len(securityFindings)),
		}
		for _, f := range securityFindings {
			findingsTable.Rows = append(findingsTable.Rows, []string{
				EscapePipeForMarkdown(f.Severity),
				EscapePipeForMarkdown(f.Component),
				EscapePipeForMarkdown(f.Title),
				EscapePipeForMarkdown(f.Recommendation),
			})
		}
		md.Table(findingsTable)
	}

	if len(inventoryFindings) > 0 {
		md.H3("Configuration Notes")
		notesTable := markdown.TableSet{
			Header: []string{"Component", "Title", "Details"},
			Rows:   make([][]string, 0, len(inventoryFindings)),
		}
		for _, f := range inventoryFindings {
			notesTable.Rows = append(notesTable.Rows, []string{
				EscapePipeForMarkdown(f.Component),
				EscapePipeForMarkdown(f.Title),
				EscapePipeForMarkdown(f.Description),
			})
		}
		md.Table(notesTable)
	}
}

// writeAuditSummary emits the compliance totals table and per-plugin
// summary statistics. Totals come from cc.Summary when present, otherwise
// derived from PluginResults (inventory-only plugins with neither Summary
// nor Findings contribute zero).
func writeAuditSummary(md *markdown.Markdown, cc *common.ComplianceResults) {
	totalFindings, totalCompliant, totalNonCompliant := computeAuditTotals(cc)

	md.H2("Compliance Audit Summary")
	md.Table(markdown.TableSet{
		Header: []string{"Metric", "Value"},
		Rows: [][]string{
			{"Mode", cc.Mode},
			{"Total Findings", strconv.Itoa(totalFindings)},
			{"Compliant", strconv.Itoa(totalCompliant)},
			{"Non-Compliant", strconv.Itoa(totalNonCompliant)},
		},
	})

	for _, pluginName := range slices.Sorted(maps.Keys(cc.PluginResults)) {
		md.H3(pluginName)
		md.BulletList(pluginSummaryItems(cc.PluginResults[pluginName])...)
	}
}

// computeAuditTotals returns (totalFindings, totalCompliant, totalNonCompliant),
// preferring cc.Summary when available. When Summary is nil, totals are
// derived per-plugin: plugin Summary when present, otherwise findings count
// plus a Controls-based compliant/non-compliant tally (UNKNOWN excluded).
//
//nolint:nonamedreturns // named returns document the 3-int contract; the unnamed form trips gocritic.unnamedResult
func computeAuditTotals(cc *common.ComplianceResults) (total, compliant, nonCompliant int) {
	if cc.Summary != nil {
		return cc.Summary.TotalFindings, cc.Summary.Compliant, cc.Summary.NonCompliant
	}

	total = len(cc.Findings)
	for _, pluginName := range slices.Sorted(maps.Keys(cc.PluginResults)) {
		pr := cc.PluginResults[pluginName]
		if pr.Summary != nil {
			total += pr.Summary.TotalFindings
			compliant += pr.Summary.Compliant
			nonCompliant += pr.Summary.NonCompliant
			continue
		}
		total += len(pr.Findings)
		for _, ctrl := range pr.Controls {
			switch ctrl.Status {
			case common.ControlStatusPass:
				compliant++
			case common.ControlStatusFail:
				nonCompliant++
			}
		}
	}
	return total, compliant, nonCompliant
}

// writeAuditMetadata emits the final "Audit Metadata" table when Metadata
// is non-empty. Keys are sorted for determinism.
func writeAuditMetadata(md *markdown.Markdown, cc *common.ComplianceResults) {
	if len(cc.Metadata) == 0 {
		return
	}
	md.H2("Audit Metadata")
	metadataTable := markdown.TableSet{
		Header: []string{"Key", "Value"},
		Rows:   make([][]string, 0, len(cc.Metadata)),
	}
	for _, key := range slices.Sorted(maps.Keys(cc.Metadata)) {
		metadataTable.Rows = append(metadataTable.Rows, []string{
			EscapePipeForMarkdown(key),
			EscapePipeForMarkdown(fmt.Sprintf("%v", cc.Metadata[key])),
		})
	}
	md.Table(metadataTable)
}

// pluginSummaryItems renders a per-plugin summary as bullet list items. When
// no Summary is attached, a single "no data available" entry is returned so
// the H3 heading is not left dangling.
func pluginSummaryItems(result common.PluginComplianceResult) []string {
	if result.Summary == nil {
		return []string{"Summary: no data available"}
	}

	items := []string{
		fmt.Sprintf("Findings: %d", result.Summary.TotalFindings),
		fmt.Sprintf("Compliant: %d", result.Summary.Compliant),
		fmt.Sprintf("Non-Compliant: %d", result.Summary.NonCompliant),
	}

	severityCounts := []struct {
		label string
		count int
	}{
		{"Critical", result.Summary.CriticalFindings},
		{"High", result.Summary.HighFindings},
		{"Medium", result.Summary.MediumFindings},
		{"Low", result.Summary.LowFindings},
		{"Informational", result.Summary.InfoFindings},
	}
	for _, s := range severityCounts {
		if s.count > 0 {
			items = append(items, fmt.Sprintf("%s: %d", s.label, s.count))
		}
	}
	return items
}

// writePluginControlsTable renders a unified controls table for a plugin with a Status column.
// Controls are sorted by ID for deterministic output. When b.failuresOnly is true, only
// non-compliant controls are included.
func (b *MarkdownBuilder) writePluginControlsTable(
	md *markdown.Markdown,
	pluginName string,
	result common.PluginComplianceResult,
) {
	// Sort controls by ID for deterministic output (GOTCHAS.md §3.1)
	sortedControls := slices.Clone(result.Controls)
	slices.SortFunc(sortedControls, func(a, c common.ComplianceControl) int {
		return strings.Compare(a.ID, c.ID)
	})

	controlTable := markdown.TableSet{
		Header: []string{"Control ID", "Title", "Severity", "Category", "Status"},
		Rows:   make([][]string, 0, len(sortedControls)),
	}

	for _, ctrl := range sortedControls {
		// Read the pre-populated Status field set by mapControls in the mapping layer.
		// Fall back to UNCONFIRMED if Status is empty (e.g., legacy code path
		// where controls were not enriched with compliance status).
		status := ctrl.Status
		if status == "" {
			status = common.ControlStatusUnknown
		}

		if b.failuresOnly && status == common.ControlStatusPass {
			continue
		}

		controlTable.Rows = append(controlTable.Rows, []string{
			EscapePipeForMarkdown(ctrl.ID),
			EscapePipeForMarkdown(TruncateString(ctrl.Title, MaxDescriptionLength)),
			EscapePipeForMarkdown(ctrl.Severity),
			EscapePipeForMarkdown(ctrl.Category),
			status,
		})
	}

	if len(controlTable.Rows) > 0 {
		md.H4(pluginName + " Plugin Results")
		md.Table(controlTable)
	} else if b.failuresOnly {
		md.H4(pluginName + " Plugin Results")
		md.PlainText("All controls compliant — no failures to display.")
	}
}

// writePluginFindingsTable renders the legacy per-plugin findings table.
// Used as a fallback when plugin Controls data is not available.
func (b *MarkdownBuilder) writePluginFindingsTable(
	md *markdown.Markdown,
	pluginName string,
	result common.PluginComplianceResult,
) {
	md.H4(pluginName + " Plugin Findings")
	pluginTable := markdown.TableSet{
		Header: []string{"Control", "Severity", "Title", "Description"},
		Rows:   make([][]string, 0, len(result.Findings)),
	}

	for _, f := range result.Findings {
		// Inventory findings are rendered in Configuration Notes, not the findings table.
		if f.Type == findingTypeInventory {
			continue
		}

		controlID := f.Control
		switch {
		case controlID != "":
		case f.Reference != "":
			controlID = f.Reference
		case len(f.References) > 0:
			controlID = strings.Join(f.References, ", ")
		}

		pluginTable.Rows = append(pluginTable.Rows, []string{
			EscapePipeForMarkdown(controlID),
			EscapePipeForMarkdown(f.Severity),
			EscapePipeForMarkdown(f.Title),
			EscapePipeForMarkdown(TruncateString(f.Description, MaxDescriptionLength)),
		})
	}

	md.Table(pluginTable)
}
