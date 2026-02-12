package formatters

import (
	_ "embed"
	htmltemplate "html/template"
	"io"
	"sort"

	"github.com/EvilBit-Labs/opnDossier/internal/diff"
)

//go:embed static/report.html.tmpl
var reportTemplate string

//go:embed static/styles.css
var stylesCSS string

//go:embed static/scripts.js
var scriptsJS string

// parsedReportTemplate is the pre-parsed HTML template, compiled once at package init.
var parsedReportTemplate = htmltemplate.Must(
	htmltemplate.New("report").Funcs(htmltemplate.FuncMap{
		"capitalize": capitalizeFirst,
	}).Parse(reportTemplate),
)

// HTMLFormatter formats diff results as a self-contained HTML report.
type HTMLFormatter struct {
	writer io.Writer
}

// NewHTMLFormatter creates a new HTML formatter.
func NewHTMLFormatter(writer io.Writer) *HTMLFormatter {
	return &HTMLFormatter{
		writer: writer,
	}
}

// sectionChanges groups changes under a named section for ordered template iteration.
type sectionChanges struct {
	Name    string
	Changes []diff.Change
}

// htmlTemplateData contains all data passed to the HTML template.
type htmlTemplateData struct {
	Result   *diff.Result
	CSS      htmltemplate.CSS
	JS       htmltemplate.JS
	Sections []sectionChanges
}

// Format formats the diff result as a self-contained HTML document.
func (f *HTMLFormatter) Format(result *diff.Result) error {
	data := htmlTemplateData{
		Result: result,
		//nolint:gosec // G203: CSS is embedded from our own static files, not user input
		CSS: htmltemplate.CSS(stylesCSS),
		//nolint:gosec // G203: JS is embedded from our own static files, not user input
		JS:       htmltemplate.JS(scriptsJS),
		Sections: sortedSections(result),
	}

	return parsedReportTemplate.Execute(f.writer, data)
}

// sortedSections returns changes grouped by section, sorted alphabetically.
// Returns an ordered slice to ensure deterministic template iteration.
func sortedSections(result *diff.Result) []sectionChanges {
	bySection := result.ChangesBySection()

	sections := make([]diff.Section, 0, len(bySection))
	for s := range bySection {
		sections = append(sections, s)
	}
	sort.Slice(sections, func(i, j int) bool {
		return sections[i].String() < sections[j].String()
	})

	ordered := make([]sectionChanges, 0, len(sections))
	for _, s := range sections {
		ordered = append(ordered, sectionChanges{
			Name:    s.String(),
			Changes: bySection[s],
		})
	}
	return ordered
}
