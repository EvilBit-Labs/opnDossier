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

// htmlTemplateData contains all data passed to the HTML template.
type htmlTemplateData struct {
	Result    *diff.Result
	CSS       htmltemplate.CSS
	JS        htmltemplate.JS
	BySection map[string][]diff.Change
}

// Format formats the diff result as a self-contained HTML document.
func (f *HTMLFormatter) Format(result *diff.Result) error {
	funcMap := htmltemplate.FuncMap{
		"capitalize": capitalizeFirst,
	}

	tmpl, err := htmltemplate.New("report").Funcs(funcMap).Parse(reportTemplate)
	if err != nil {
		return err
	}

	data := htmlTemplateData{
		Result: result,
		//nolint:gosec // G203: CSS is embedded from our own static files, not user input
		CSS: htmltemplate.CSS(stylesCSS),
		//nolint:gosec // G203: JS is embedded from our own static files, not user input
		JS:        htmltemplate.JS(scriptsJS),
		BySection: sortedSections(result),
	}

	return tmpl.Execute(f.writer, data)
}

// sortedSections returns changes grouped by section name, sorted alphabetically.
func sortedSections(result *diff.Result) map[string][]diff.Change {
	bySection := result.ChangesBySection()

	// Convert to string keys for template iteration determinism
	sorted := make(map[string][]diff.Change, len(bySection))

	sections := make([]diff.Section, 0, len(bySection))
	for s := range bySection {
		sections = append(sections, s)
	}
	sort.Slice(sections, func(i, j int) bool {
		return sections[i].String() < sections[j].String()
	})

	for _, s := range sections {
		sorted[s.String()] = bySection[s]
	}

	return sorted
}
