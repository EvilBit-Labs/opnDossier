package diff

// addressUnknown is the fallback label used when a rule source or destination address is empty.
const addressUnknown = "unknown"

// Analyzer performs structural comparison of configurations.
type Analyzer struct{}

// NewAnalyzer creates a new structural analyzer.
func NewAnalyzer() *Analyzer {
	return &Analyzer{}
}
