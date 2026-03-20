package converter

import (
	"fmt"
	"io"
	"slices"
	"strings"
	"sync"

	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
)

// FormatHandler defines the interface for format-specific generation logic.
// Each handler encapsulates the generation, streaming, and metadata for a single
// output format, allowing the FormatRegistry to dispatch by format name.
type FormatHandler interface {
	// FileExtension returns the file extension for this format (e.g., ".md", ".json").
	FileExtension() string

	// Aliases returns alternative names for this format (e.g., "md" for markdown).
	Aliases() []string

	// Generate creates documentation as a string using the provided generator context.
	Generate(g *HybridGenerator, data *common.CommonDevice, opts Options) (string, error)

	// GenerateToWriter writes documentation directly to the provided io.Writer.
	GenerateToWriter(g *HybridGenerator, w io.Writer, data *common.CommonDevice, opts Options) error
}

// FormatRegistry centralises format dispatch by mapping canonical format names
// and aliases to FormatHandler implementations. It replaces scattered switch
// statements with a single source of truth for supported formats.
type FormatRegistry struct {
	mu       sync.RWMutex
	handlers map[string]FormatHandler
	aliases  map[string]string
}

// NewFormatRegistry creates an empty FormatRegistry.
func NewFormatRegistry() *FormatRegistry {
	return &FormatRegistry{
		handlers: make(map[string]FormatHandler),
		aliases:  make(map[string]string),
	}
}

// Register adds a handler for the given canonical format name. It also registers
// all aliases returned by handler.Aliases(). Panics on duplicate registration,
// consistent with the database/sql driver pattern.
func (r *FormatRegistry) Register(format string, handler FormatHandler) {
	if handler == nil {
		panic(fmt.Sprintf("converter: nil handler for format %q", format))
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	key := strings.ToLower(format)
	if _, exists := r.handlers[key]; exists {
		panic(fmt.Sprintf("converter: format %q already registered", key))
	}

	r.handlers[key] = handler

	for _, alias := range handler.Aliases() {
		aliasKey := strings.ToLower(alias)
		if _, exists := r.aliases[aliasKey]; exists {
			panic(fmt.Sprintf("converter: alias %q already registered", aliasKey))
		}
		if _, exists := r.handlers[aliasKey]; exists {
			panic(fmt.Sprintf("converter: alias %q conflicts with canonical format", aliasKey))
		}

		r.aliases[aliasKey] = key
	}
}

// Get returns the handler for the given format name (canonical or alias).
// Returns ErrUnsupportedFormat if no handler matches.
func (r *FormatRegistry) Get(format string) (FormatHandler, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	key := strings.ToLower(format)

	if h, ok := r.handlers[key]; ok {
		return h, nil
	}

	if canonical, ok := r.aliases[key]; ok {
		return r.handlers[canonical], nil
	}

	return nil, fmt.Errorf("%w: %s", ErrUnsupportedFormat, format)
}

// Canonical returns the canonical format name for the given format string,
// resolving aliases. The boolean indicates whether the format was recognized.
// When ok is false, the returned string is the lowercased input (unresolved).
func (r *FormatRegistry) Canonical(format string) (string, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	key := strings.ToLower(format)

	if _, exists := r.handlers[key]; exists {
		return key, true
	}

	if canonical, exists := r.aliases[key]; exists {
		return canonical, true
	}

	return key, false
}

// Extensions returns a map of canonical format name to file extension.
func (r *FormatRegistry) Extensions() map[string]string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	exts := make(map[string]string, len(r.handlers))
	for name, h := range r.handlers {
		exts[name] = h.FileExtension()
	}

	return exts
}

// ValidFormats returns a sorted slice of canonical format names.
func (r *FormatRegistry) ValidFormats() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	formats := make([]string, 0, len(r.handlers))
	for name := range r.handlers {
		formats = append(formats, name)
	}

	slices.Sort(formats)

	return formats
}

// ValidFormatsWithAliases returns a sorted slice of all accepted format strings,
// including both canonical names and aliases.
func (r *FormatRegistry) ValidFormatsWithAliases() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	all := make([]string, 0, len(r.handlers)+len(r.aliases))
	for name := range r.handlers {
		all = append(all, name)
	}
	for alias := range r.aliases {
		all = append(all, alias)
	}

	slices.Sort(all)

	return all
}

// DefaultRegistry is the package-level registry pre-populated with all built-in
// format handlers. It is the single source of truth for supported formats.
var DefaultRegistry = newDefaultRegistry() //nolint:gochecknoglobals // package-level singleton

// newDefaultRegistry creates a FormatRegistry populated with all built-in handlers.
func newDefaultRegistry() *FormatRegistry {
	r := NewFormatRegistry()
	r.Register(string(FormatMarkdown), &markdownHandler{})
	r.Register(string(FormatJSON), &jsonHandler{})
	r.Register(string(FormatYAML), &yamlHandler{})
	r.Register(string(FormatText), &textHandler{})
	r.Register(string(FormatHTML), &htmlHandler{})

	return r
}

// Format handler implementations below follow a uniform delegation pattern:
// each Generate/GenerateToWriter method forwards the full Options to the
// corresponding private method on HybridGenerator, which owns the actual
// generation logic. Handlers exist to provide format metadata (extension,
// aliases) and to decouple registry dispatch from generation internals.

// markdownHandler handles markdown format output using the programmatic builder.
type markdownHandler struct{}

func (h *markdownHandler) FileExtension() string { return ".md" }
func (h *markdownHandler) Aliases() []string     { return []string{"md"} }

// Generate produces markdown output via the builder pattern, supporting standard and comprehensive modes.
func (h *markdownHandler) Generate(g *HybridGenerator, data *common.CommonDevice, opts Options) (string, error) {
	return g.generateMarkdown(data, opts)
}

// GenerateToWriter streams markdown sections incrementally via SectionWriter when available.
func (h *markdownHandler) GenerateToWriter(
	g *HybridGenerator,
	w io.Writer,
	data *common.CommonDevice,
	opts Options,
) error {
	return g.generateMarkdownToWriter(w, data, opts)
}

// jsonHandler handles JSON format output via encoding/json serialization.
type jsonHandler struct{}

func (h *jsonHandler) FileExtension() string { return ".json" }
func (h *jsonHandler) Aliases() []string     { return nil }

// Generate produces indented JSON from the enriched CommonDevice model.
func (h *jsonHandler) Generate(g *HybridGenerator, data *common.CommonDevice, opts Options) (string, error) {
	return g.generateJSON(data, opts)
}

// GenerateToWriter encodes JSON directly to the writer via json.NewEncoder.
func (h *jsonHandler) GenerateToWriter(g *HybridGenerator, w io.Writer, data *common.CommonDevice, opts Options) error {
	return g.generateJSONToWriter(w, data, opts)
}

// yamlHandler handles YAML format output via gopkg.in/yaml.v3 serialization.
type yamlHandler struct{}

func (h *yamlHandler) FileExtension() string { return ".yaml" }
func (h *yamlHandler) Aliases() []string     { return []string{"yml"} }

// Generate produces YAML from the enriched CommonDevice model.
func (h *yamlHandler) Generate(g *HybridGenerator, data *common.CommonDevice, opts Options) (string, error) {
	return g.generateYAML(data, opts)
}

// GenerateToWriter encodes YAML directly to the writer via yaml.NewEncoder.
func (h *yamlHandler) GenerateToWriter(g *HybridGenerator, w io.Writer, data *common.CommonDevice, opts Options) error {
	return g.generateYAMLToWriter(w, data, opts)
}

// textHandler handles plain text output by generating markdown and stripping formatting.
type textHandler struct{}

func (h *textHandler) FileExtension() string { return ".txt" }
func (h *textHandler) Aliases() []string     { return []string{"txt"} }

// Generate produces plain text by rendering markdown then removing all formatting markers.
func (h *textHandler) Generate(g *HybridGenerator, data *common.CommonDevice, opts Options) (string, error) {
	return g.generatePlainText(data, opts)
}

// GenerateToWriter writes the stripped plain text output to the writer.
func (h *textHandler) GenerateToWriter(g *HybridGenerator, w io.Writer, data *common.CommonDevice, opts Options) error {
	return g.generatePlainTextToWriter(w, data, opts)
}

// htmlHandler handles HTML output by generating markdown and converting via goldmark.
type htmlHandler struct{}

func (h *htmlHandler) FileExtension() string { return ".html" }
func (h *htmlHandler) Aliases() []string     { return []string{"htm"} }

// Generate produces HTML by rendering markdown then converting via goldmark.
func (h *htmlHandler) Generate(g *HybridGenerator, data *common.CommonDevice, opts Options) (string, error) {
	return g.generateHTML(data, opts)
}

// GenerateToWriter writes the rendered HTML output to the writer.
func (h *htmlHandler) GenerateToWriter(g *HybridGenerator, w io.Writer, data *common.CommonDevice, opts Options) error {
	return g.generateHTMLToWriter(w, data, opts)
}
